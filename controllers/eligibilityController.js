const User = require('../models/User');
const aiService = require('../services/aiService');
const ragService = require('../services/ragService');
const Document = require('../models/Document');


// Every top-level {...} block in the text, found by counting braces and skipping strings,
// so nested objects (missingRequirements) stay inside their parent.
function jsonObjects(text) {
  const found = [];
  let depth = 0, start = -1, inString = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { if (depth > 0) inString = true; continue; }
    if (ch === '{') { if (depth === 0) start = i; depth++; }
    else if (ch === '}' && depth > 0) {
      depth--;
      if (depth === 0) found.push(text.slice(start, i + 1));
    }
  }
  return found;
}

// Reasoning models write their thinking first; the real answer is the last block with our fields.
function extractResult(text) {
  const clean = String(text).replace(/```json/gi, '').replace(/```/g, '');
  const blocks = jsonObjects(clean);
  for (let i = blocks.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(blocks[i]);
      if (parsed && (parsed.matchScore !== undefined || parsed.opportunityType !== undefined)) return parsed;
    } catch { /* try the next block */ }
  }
  return null;
}

// The screen expects exact types, so coerce what the model gave and fill what it left out.
function normalizeResult(raw) {
  if (!raw) return null;
  const score = Math.round(Number(raw.matchScore));
  if (!Number.isFinite(score)) return null;
  const list = (v) => (Array.isArray(v) ? v : []).map((x) => String(x?.requirement ?? x)).filter(Boolean);
  return {
    opportunityType: String(raw.opportunityType || 'Eligibility check'),
    matchScore: Math.min(100, Math.max(0, score)),
    isEligible: raw.isEligible === true || raw.isEligible === 'true',
    strengths: list(raw.strengths),
    missingRequirements: (Array.isArray(raw.missingRequirements) ? raw.missingRequirements : [])
      .map((m) => (typeof m === 'string' ? { requirement: m, suggestion: '' } : { requirement: String(m?.requirement || ''), suggestion: String(m?.suggestion || '') }))
      .filter((m) => m.requirement),
    reasoning: String(raw.reasoning || '')
  };
}

const DOC_LABELS = { aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', other: 'Other document' };

const ageFrom = (dob) => {
  const m = String(dob || '').match(/(\d{2})\/(\d{2})\/(\d{4})/);
  if (!m) return null;
  const born = new Date(Number(m[3]), Number(m[2]) - 1, Number(m[1]));
  if (Number.isNaN(born.getTime())) return null;
  const now = new Date();
  let age = now.getFullYear() - born.getFullYear();
  if (now < new Date(now.getFullYear(), born.getMonth(), born.getDate())) age--;
  return age >= 0 && age < 120 ? age : null;
};

// What the AI is told about the person. Built only from what is stored: nothing is assumed.
async function buildContext(user, v2Facts = null) {
  if (user.securityVersion === 2 && v2Facts) {
    // Only coarse facts leave the vault for the AI: no names, numbers or addresses.
    let context = `Candidate profile (from the member's own opened vault, identity details withheld):\n`;
    if (v2Facts.age !== null && v2Facts.age !== undefined) context += `Age: ${v2Facts.age} years\n`;
    if (v2Facts.state) context += `State: ${v2Facts.state}\n`;
    if (v2Facts.city) context += `City: ${v2Facts.city}\n`;
    context += v2Facts.documents.length ? `Documents held: ${v2Facts.documents.join(', ')}\n` : 'Documents held: none read yet\n';
    return `${context}\nAnything not listed above is NOT known. Do not assume it.\n`;
  }
  if (user.securityVersion === 2) {
    return `Candidate: ${user.name || 'Account holder'}
Stored details: NONE AVAILABLE. This account encrypts documents on the user's own device, so FormOS cannot read their contents.
Do not assume the candidate holds any document, qualification, job, address or age. Judge each requirement as "not confirmed" and list what the candidate should check or provide.`;
  }

  let context = ragService.prepareContext(user);
  const profile = ragService.getNormalizedProfile(user);
  const age = ageFrom(profile.dateOfBirth);
  if (age !== null) context += `Age: ${age} years\n`;
  if (user.extractedData?.state) context += `State: ${user.extractedData.state}\n`;
  if (user.extractedData?.gender) context += `Gender: ${user.extractedData.gender}\n`;

  const docs = await Document.find({ userId: user._id, securityVersion: { $ne: 2 } }).select('documentType originalName structuredData').limit(20).lean();
  if (docs.length) {
    context += '\nDocuments the candidate has uploaded:\n';
    docs.forEach((doc) => { context += `- ${DOC_LABELS[doc.documentType] || 'Document'}: ${doc.originalName}\n`; });
  } else {
    context += '\nDocuments uploaded: none.\n';
  }
  context += '\nAnything not listed above is NOT known. Do not assume it.\n';
  return context;
}

// The whole check, shared by the app and the WhatsApp assistant: builds the profile from what is
// stored, asks the AI, and returns a clean result. Throws with httpStatus on failure.
async function evaluateEligibility(user, jd, extra = {}) {
  const context = await buildContext(user, extra.v2Facts || null);

  const systemPrompt = `You are a universal eligibility assessment expert. You evaluate whether a person meets the requirements for ANY type of opportunity: jobs, government schemes, scholarships, loans, housing, welfare programs, internships, visas, or any other application.

First detect the opportunity type, then evaluate the candidate profile against the requirements.

GROUNDING RULES:
- Use ONLY facts written in CANDIDATE PROFILE. If a fact is not there, it is unknown: never say the candidate has or lacks something unless the profile shows it.
- Something unknown goes in missingRequirements with a suggestion to provide or confirm it. Do not list it under strengths.
- A requirement the profile clearly satisfies (for example age, state, document held) goes in strengths and must NOT appear in missingRequirements.
- Compare numbers yourself: use the Age line for age limits, the Address and State lines for location.

CRITICAL: Output ONLY a raw JSON object. No thinking. No explanation. No markdown. No backticks. Start your response with { and end with }. Nothing before or after.

Required JSON structure:
{
"opportunityType": "e.g. SDE Job Role / PM Scholarship / PM Awas Yojana / Student Loan",
"matchScore": <integer 0-100>,
"isEligible": <true or false>,
"strengths": ["matching criteria from candidate profile"],
"missingRequirements": [
  {
    "requirement": "unmet requirement name",
    "suggestion": "specific actionable step to meet it"
  }
],
"reasoning": "2-3 sentence summary"
}`;

  const userPrompt = `CANDIDATE PROFILE:
${context}

OPPORTUNITY REQUIREMENTS:
${jd}

JSON:`;

  const options = {
    user: user.securityVersion === 2 ? { ...user.toObject(), securityVersion: 1 } : user,
    operation: user.securityVersion === 2 ? aiService.AI_OPERATION.CLASSIFICATION : aiService.AI_OPERATION.ELIGIBILITY
  };

  // Models sometimes add prose, markdown or a cut-off answer. Ask again once before giving up.
  let result = null;
  let lastResponse = '';
  for (let attempt = 1; attempt <= 2 && !result; attempt++) {
    const aiResponse = await aiService.chat(systemPrompt, userPrompt, options);
    if (!aiResponse) continue;
    lastResponse = aiResponse;
    result = normalizeResult(extractResult(aiResponse));
  }

  if (!result) {
    console.error('Eligibility: AI answer could not be read:', lastResponse.slice(0, 500));
    const message = lastResponse ? 'The AI answer could not be read. Please try again.' : 'AI service returned no response.';
    throw Object.assign(new Error(message), { httpStatus: 502 });
  }

  return result;
}

exports.evaluateEligibility = evaluateEligibility;
exports.ageFrom = ageFrom;

exports.checkEligibility = async (req, res) => {
  try {
    const { jd } = req.body;

    if (!jd) {
      return res.status(400).json({ success: false, message: 'Requirements text is required' });
    }

    if (!aiService.isConfigured()) {
      return res.status(500).json({ success: false, message: 'AI service is not configured' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const result = await evaluateEligibility(user, jd);
    res.json({ success: true, data: result });

  } catch (error) {
    if (error.httpStatus) {
      return res.status(error.httpStatus).json({ success: false, message: error.message });
    }
    console.error('Eligibility check error:', error);
    if (error.name === 'AIPolicyViolationError') {
      return res.status(403).json({
        success: false,
        code: error.code,
        message: error.message,
        operation: error.operation,
        securityVersion: error.securityVersion
      });
    }
    res.status(500).json({ success: false, message: 'Error checking eligibility' });
  }
};
