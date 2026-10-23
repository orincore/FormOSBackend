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

  // Everything saved from the member's documents: a resume (jobs with dates, education, skills, projects), marksheets, certificates,
  // IDs (numbers masked) and so on. This is what a job or scheme is judged against, not just the names of the files.
  const blocks = await require('../services/documentRecords').recordsFor(user, { profile: false, maxChars: 30000 });
  if (blocks.length) {
    context += '\nDocuments the candidate has uploaded, with everything that was read from each:\n\n' + blocks.join('\n\n') + '\n';
  } else {
    context += '\nDocuments uploaded: none.\n';
  }
  context += '\nAnything not listed above is NOT known. Do not assume it.\n';
  return context;
}

// Is this the description of a job (not a scheme, loan or scholarship)? A job is judged against a resume, so one is needed first.
const JOB_WORDS = /\b(job|jobs|role|position|vacanc(?:y|ies)|opening|hiring|recruit\w*|employment|employer|full[- ]?time|part[- ]?time|internship|intern|fresher|work experience|years? of experience|\d+\+?\s*(?:years?|yrs?)|responsibilit\w+|skills?|qualifications?|salary|ctc|lpa|engineer|developer|manager|analyst|designer|executive|consultant|architect|administrator|associate|officer|assistant|programmer|tester|devops|backend|frontend|full[- ]?stack)\b/gi;
// A job posting is built the same way everywhere: a role, a summary, responsibilities, qualifications, skills. Recognising that
// structure (several of its headings) is stronger than counting keywords.
const JD_HEADINGS = /\b(job description|job summary|role summary|key responsibilities|responsibilities|required qualifications?|preferred qualifications?|minimum qualifications?|qualifications|requirements|technical skills|skills required|about the (?:role|job|position)|what you(?:'|\u2019)ll (?:do|bring|need)|who you are|years? of experience|equal opportunity|we are (?:seeking|looking|hiring)|apply (?:now|today)|job type|employment type|work location|notice period|ctc|salary range)\b/gi;

function looksLikeJob(text) {
  const t = String(text || '');
  const hits = new Set((t.match(JOB_WORDS) || []).map((w) => w.toLowerCase()));
  const headings = new Set((t.match(JD_HEADINGS) || []).map((w) => w.toLowerCase()));
  const other = /\b(scholarship|scheme|yojana|subsidy|loan|visa|pension|housing|grant|fellowship)\b/i.test(t);
  if (other) return hits.size >= 5;
  if (headings.size >= 3 && hits.size >= 1) return true; // laid out like a posting
  return hits.size >= 2;
}

// For a long message the rules cannot settle, a cheap AI check says whether it is a job posting. Used only for long text.
async function aiLooksLikeJob(user, text) {
  try {
    const reply = await aiService.chat('You decide whether a message is a job posting or job description (a role with duties, qualifications or skills an employer wants). Answer with exactly one word: JOB or NOT_JOB.', String(text).slice(0, 2500), {
      user: { securityVersion: 1, _id: user?._id }, operation: aiService.AI_OPERATION.CLASSIFICATION, primaryTimeout: 15000,
    });
    return /^\s*JOB\b/i.test(String(reply || ''));
  } catch { return false; }
}

const NEEDS_RESUME = {
  needsResume: true,
  message: 'Job checks use your resume, and you have not added one yet. Add your resume in Documents on the portal, or send it here in WhatsApp as a PDF or photo. Then ask again.',
  chatMessage: 'Job checks use your resume, and I do not have one for you yet.\n\nSend your resume here as a PDF or a photo, or add it in Documents on the portal. I will keep this job, and once your resume is read I will check it for you.',
};

// The whole check, shared by the app and the WhatsApp assistant: builds the profile from what is
// stored, asks the AI, and returns a clean result. Throws with httpStatus on failure.
async function evaluateEligibility(user, jd, extra = {}) {
  // A job needs a resume first (standard accounts, where the documents can be read). The caller shows the message; nothing is judged.
  if (user.securityVersion !== 2 && !extra.skipResume && looksLikeJob(jd) && !(await require('../services/documentRecords').findResume(user._id))) return NEEDS_RESUME;
  const context = await buildContext(user, extra.v2Facts || null);

  const systemPrompt = `You are a universal eligibility assessment expert. You evaluate whether a person meets the requirements for ANY type of opportunity: jobs, government schemes, scholarships, loans, housing, welfare programs, internships, visas, or any other application.

First detect the opportunity type, then evaluate the candidate profile against the requirements.

GROUNDING RULES:
- Use ONLY facts written in CANDIDATE PROFILE (the profile lines and the documents with everything read from them). If a fact is not there, it is unknown: never say the candidate has or lacks something unless the profile shows it.
- Something unknown goes in missingRequirements with a suggestion to provide or confirm it. Do not list it under strengths.
- A requirement the profile clearly satisfies (for example age, state, document held) goes in strengths and must NOT appear in missingRequirements.
- Compare numbers yourself: use the Age line for age limits, the Address and State lines for location.
- Today's date is ${new Date().toLocaleDateString('en-GB')}.
- For a JOB: judge it against the resume and the other documents. Skills: compare each required skill with the Skills lines, the jobs and the projects (a skill used in a project or job counts). Experience: work out the years from the From and To dates of the jobs (a job that says Present runs to today; add the jobs up and do not double count overlaps) and say the figure you found. Education: compare the required degree, field and minimum marks with the Education entries, marksheets and certificates. Certifications, languages and location likewise. A requirement the documents do not mention is unknown, not failed.
- Name the document a fact comes from in the strengths and the missing list, for example "5 years of experience (Resume: Infosys 06/2021 to Present)".

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
    let aiResponse;
    try {
      // Judging a candidate against a job is careful work (dates, sums, many records): the stronger model does it.
      aiResponse = await aiService.chatVision([{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }], { ...options, model: process.env.AI_ANSWER_MODEL || 'openai/gpt-4o', maxTokens: 1800, timeout: 60000 });
    } catch (error) {
      if (error.name === 'AIPolicyViolationError') throw error;
      aiResponse = await aiService.chat(systemPrompt, userPrompt, options);
    }
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
exports.looksLikeJob = looksLikeJob;
exports.aiLooksLikeJob = aiLooksLikeJob;
exports.NEEDS_RESUME = NEEDS_RESUME;
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

    const result = await evaluateEligibility(user, jd, { skipResume: req.body.skipResume === true });
    if (result.needsResume) return res.json({ success: true, needsResume: true, message: result.message });
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

// GET /api/eligibility/context: what a check will use, so the page can say so before anything is pasted.
exports.context = async (req, res) => {
  try {
    const documentRecords = require('../services/documentRecords');
    const resume = await documentRecords.findResume(req.userId);
    const documents = await Document.countDocuments({ userId: req.userId, securityVersion: { $ne: 2 }, ocrStatus: 'completed' });
    return res.json({ success: true, resume: resume ? { title: resume.structuredData?.documentTitle || resume.originalName, addedAt: resume.uploadedAt } : null, documents });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Could not load what the check will use.' });
  }
};
