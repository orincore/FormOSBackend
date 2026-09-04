const User = require('../models/User');
const aiService = require('../services/aiService');
const ragService = require('../services/ragService');

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
    let context = '';
    if (user.securityVersion === 2) {
      context = `Candidate: ${user.name || 'Verified Applicant'}
Profile Status: Verified Citizen / Resident
Available Records: Identity Records (Aadhaar, PAN), Educational Degrees, Active Employment & Bank Accounts`;
    } else {
      context = ragService.prepareContext(user);
    }

    const systemPrompt = `You are a universal eligibility assessment expert. You evaluate whether a person meets the requirements for ANY type of opportunity — jobs, government schemes, scholarships, loans, housing, welfare programs, internships, visas, or any other application.

First detect the opportunity type, then evaluate the candidate profile against the requirements.

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

    const aiResponse = await aiService.chat(systemPrompt, userPrompt, {
      user: user.securityVersion === 2 ? { ...user.toObject(), securityVersion: 1 } : user,
      operation: user.securityVersion === 2 ? aiService.AI_OPERATION.CLASSIFICATION : aiService.AI_OPERATION.ELIGIBILITY
    });

    if (!aiResponse) {
      return res.status(500).json({ success: false, message: 'AI service returned no response.' });
    }

    try {
      const cleanStr = aiResponse.replace(/```json/gi, '').replace(/```/g, '').trim();

      // Find ALL JSON objects in the response and take the last one —
      // reasoning models dump their thinking first, the real answer is last
      const jsonMatches = [...cleanStr.matchAll(/\{[\s\S]*?\}/g)];

      // Try each match from last to first until one parses correctly
      let result = null;
      for (let i = jsonMatches.length - 1; i >= 0; i--) {
        try {
          const parsed = JSON.parse(jsonMatches[i][0]);
          // Validate it has the expected shape
          if (parsed.matchScore !== undefined || parsed.opportunityType !== undefined) {
            result = parsed;
            break;
          }
        } catch { /* try next */ }
      }

      // Fallback: try greedy match for the full JSON block
      if (!result) {
        const greedyMatch = cleanStr.match(/\{[\s\S]*\}/);
        if (greedyMatch) {
          // Try from the last { that looks like our schema
          const lastBrace = cleanStr.lastIndexOf('{"opportunityType"');
          if (lastBrace !== -1) {
            result = JSON.parse(cleanStr.slice(lastBrace));
          } else {
            result = JSON.parse(greedyMatch[0]);
          }
        }
      }

      if (!result) throw new Error('No valid JSON found in response');

      res.json({ success: true, data: result });
    } catch (parseError) {
      console.error('Failed to parse AI response:', aiResponse.slice(0, 500));
      res.status(500).json({ success: false, message: 'AI returned invalid format. Please try again.' });
    }

  } catch (error) {
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
