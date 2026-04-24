const User = require('../models/User');
const aiService = require('../services/aiService');
const ragService = require('../services/ragService');

exports.checkEligibility = async (req, res) => {
  try {
    const { jd } = req.body;
    
    if (!jd) {
      return res.status(400).json({ success: false, message: 'Job description is required' });
    }

    if (!aiService.isConfigured()) {
      return res.status(500).json({ success: false, message: 'AI service is not configured' });
    }

    // Get user and their extracted data
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Use RAG service to format the user's data context
    const context = ragService.prepareContext(user);

    const systemPrompt = `You are an expert HR Technical Recruiter and Career Coach. 
Your task is to evaluate a candidate's eligibility for a specific Job Description (JD) based on their stored profile data.

You must reply ONLY with a valid JSON object matching this exact structure, with NO markdown formatting, NO backticks, and NO additional text:
{
  "matchScore": <number between 0-100>,
  "isEligible": <boolean>,
  "strengths": ["list", "of", "matching", "skills"],
  "missingSkills": [
    {
      "skill": "name of missing skill",
      "suggestion": "Specific course or certification to acquire this skill"
    }
  ],
  "reasoning": "Brief 2-3 sentence explanation of the evaluation"
}`;

    const userPrompt = `CANDIDATE DATA:
${context}

JOB DESCRIPTION:
${jd}

Evaluate the candidate based on the job description and provide the JSON response.`;

    const aiResponse = await aiService.chat(systemPrompt, userPrompt);
    
    // Log the raw AI response for debugging
    console.log('=== AI Response ===');
    console.log('Type:', typeof aiResponse);
    console.log('Value:', aiResponse);
    console.log('===================');
    
    // Check if response is null or undefined
    if (!aiResponse) {
      console.error('AI service returned null or undefined response');
      return res.status(500).json({ 
        success: false, 
        message: 'AI service returned no response. Please check your AI configuration.' 
      });
    }
    
    try {
      // Clean up potential markdown formatting from AI response (e.g., ```json ... ```)
      const cleanJsonStr = aiResponse.replace(/```json/g, '').replace(/```/g, '').trim();
      const result = JSON.parse(cleanJsonStr);
      
      res.json({
        success: true,
        data: result
      });
    } catch (parseError) {
      console.error('Failed to parse AI response as JSON:', aiResponse);
      console.error('Parse error:', parseError);
      res.status(500).json({ 
        success: false, 
        message: 'AI returned invalid format. Raw response logged to console.' 
      });
    }

  } catch (error) {
    console.error('Eligibility check error:', error);
    res.status(500).json({
      success: false,
      message: 'Error checking eligibility'
    });
  }
};
