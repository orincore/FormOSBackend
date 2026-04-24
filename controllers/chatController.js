const ragService = require('../services/ragService');
const User = require('../models/User');

exports.chat = async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        success: false,
        message: 'Message is required'
      });
    }

    // Get user data
    const user = await User.findById(req.userId);

    // Query using RAG
    const response = await ragService.queryUserData(message, user);

    res.json({
      success: true,
      response
    });
  } catch (error) {
    console.error('Chat error:', error);
    if (error.message === 'AI service is not configured') {
      return res.status(503).json({
        success: false,
        message: 'AI is not configured. Add GEMINI_API_KEY, OPENAI_API_KEY, or OPENROUTER_API_KEY to enable chat.'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Error processing chat message'
    });
  }
};
