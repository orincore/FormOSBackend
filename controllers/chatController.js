const ragService = require('../services/ragService');
const User = require('../models/User');
const Document = require('../models/Document');

exports.chat = async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        success: false,
        message: 'Message is required'
      });
    }

    // Get fresh user data
    const user = await User.findById(req.userId);

    // A question about the member's own documents is answered from what was saved when they were added, the same way as on WhatsApp.
    // Anything else (how to apply for something, what a form field means) falls through to the general assistant below.
    if (user && user.securityVersion !== 2) {
      const grounded = await require('../services/whatsappAgent').answerGrounded({ user }, message);
      if (grounded?.found) return res.json({ success: true, response: grounded.text });
    }

    // Attach recent completed document extractions so RAG has full context
    const recentDocs = await Document.find({
      userId: req.userId,
      ocrStatus: 'completed',
      extractedText: { $exists: true, $ne: '' }
    })
      .sort({ uploadedAt: -1 })
      .limit(5)
      .select('originalName extractedText structuredData uploadedAt');

    user._recentDocuments = recentDocs;

    const response = await ragService.queryUserData(message, user);

    res.json({ success: true, response });
  } catch (error) {
    if (error.name === 'AIPolicyViolationError') {
      return res.status(403).json({
        success: false,
        code: error.code,
        message: error.message,
        operation: error.operation,
        securityVersion: error.securityVersion
      });
    }
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
