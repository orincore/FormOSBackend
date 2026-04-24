// @google/generative-ai is loaded lazily only when AI_PROVIDER=gemini

class AIService {
  constructor() {
    this.provider = process.env.AI_PROVIDER || 'openrouter'; // 'gemini', 'openai', or 'openrouter'
    
    if (this.provider === 'gemini') {
      const { GoogleGenerativeAI } = require('@google/generative-ai');
      this.gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
      this.model = this.gemini.getGenerativeModel({ model: 'gemini-pro' });
    } else if (this.provider === 'openai') {
      const OpenAI = require('openai');
      this.openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    } else if (this.provider === 'openrouter') {
      const OpenAI = require('openai');
      this.openrouter = new OpenAI({
        baseURL: 'https://openrouter.ai/api/v1',
        apiKey: process.env.OPENROUTER_API_KEY || 'no-key',
        defaultHeaders: {
          'HTTP-Referer': process.env.FRONTEND_URL || 'http://localhost:3001',
          'X-Title': 'FormOS'
        }
      });
    }

    console.log(`🤖 AI Provider: ${this.provider.toUpperCase()}`);
  }

  async chat(systemPrompt, userPrompt) {
    try {
      if (this.provider === 'gemini') {
        return await this.chatWithGemini(systemPrompt, userPrompt);
      } else if (this.provider === 'openai') {
        return await this.chatWithOpenAI(systemPrompt, userPrompt);
      } else if (this.provider === 'openrouter') {
        return await this.chatWithOpenRouter(systemPrompt, userPrompt);
      }
    } catch (error) {
      console.error('AI chat error:', error);
      throw new Error('Failed to process AI query');
    }
  }

  async chatWithGemini(systemPrompt, userPrompt) {
    const fullPrompt = `${systemPrompt}\n\n${userPrompt}`;
    const result = await this.model.generateContent(fullPrompt);
    const response = await result.response;
    return response.text();
  }

  async chatWithOpenAI(systemPrompt, userPrompt) {
    const response = await this.openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: 0.3,
      max_tokens: 500
    });

    return response.choices[0].message.content;
  }

  async chatWithOpenRouter(systemPrompt, userPrompt) {
    try {
      console.log('OpenRouter: Sending request with model:', process.env.OPENROUTER_MODEL);
      
      const response = await this.openrouter.chat.completions.create({
        model: process.env.OPENROUTER_MODEL || 'google/gemini-2.0-flash-exp:free',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.3,
        max_tokens: 500
      });

      console.log('OpenRouter: Response received:', {
        id: response.id,
        model: response.model,
        hasChoices: !!response.choices,
        choicesLength: response.choices?.length
      });

      const content = response.choices[0]?.message?.content;
      
      if (!content) {
        console.error('OpenRouter returned empty content. Full response:', JSON.stringify(response, null, 2));
        throw new Error('OpenRouter returned empty response');
      }
      
      console.log('OpenRouter: Content length:', content.length);
      return content;
    } catch (error) {
      console.error('OpenRouter API Error Details:');
      console.error('- Message:', error.message);
      console.error('- Status:', error.status);
      console.error('- Code:', error.code);
      
      if (error.response) {
        console.error('- Response status:', error.response.status);
        console.error('- Response data:', JSON.stringify(error.response.data, null, 2));
      }
      
      if (error.error) {
        console.error('- Error object:', JSON.stringify(error.error, null, 2));
      }
      
      throw new Error(`OpenRouter API failed: ${error.message}`);
    }
  }

  // Check if AI is configured
  isConfigured() {
    if (this.provider === 'gemini') {
      return !!process.env.GEMINI_API_KEY;
    } else if (this.provider === 'openai') {
      return !!process.env.OPENAI_API_KEY;
    } else if (this.provider === 'openrouter') {
      return !!process.env.OPENROUTER_API_KEY;
    }
    return false;
  }
}

module.exports = new AIService();
