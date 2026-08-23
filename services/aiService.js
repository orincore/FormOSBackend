// @google/generative-ai is loaded lazily only when AI_PROVIDER=gemini

class AIPolicyViolationError extends Error {
  constructor(message, operation, securityVersion) {
    super(message);
    this.name = 'AIPolicyViolationError';
    this.code = 'AI_POLICY_VIOLATION';
    this.operation = operation;
    this.securityVersion = securityVersion;
  }
}

const AI_OPERATION = {
  SCHEMA_MAPPING: 'SCHEMA_MAPPING',
  CLASSIFICATION: 'CLASSIFICATION',
  SENSITIVE_ANALYSIS: 'SENSITIVE_ANALYSIS',
  RAG: 'RAG',
  ELIGIBILITY: 'ELIGIBILITY'
};

const OPERATION_POLICIES = {
  [AI_OPERATION.SCHEMA_MAPPING]: 'SAFE_FOR_CLOUD',
  [AI_OPERATION.CLASSIFICATION]: 'SAFE_FOR_CLOUD',
  [AI_OPERATION.SENSITIVE_ANALYSIS]: 'LOCAL_ONLY',
  [AI_OPERATION.RAG]: 'LOCAL_ONLY',
  [AI_OPERATION.ELIGIBILITY]: 'LOCAL_ONLY'
};

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

  async chat(systemPrompt, userPrompt, options = {}) {
    // Synchronously enforce AI policy guard checks
    this.enforcePolicyGuard(systemPrompt, userPrompt, options);

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

  enforcePolicyGuard(systemPrompt, userPrompt, options) {
    const user = options.user;
    const operation = options.operation;

    // Rule 1: Fail closed if operation context is missing or unrecognized
    if (!operation || !AI_OPERATION[operation]) {
      throw new AIPolicyViolationError(
        'Blocked: Unidentified or missing operation. Fails closed under Security V2.',
        operation || 'UNKNOWN',
        2
      );
    }

    // Rule 2: Fail closed if trusted user context is missing
    if (!user) {
      throw new AIPolicyViolationError(
        'Blocked: Missing authenticated user context. Fails closed under Security V2.',
        operation,
        2
      );
    }

    const securityVersion = user.securityVersion || 1;

    // V1 users bypass AI policy checks during migration
    if (securityVersion === 1) {
      return;
    }

    if (securityVersion === 2) {
      // 1. Check operation classification
      const category = OPERATION_POLICIES[operation] || 'LOCAL_ONLY';
      if (category !== 'SAFE_FOR_CLOUD') {
        throw new AIPolicyViolationError(
          `Blocked: Operation '${operation}' is classified as LOCAL_ONLY/SENSITIVE and is blocked under Security V2.`,
          operation,
          securityVersion
        );
      }

      // 2. Secondary defense-in-depth scanner for SAFE_FOR_CLOUD operations
      const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;
      const phoneRegex = /\+?\d{10,12}/;
      const panRegex = /[A-Z]{5}\d{4}[A-Z]/i;
      const aadhaarRegex = /\d{4}\s?\d{4}\s?\d{4}/;
      const passportRegex = /[A-Z]\d{7}/i;
      const longTokenRegex = /[a-zA-Z0-9_-]{15,}/;

      const combinedPrompt = `${systemPrompt || ''}\n${userPrompt || ''}`;

      if (emailRegex.test(combinedPrompt)) {
        throw new AIPolicyViolationError('Blocked: Request payload contains sensitive data (email) under Security V2.', operation, securityVersion);
      }
      if (phoneRegex.test(combinedPrompt)) {
        throw new AIPolicyViolationError('Blocked: Request payload contains sensitive data (phone) under Security V2.', operation, securityVersion);
      }
      if (panRegex.test(combinedPrompt)) {
        throw new AIPolicyViolationError('Blocked: Request payload contains sensitive data (PAN) under Security V2.', operation, securityVersion);
      }
      if (aadhaarRegex.test(combinedPrompt)) {
        throw new AIPolicyViolationError('Blocked: Request payload contains sensitive data (Aadhaar) under Security V2.', operation, securityVersion);
      }
      if (passportRegex.test(combinedPrompt)) {
        throw new AIPolicyViolationError('Blocked: Request payload contains sensitive data (Passport ID) under Security V2.', operation, securityVersion);
      }
      if (longTokenRegex.test(combinedPrompt)) {
        if (this.containsLongSensitiveToken(userPrompt)) {
          throw new AIPolicyViolationError('Blocked: Request payload contains sensitive data (long identifier token) under Security V2.', operation, securityVersion);
        }
      }
    }
  }

  containsLongSensitiveToken(text) {
    if (!text) return false;
    const tokens = text.match(/[a-zA-Z0-9_-]{15,}/g) || [];
    for (const t of tokens) {
      const lowerT = t.toLowerCase();
      if (
        lowerT === 'opportunitytype' ||
        lowerT === 'missingrequirements' ||
        lowerT === 'date_of_birth' ||
        lowerT === 'passport_number' ||
        lowerT === 'joining_date' ||
        lowerT === 'employee_id' ||
        lowerT === 'google-generative-ai' ||
        lowerT === 'openrouter_model'
      ) {
        continue;
      }
      return true;
    }
    return false;
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
      const model = process.env.OPENROUTER_MODEL || 'google/gemini-2.0-flash-exp:free';
      console.log('OpenRouter: Sending request with model:', model);
      
      const response = await this.openrouter.chat.completions.create({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.3,
        max_tokens: 2000,
      });

      console.log('OpenRouter: Response received:', {
        id: response.id,
        model: response.model,
        choicesLength: response.choices?.length,
      });

      const choice = response.choices?.[0];
      const message = choice?.message;

      // Standard content field
      let content = message?.content;

      // Some reasoning models (e.g. deepseek-r1, nemotron) put the final answer
      // in message.reasoning or a non-standard text field when content is empty
      if (!content && message?.reasoning) {
        content = message.reasoning;
      }

      // OpenRouter sometimes wraps it in a non-standard `text` array
      if (!content && Array.isArray(message?.content)) {
        const textBlock = message.content.find((b) => b.type === 'text');
        if (textBlock) content = textBlock.text;
      }

      if (!content) {
        console.error('OpenRouter returned empty content. Full response:', JSON.stringify(response, null, 2));
        throw new Error('OpenRouter returned empty response');
      }

      console.log('OpenRouter: Content length:', content.length);
      return content;
    } catch (error) {
      console.error('OpenRouter API Error:', error.message);
      if (error.response) {
        console.error('Response data:', JSON.stringify(error.response.data, null, 2));
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

const serviceInstance = new AIService();
serviceInstance.AIPolicyViolationError = AIPolicyViolationError;
serviceInstance.AI_OPERATION = AI_OPERATION;
module.exports = serviceInstance;
