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
    // CleanAPI is the primary provider and OpenRouter the fallback. AI_PROVIDER can still pick another one ('openrouter',
    // 'gemini', 'openai'); with 'cleanapi' (the default when a CleanAPI key exists) or 'openrouter' the other one is
    // used as the fallback whenever its key is set.
    this.provider = process.env.AI_PROVIDER || (process.env.CLEANAPI_API_KEY ? 'cleanapi' : 'openrouter'); // 'cleanapi', 'openrouter', 'gemini', 'openai'
    this.blockedUntil = {};

    if (this.provider === 'gemini') {
      const { GoogleGenerativeAI } = require('@google/generative-ai');
      this.gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
      this.model = this.gemini.getGenerativeModel({ model: 'gemini-pro' });
    } else if (this.provider === 'openai') {
      const OpenAI = require('openai');
      this.openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    }

    const wantsCleanApi = this.provider === 'cleanapi' || (['cleanapi', 'openrouter'].includes(this.provider) && process.env.CLEANAPI_API_KEY);
    const wantsOpenRouter = this.provider === 'openrouter' || (this.provider === 'cleanapi' && process.env.OPENROUTER_API_KEY);
    if (wantsCleanApi) {
      const OpenAI = require('openai');
      this.cleanapi = new OpenAI({
        baseURL: process.env.CLEANAPI_BASE_URL || 'https://cleanapis.com/v1',
        apiKey: process.env.CLEANAPI_API_KEY || 'no-key',
      });
      this.cleanapiModel = process.env.CLEANAPI_MODEL || 'gemini-3.7-flash';
    }
    if (wantsOpenRouter) {
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

    const chain = this.chain();
    console.log(chain.length ? `🤖 AI providers: ${chain.map((n, i) => `${n}${i === 0 ? ' (primary)' : ' (fallback)'}`).join(' → ')}` : `🤖 AI Provider: ${this.provider.toUpperCase()}`);
  }

  // The providers to try, in order: the primary first, then the fallback when its key is set.
  chain() {
    const have = { cleanapi: Boolean(this.cleanapi && process.env.CLEANAPI_API_KEY), openrouter: Boolean(this.openrouter && process.env.OPENROUTER_API_KEY) };
    if (!['cleanapi', 'openrouter'].includes(this.provider)) return [];
    const order = this.provider === 'cleanapi' ? ['cleanapi', 'openrouter'] : ['openrouter', 'cleanapi'];
    return order.filter((name) => have[name]);
  }

  label(name) { return name === 'cleanapi' ? 'CleanAPI' : 'OpenRouter'; }

  // When a provider says it is rate limited (a free tier has a daily cap), skip it for a while and let the next one answer
  // straight away instead of spending a failed request on every message.
  coolingDown(name) {
    return this.chain().length > 1 && this.blockedUntil[name] && this.blockedUntil[name] > Date.now();
  }

  noteFailure(name, error) {
    if (this.chain().length < 2) return;
    const text = String(error?.message || error);
    // A billing or key problem will not fix itself in seconds: skip that provider for much longer than a rate limit.
    if (/\b(401|402|403)\b|billing|payment|unauthori[sz]ed|invalid api key|insufficient/i.test(text)) {
      this.blockedUntil[name] = Date.now() + (parseInt(process.env.AI_AUTH_COOLDOWN_MS, 10) || 30 * 60 * 1000);
      console.warn(`${this.label(name)} was refused (billing or key problem): using the other provider directly for the next 30 minutes. Fix the account to switch back.`);
    } else if (/\b(502|503|504)\b|being upgraded|temporarily unavailable|service unavailable|econnreset|etimedout|enotfound|fetch failed/i.test(text)) {
      // A provider that is down for maintenance: stop trying it for a minute instead of failing on every request first.
      this.blockedUntil[name] = Date.now() + (parseInt(process.env.AI_OUTAGE_COOLDOWN_MS, 10) || 60 * 1000);
      console.warn(`${this.label(name)} is unavailable: using the other provider directly for the next minute`);
    } else if (/\b429\b|rate limit/i.test(text)) {
      this.blockedUntil[name] = Date.now() + (parseInt(process.env.AI_PRIMARY_COOLDOWN_MS, 10) || 10 * 60 * 1000);
      console.warn(`${this.label(name)} is rate limited: using the other provider directly for the next few minutes`);
    }
  }

  // Runs `call(name, timeout)` on each provider in turn until one answers. A provider that is cooling down is skipped
  // unless it is the last one left. The primary gets `primaryTimeout`; the last provider gets the longer fallback timeout.
  async withFallback(call, { primaryTimeout, fallbackTimeout, retries }) {
    const chain = this.chain();
    const errors = [];
    for (let i = 0; i < chain.length; i++) {
      const name = chain[i];
      const last = i === chain.length - 1;
      if (!last && this.coolingDown(name)) { errors.push(`${this.label(name)} skipped while rate limited`); continue; }
      try {
        const result = await call(name, last ? fallbackTimeout : primaryTimeout, last, retries);
        if (i > 0) console.log(`↩️  Answered by the fallback (${this.label(name)})`);
        return result;
      } catch (error) {
        this.noteFailure(name, error);
        errors.push(`${this.label(name)}: ${error.message}`);
        console.warn(`⚠️  ${this.label(name)} failed: ${error.message}`);
      }
    }
    throw new Error(errors.length ? errors.join(' | ') : 'No AI provider is configured');
  }

  async chat(systemPrompt, userPrompt, options = {}) {
    // Synchronously enforce AI policy guard checks
    this.enforcePolicyGuard(systemPrompt, userPrompt, options);

    try {
      if (this.provider === 'gemini') {
        return await this.chatWithGemini(systemPrompt, userPrompt);
      } else if (this.provider === 'openai') {
        return await this.chatWithOpenAI(systemPrompt, userPrompt);
      } else if (['cleanapi', 'openrouter'].includes(this.provider)) {
        return await this.withFallback(
          (name, timeout, last, retries) => (name === 'cleanapi' ? this.chatWithCleanAPI(systemPrompt, userPrompt, timeout, retries !== undefined ? retries : (last ? 1 : 0)) : this.chatWithOpenRouter(systemPrompt, userPrompt, timeout)),
          { primaryTimeout: options.primaryTimeout || parseInt(process.env.AI_PRIMARY_TIMEOUT_MS, 10) || 25000, fallbackTimeout: options.fallbackTimeout || parseInt(process.env.AI_FALLBACK_TIMEOUT_MS, 10) || 60000, retries: options.retries }
        );
      }
      throw new Error(`Unknown AI provider: ${this.provider}`);
    } catch (error) {
      if (error.name === 'AIPolicyViolationError') throw error;
      console.error('AI chat error:', error);
      throw new Error(error.message || 'Failed to process AI query');
    }
  }

  // One planning step for an assistant that can use tools. `messages` and `tools` are in the OpenAI chat format.
  // The primary provider is tried first and the fallback answers if it fails (a model without tool support counts as failing).
  // Returns the model's message: { content, tool_calls }. The same Security V2 policy guard applies as for chat().
  async chatWithTools(messages, tools, options = {}) {
    this.enforcePolicyGuard(messages[0]?.content || '', messages.slice(1).map((m) => (typeof m.content === 'string' ? m.content : '')).join('\n'), options);

    const attempt = async (client, model, timeout) => {
      const response = await client.chat.completions.create(
        { model, messages, tools, tool_choice: 'auto', temperature: 0.2, max_tokens: 1200 },
        { timeout, maxRetries: 0 }
      );
      const message = response.choices?.[0]?.message;
      if (!message || (!message.content && !(message.tool_calls && message.tool_calls.length))) throw new Error('The model returned nothing');
      return message;
    };

    // Planning is a short answer, so a slow primary is given less time before the fallback takes over.
    return this.withFallback(
      (name, timeout) => (name === 'cleanapi'
        ? attempt(this.cleanapi, this.cleanapiModel || process.env.CLEANAPI_MODEL || 'gemini-3.7-flash', timeout)
        : attempt(this.openrouter, process.env.OPENROUTER_MODEL || 'openrouter/free', timeout)),
      { primaryTimeout: parseInt(process.env.AI_PLAN_PRIMARY_TIMEOUT_MS, 10) || 12000, fallbackTimeout: parseInt(process.env.AI_FALLBACK_TIMEOUT_MS, 10) || 60000 }
    );
  }

  // One request to a model that can see: `messages` may hold image and file parts. OpenRouter only, and standard accounts only
  // (the same policy guard as every other call). Returns the model's text. Throws when the model cannot answer.
  async chatVision(messages, options = {}) {
    const system = typeof messages[0]?.content === 'string' ? messages[0].content : '';
    this.enforcePolicyGuard(system, '', options);
    if (!this.openrouter) throw new Error('No vision provider is configured');
    const model = options.model || process.env.AI_VISION_MODEL || 'openai/gpt-4o';
    const body = { model, messages, temperature: 0, max_tokens: 12000, response_format: { type: 'json_object' } };
    if (options.plugins) body.plugins = options.plugins;
    const response = await this.openrouter.chat.completions.create(body, { timeout: options.timeout || 120000, maxRetries: 1 });
    const message = response.choices?.[0]?.message;
    const content = message?.content || (Array.isArray(message?.content) ? message.content.map((b) => b.text).join('') : '');
    if (!content) throw new Error('The vision model returned nothing');
    return content;
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

  async chatWithOpenRouter(systemPrompt, userPrompt, timeout = parseInt(process.env.AI_PRIMARY_TIMEOUT_MS, 10) || 25000) {
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
      }, { timeout, maxRetries: 0 });

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

  async chatWithCleanAPI(systemPrompt, userPrompt, timeout = parseInt(process.env.AI_FALLBACK_TIMEOUT_MS, 10) || 60000, retries = 1) {
    try {
      const model = this.cleanapiModel || process.env.CLEANAPI_MODEL || 'gemini-3.7-flash';
      const baseURL = process.env.CLEANAPI_BASE_URL || 'https://cleanapis.com/v1';
      console.log('CleanAPI: Sending request with model:', model, 'baseURL:', baseURL);

      const response = await this.cleanapi.chat.completions.create({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.3,
        max_tokens: 2000,
      }, { timeout, maxRetries: retries });

      console.log('CleanAPI: Response received:', {
        id: response.id,
        model: response.model,
        choicesLength: response.choices?.length,
      });

      const choice = response.choices?.[0];
      const message = choice?.message;
      let content = message?.content;

      if (!content && message?.reasoning) {
        content = message.reasoning;
      }
      if (!content && Array.isArray(message?.content)) {
        const textBlock = message.content.find((b) => b.type === 'text');
        if (textBlock) content = textBlock.text;
      }

      if (!content) {
        console.error('CleanAPI returned empty content. Full response:', JSON.stringify(response, null, 2));
        throw new Error('CleanAPI returned empty response');
      }

      console.log('CleanAPI: Content length:', content.length);
      return content;
    } catch (error) {
      console.error('CleanAPI API Error:', error.message);
      if (error.response) {
        console.error('Response data:', JSON.stringify(error.response.data, null, 2));
      }
      throw new Error(`CleanAPI API failed: ${error.message}`);
    }
  }

  // Check if AI is configured
  isConfigured() {
    if (this.provider === 'gemini') return !!process.env.GEMINI_API_KEY;
    if (this.provider === 'openai') return !!process.env.OPENAI_API_KEY;
    // CleanAPI / OpenRouter: configured when either one has a key
    return this.chain().length > 0;
  }
}

const serviceInstance = new AIService();
serviceInstance.AIPolicyViolationError = AIPolicyViolationError;
serviceInstance.AI_OPERATION = AI_OPERATION;
module.exports = serviceInstance;
