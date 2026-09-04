const aiService = require('./aiService');

class RAGService {
  async queryUserData(userQuestion, userData) {
    try {
      if (userData && userData.securityVersion === 2) {
        throw new aiService.AIPolicyViolationError(
          "Blocked: Operation 'RAG' is classified as LOCAL_ONLY/SENSITIVE and is blocked under Security V2.",
          'RAG',
          2
        );
      }

      // Return a user-friendly message instead of crashing when AI is not configured.
      if (!aiService.isConfigured()) {
        return 'AI service is not configured. Please add GEMINI_API_KEY, OPENAI_API_KEY, or OPENROUTER_API_KEY to your .env file.';
      }

      const directAnswer = this.getDirectAnswer(userQuestion, userData);
      if (directAnswer) {
        return directAnswer;
      }

      const context = this.prepareContext(userData);
      const systemPrompt = 'You are FormOS AI Assistant. You help users access their stored personal data securely.';

      const userPrompt = `Answer the user's question ONLY based on their stored data.

USER'S STORED DATA:
${context}

USER QUESTION: ${userQuestion}

INSTRUCTIONS:
- Answer ONLY using the data provided above
- If the information is not available, say "I don't have that information in your stored data"
- Be concise and helpful
- For sensitive data like Aadhaar or PAN, show masked version (****1234)
- If asked to "fill details" or "autofill", provide all available information in a structured format

ANSWER:`;

      return await aiService.chat(systemPrompt, userPrompt, {
        user: userData,
        operation: aiService.AI_OPERATION.RAG
      });
    } catch (error) {
      if (error.name === 'AIPolicyViolationError') {
        throw error;
      }
      console.error('RAG query error:', error);
      throw new Error('Failed to process AI query');
    }
  }

  getNormalizedProfile(userData = {}) {
    const extractedData = userData.extractedData || {};
    const derivedName = [
      extractedData.firstName,
      extractedData.middleName,
      extractedData.lastName,
    ].filter(Boolean).join(' ').trim();
    // Fall back to auth-level name/email/phone if not in extractedData
    const normalizedName = extractedData.fullName || derivedName || userData.name || '';
    const normalizedEmail = extractedData.email || userData.email || '';
    const normalizedPhone = extractedData.phone || userData.phone || '';

    return {
      name: normalizedName,
      email: normalizedEmail,
      phone: normalizedPhone,
      dateOfBirth: extractedData.dateOfBirth || '',
      aadhaarNumber: extractedData.aadhaarNumber || '',
      panNumber: extractedData.panNumber || '',
      address: extractedData.address || '',
      customFields: extractedData.customFields || null,
    };
  }

  getDirectAnswer(userQuestion, userData) {
    const question = String(userQuestion || '').trim().toLowerCase();
    if (!question) return null;

    const profile = this.getNormalizedProfile(userData);
    const isNameQuestion = /\b(what('?s| is)?\s+my\s+name|my\s+name)\b/.test(question);
    const isEmailQuestion = /\b(what('?s| is)?\s+my\s+email|my\s+email|email address)\b/.test(question);
    const isPhoneQuestion = /\b(what('?s| is)?\s+my\s+(phone|mobile|number)|my\s+(phone|mobile|number))\b/.test(question);
    const isDobQuestion = /\b(what('?s| is)?\s+my\s+(dob|date of birth|birth date)|my\s+(dob|date of birth|birth date))\b/.test(question);
    const isAddressQuestion = /\b(what('?s| is)?\s+my\s+address|my\s+address)\b/.test(question);
    const wantsAllDetails = /\b(show|list|display|tell me)\b.*\b(details|data|profile|information)\b|\bwhat do you know about me\b/.test(question);

    if (isNameQuestion) {
      return profile.name
        ? `Your name is ${profile.name}.`
        : "I don't have your name in your stored data.";
    }

    if (isEmailQuestion) {
      return profile.email
        ? `Your email is ${profile.email}.`
        : "I don't have your email in your stored data.";
    }

    if (isPhoneQuestion) {
      return profile.phone
        ? `Your phone number is ${profile.phone}.`
        : "I don't have your phone number in your stored data.";
    }

    if (isDobQuestion) {
      return profile.dateOfBirth
        ? `Your date of birth is ${profile.dateOfBirth}.`
        : "I don't have your date of birth in your stored data.";
    }

    if (isAddressQuestion) {
      return profile.address
        ? `Your address is ${profile.address}.`
        : "I don't have your address in your stored data.";
    }

    if (wantsAllDetails) {
      const lines = [];
      if (profile.name) lines.push(`Name: ${profile.name}`);
      if (profile.email) lines.push(`Email: ${profile.email}`);
      if (profile.phone) lines.push(`Phone: ${profile.phone}`);
      if (profile.dateOfBirth) lines.push(`Date of Birth: ${profile.dateOfBirth}`);
      if (profile.address) lines.push(`Address: ${profile.address}`);
      if (profile.aadhaarNumber) lines.push(`Aadhaar: ****${profile.aadhaarNumber.slice(-4)}`);
      if (profile.panNumber) lines.push(`PAN: ****${profile.panNumber.slice(-4)}`);

      return lines.length > 0
        ? lines.join('\n')
        : "I don't have any stored profile details available yet.";
    }

    return null;
  }

  prepareContext(userData) {
    const profile = this.getNormalizedProfile(userData);
    let context = '';

    if (profile.name) context += `Name: ${profile.name}\n`;
    if (profile.email) context += `Email: ${profile.email}\n`;
    if (profile.phone) context += `Phone: ${profile.phone}\n`;
    if (profile.dateOfBirth) context += `Date of Birth: ${profile.dateOfBirth}\n`;
    if (profile.aadhaarNumber) context += `Aadhaar: ****${profile.aadhaarNumber.slice(-4)}\n`;
    if (profile.panNumber) context += `PAN: ****${profile.panNumber.slice(-4)}\n`;
    if (profile.address) context += `Address: ${profile.address}\n`;

    if (profile.customFields) {
      context += '\nAdditional Information:\n';
      Object.entries(profile.customFields).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          context += `${key}: ${value}\n`;
        }
      });
    }

    // Include text extracted from recently uploaded documents
    const recentDocs = userData._recentDocuments;
    if (recentDocs && recentDocs.length > 0) {
      context += '\nRecently Uploaded Documents:\n';
      recentDocs.forEach((doc) => {
        context += `\n--- ${doc.originalName} ---\n`;
        if (doc.extractedText) {
          // Include up to 1000 chars of extracted text per doc
          context += doc.extractedText.substring(0, 1000);
          if (doc.extractedText.length > 1000) context += '...(truncated)';
          context += '\n';
        }
      });
    }

    return context || 'No data available';
  }

  async generateAutofillData(userData) {
    const profile = this.getNormalizedProfile(userData);
    const fullName = profile.name || '';

    return {
      name: fullName,
      firstName: fullName.split(' ')[0] || '',
      lastName: fullName.split(' ').slice(1).join(' ') || '',
      email: profile.email || '',
      phone: profile.phone || '',
      dateOfBirth: profile.dateOfBirth || '',
      address: profile.address || '',
      aadhaar: profile.aadhaarNumber || '',
      pan: profile.panNumber || ''
    };
  }
}

module.exports = new RAGService();
