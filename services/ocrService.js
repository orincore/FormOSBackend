const Tesseract = require('tesseract.js');
const path = require('path');
const fs = require('fs').promises;
const pdfParse = require('pdf-parse');
const { fromPath } = require('pdf2pic');

class OCRService {
  async extractText(filePath) {
    try {
      const ext = path.extname(filePath).toLowerCase();
      
      if (ext === '.pdf') {
        return await this.extractTextFromPDF(filePath);
      } else {
        return await this.extractTextFromImage(filePath);
      }
    } catch (error) {
      console.error('OCR extraction error:', error);
      throw new Error('Failed to extract text from document');
    }
  }

  // Reads text straight from memory, so a document that must stay encrypted at rest never touches the disk.
  // Photos are read by OCR; PDFs that contain real text are read directly. A scanned PDF yields no text.
  async extractTextFromBuffer(buffer, mimeType) {
    try {
      if (mimeType === 'application/pdf') {
        const parsed = await pdfParse(buffer);
        return (parsed.text || '').trim().length > 30 ? parsed.text : '';
      }
      const result = await Tesseract.recognize(buffer, 'eng');
      return result.data.text || '';
    } catch (error) {
      console.error('In-memory OCR error:', error.message);
      return '';
    }
  }

  async extractTextFromImage(imagePath) {
    const result = await Tesseract.recognize(imagePath, 'eng', {
      logger: (m) => console.log(m)
    });
    return result.data.text;
  }

  async extractTextFromPDF(pdfPath) {
    try {
      // First, try to extract text directly from PDF
      const dataBuffer = await fs.readFile(pdfPath);
      const pdfData = await pdfParse(dataBuffer);
      
      if (pdfData.text && pdfData.text.trim().length > 50) {
        console.log('✅ Extracted text directly from PDF');
        return pdfData.text;
      }

      // If PDF is image-based (scanned), convert to images and use OCR
      console.log('📄 PDF appears to be image-based, using OCR...');
      return await this.extractTextFromScannedPDF(pdfPath);
    } catch (error) {
      console.error('PDF extraction error:', error);
      // If PDF parsing fails, try OCR on scanned PDF
      console.log('📄 Trying OCR on PDF...');
      try {
        return await this.extractTextFromScannedPDF(pdfPath);
      } catch (ocrError) {
        console.error('PDF OCR error:', ocrError);
        return 'Failed to extract text from PDF. The file may be encrypted or corrupted.';
      }
    }
  }

  async extractTextFromScannedPDF(pdfPath) {
    try {
      const options = {
        density: 300,
        saveFilename: 'pdf-page',
        savePath: path.dirname(pdfPath),
        format: 'png',
        width: 2000,
        height: 2000
      };

      const convert = fromPath(pdfPath, options);
      
      // Convert first 3 pages (to avoid processing huge PDFs)
      const pageLimit = 3;
      let allText = '';

      for (let i = 1; i <= pageLimit; i++) {
        try {
          const pageImage = await convert(i, { responseType: 'image' });
          
          if (pageImage && pageImage.path) {
            const result = await Tesseract.recognize(pageImage.path, 'eng');
            allText += result.data.text + '\n\n';
            
            // Clean up temporary image
            await fs.unlink(pageImage.path).catch(() => {});
          }
        } catch (pageError) {
          // Page doesn't exist or error, stop processing
          break;
        }
      }

      return allText.trim() || 'No text could be extracted from PDF';
    } catch (error) {
      console.error('Scanned PDF OCR error:', error);
      return 'PDF processing failed. Please try uploading as an image.';
    }
  }

  // Aadhaar numbers carry a Verhoeff check digit, so a random 12-digit run (a VID, a phone number)
  // is rejected instead of being saved as the Aadhaar number.
  isValidAadhaar(digits) {
    if (!/^[2-9]\d{11}$/.test(digits)) return false;
    const d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
    const pm = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
    let c = 0;
    digits.split('').reverse().forEach((ch, i) => { c = d[c][pm[i % 8][Number(ch)]]; });
    return c === 0;
  }

  detectDocumentType(text) {
    const t = text.toUpperCase();
    if (/INCOME TAX DEPARTMENT|PERMANENT ACCOUNT NUMBER/.test(t) || /\b[A-Z]{5}\d{4}[A-Z]\b/.test(t) && !/AADHAAR|UIDAI/.test(t)) return 'pan';
    if (/AADHAAR|UIDAI|UNIQUE IDENTIFICATION|आधार/.test(t)) return 'aadhaar';
    if (/REPUBLIC OF INDIA/.test(t) && /PASSPORT/.test(t)) return 'passport';
    if (/DRIVING LICEN[CS]E|UNION OF INDIA.*LICEN/.test(t)) return 'license';
    if (/ELECTION COMMISSION|ELECTOR/.test(t)) return 'voter';
    return 'other';
  }

  toTitleCase(value) {
    return value.toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
  }

  // Dates are stored as DD/MM/YYYY whatever the card printed.
  normalizeDate(raw) {
    const m = String(raw || '').match(/(\d{1,2})\s*[-\/.]\s*(\d{1,2})\s*[-\/.]\s*(\d{4})/);
    if (!m) return '';
    const [, dd, mm, yyyy] = m;
    if (Number(mm) < 1 || Number(mm) > 12 || Number(dd) < 1 || Number(dd) > 31) return '';
    return `${dd.padStart(2, '0')}/${mm.padStart(2, '0')}/${yyyy}`;
  }

  parseStructuredData(text) {
    const data = {};
    if (!text || text.length < 10 || /processing failed|Failed to extract|No text could be extracted/i.test(text)) {
      return data;
    }
    const flat = text.replace(/[ \t]+/g, ' ');

    const type = this.detectDocumentType(flat);
    if (type !== 'other') data.documentType = type;

    // Aadhaar: 4-4-4 groups, but only a number that passes the check digit counts.
    for (const m of flat.matchAll(/\b([2-9]\d{3})\s?(\d{4})\s?(\d{4})\b/g)) {
      const digits = m[1] + m[2] + m[3];
      if (this.isValidAadhaar(digits)) { data.aadhaarNumber = digits; break; }
    }

    const panMatch = flat.match(/\b[A-Z]{5}\d{4}[A-Z]\b/);
    if (panMatch) data.panNumber = panMatch[0];

    const passport = flat.match(/(?:Passport\s*(?:No\.?|Number)[:\s]*)\b([A-PR-WY][1-9]\d{6}[1-9])\b/i);
    if (passport) data.passportNumber = passport[1].toUpperCase();

    const license = flat.match(/\b([A-Z]{2}[-\s]?\d{2}[-\s]?(?:19|20)\d{2}\d{7})\b/);
    if (license && type === 'license') data.drivingLicenseNumber = license[1].replace(/[\s-]/g, '');

    // Name: a labelled line, in any case. On a PAN card the name is the line after "Name".
    const lines = flat.split('\n').map((l) => l.trim()).filter(Boolean);
    const nameLine = (label) => {
      for (let i = 0; i < lines.length; i++) {
        const same = lines[i].match(new RegExp(`^${label}\\s*[:\\-]\\s*([A-Za-z][A-Za-z .']{2,60})$`, 'i'));
        if (same) return same[1].trim();
        if (new RegExp(`^${label}\\s*$`, 'i').test(lines[i]) && lines[i + 1] && /^[A-Za-z][A-Za-z .']{2,60}$/.test(lines[i + 1])) return lines[i + 1].trim();
      }
      return '';
    };
    const name = nameLine('(?:Full\\s+)?Name');
    if (name && !/father|mother/i.test(name)) data.fullName = this.toTitleCase(name);
    if (!data.fullName && type === 'aadhaar') {
      // On an Aadhaar card the holder's name is printed on the line above the date of birth.
      const at = lines.findIndex((l) => /^(?:DOB|D\.O\.B|Date\s+of\s+Birth|Year\s+of\s+Birth)/i.test(l));
      const above = at > 0 ? lines[at - 1] : '';
      if (/^[A-Za-z][A-Za-z .']{2,50}$/.test(above) && above.trim().split(/\s+/).length <= 5 && !/government|india|authority|aadhaar/i.test(above)) data.fullName = this.toTitleCase(above.trim());
    }
    const father = nameLine("Father'?s?\\s+Name") || nameLine('S/O|Son of|D/O|Daughter of|W/O');
    if (father) data.fatherName = this.toTitleCase(father);

    const dob = flat.match(/(?:DOB|D\.O\.B|Date\s+of\s+Birth|Birth\s+Date)\s*[:\-]?\s*(\d{1,2}\s*[-\/.]\s*\d{1,2}\s*[-\/.]\s*\d{4})/i)
      || (type === 'pan' ? flat.match(/\b(\d{2}\/\d{2}\/\d{4})\b/) : null);
    if (dob) data.dateOfBirth = this.normalizeDate(dob[1]);
    else {
      const yob = flat.match(/Year\s+of\s+Birth\s*[:\-]?\s*(\d{4})/i);
      if (yob) data.yearOfBirth = yob[1];
    }

    const gender = flat.match(/\b(Male|Female|Transgender)\b/i) || flat.match(/\/\s*(MALE|FEMALE)\b/i);
    if (gender) data.gender = this.toTitleCase(gender[1]);

    const phone = flat.match(/(?:Phone|Mobile|Mob|Tel)\.?\s*(?:No\.?)?\s*[:\-]?\s*(\+?91[\s-]?)?([6-9]\d{9})\b/i);
    if (phone) data.phone = phone[2];

    const email = flat.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
    if (email) data.email = email[0];

    const pin = flat.match(/\b([1-9]\d{5})\b(?!\d)/);
    const clean = (a) => a.replace(/\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/g, '').replace(/VID\s*:?\s*\d[\d\s]*/gi, '')
      .replace(/Details\s+as\s+on:?\s*[\d\/-]*/gi, '').replace(/\s{2,}/g, ' ').replace(/^[\s,:-]+|[\s,:-]+$/g, '');
    const addr = flat.match(/Address\s*[:\-]?\s*([\s\S]+?)(?=\n\s*\n|\bVID\b|\bAadhaar\b|\bDOB\b|\bDate of\b|$)/i);
    if (addr && clean(addr[1]).length > 8) data.address = clean(addr[1]).replace(/\n/g, ', ');
    else if (type === 'aadhaar' && pin) {
      const around = flat.slice(Math.max(0, flat.indexOf(pin[1]) - 160), flat.indexOf(pin[1]) + 6);
      const start = around.search(/\b(?:S\/O|D\/O|W\/O|C\/O|House|Flat|Plot|H\.?No)\b/i);
      if (start !== -1 && clean(around.slice(start)).length > 8) data.address = clean(around.slice(start)).replace(/\n/g, ', ');
    }
    if (pin && data.address && data.address.includes(pin[1])) data.pincode = pin[1];

    return data;
  }

  // Reads the OCR text with the AI to fill what the patterns could not find and to fix OCR slips.
  // Numbers that passed their own format check are never replaced by the AI's guess.
  async extractWithAI(text, patternData, aiService, user) {
    if (!aiService?.isConfigured?.() || !text || text.length < 20) return patternData;
    const FIELDS = ['documentType', 'fullName', 'fatherName', 'dateOfBirth', 'gender', 'aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber', 'address', 'pincode', 'state', 'phone', 'email'];
    const system = `You read OCR text from an Indian identity or personal document and return the fields printed on it.
Rules: copy only what is in the text. Never guess or invent. Use "" for anything not present. Fix obvious OCR slips (0/O, 1/I) only when the document's own format makes the fix certain.
documentType is one of: aadhaar, pan, passport, license, voter, marksheet, degree, bank_statement, other.
dateOfBirth as DD/MM/YYYY. Names in Title Case. Aadhaar as 12 digits, PAN as 10 characters.
Output ONLY one raw JSON object with exactly these keys: ${FIELDS.join(', ')}.`;
    try {
      const reply = await aiService.chat(system, `OCR TEXT:\n${text.slice(0, 6000)}\n\nJSON:`, {
        user: { ...(user?.toObject ? user.toObject() : user || {}), securityVersion: 1 },
        operation: aiService.AI_OPERATION.CLASSIFICATION,
      });
      const start = reply.indexOf('{');
      const end = reply.lastIndexOf('}');
      if (start === -1 || end <= start) return patternData;
      const ai = JSON.parse(reply.slice(start, end + 1));

      const merged = { ...patternData };
      for (const key of FIELDS) {
        let value = typeof ai[key] === 'string' ? ai[key].trim() : '';
        if (!value) continue;
        if (key === 'aadhaarNumber') { value = value.replace(/\s/g, ''); if (!this.isValidAadhaar(value) || merged[key]) continue; }
        else if (key === 'panNumber') { value = value.toUpperCase(); if (!/^[A-Z]{5}\d{4}[A-Z]$/.test(value) || merged[key]) continue; }
        else if (key === 'dateOfBirth') { value = this.normalizeDate(value); if (!value || merged[key]) continue; }
        else if (key === 'pincode') { if (!/^[1-9]\d{5}$/.test(value)) continue; }
        else if (key === 'phone') { value = value.replace(/\D/g, '').slice(-10); if (!/^[6-9]\d{9}$/.test(value)) continue; }
        else if (key === 'documentType') { value = value.toLowerCase(); }
        else if (merged[key] && merged[key].length >= value.length) continue; // keep the longer, already-read value
        merged[key] = value;
      }
      return merged;
    } catch (error) {
      console.warn('AI field extraction skipped:', error.message);
      return patternData;
    }
  }
}

module.exports = new OCRService();
