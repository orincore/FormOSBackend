const Tesseract = require('tesseract.js');
const path = require('path');
const fs = require('fs').promises;
const pdfParse = require('pdf-parse');
const { fromPath } = require('pdf2pic');
const sharp = require('sharp');

// Text is read on this server only (nothing is sent to a cloud OCR service), so documents that must stay private
// can use it too. The main reader is PaddleOCR (PP-OCR models on ONNX), far more accurate than Tesseract on phone
// photos, skewed or low-contrast cards. Tesseract on a cleaned-up copy is the backup and a second opinion.
const MIN_PADDLE_CONFIDENCE = 0.75;
let paddlePromise = null;
let paddleQueue = Promise.resolve(); // one image at a time: the engine instance is not safe for parallel use

const loadPaddle = () => {
  if (!paddlePromise) {
    paddlePromise = import('@gutenye/ocr-node')
      .then((mod) => (mod.default || mod).create())
      .catch((error) => { paddlePromise = null; console.error('PaddleOCR could not start, using Tesseract only:', error.message); return null; });
  }
  return paddlePromise;
};

class OCRService {
  // Straightens (EXIF), enlarges small photos, stretches contrast. Returns RGBA pixels for PaddleOCR and a
  // sharpened greyscale PNG for Tesseract.
  async prepareImage(buffer, angle = 0) {
    let base = sharp(buffer, { failOn: 'none' }).rotate();
    if (angle) base = sharp(await base.png().toBuffer()).rotate(angle);
    const { width = 0 } = await base.clone().metadata();
    const target = width < 1600 ? 1800 : Math.min(width, 3200);
    const sized = base.resize({ width: target, withoutEnlargement: false }).normalize();
    const raw = await sized.clone().ensureAlpha(1).raw().toBuffer({ resolveWithObject: true });
    const grey = await sized.clone().grayscale().sharpen().png().toBuffer();
    return { pixels: { data: raw.data, width: raw.info.width, height: raw.info.height }, grey };
  }

  // Joins the detected pieces into lines, top to bottom and left to right, the way the card reads.
  linesFromPaddle(texts) {
    const items = texts
      .filter((t) => t.text && t.text.trim())
      .map((t) => {
        const ys = t.box.map((p) => p[1]); const xs = t.box.map((p) => p[0]);
        return { text: t.text.trim(), top: Math.min(...ys), bottom: Math.max(...ys), left: Math.min(...xs), right: Math.max(...xs), mean: t.mean || 0 };
      })
      .sort((a, b) => a.top - b.top);
    const rows = [];
    for (const item of items) {
      const row = rows.find((r) => Math.abs((r.top + r.bottom) / 2 - (item.top + item.bottom) / 2) < (item.bottom - item.top) * 0.5);
      if (row) { row.items.push(item); row.top = Math.min(row.top, item.top); row.bottom = Math.max(row.bottom, item.bottom); } else rows.push({ top: item.top, bottom: item.bottom, items: [item] });
    }
    const confidence = items.length ? items.reduce((sum, i) => sum + i.mean, 0) / items.length : 0;
    // How much confidently-read text there is: used to pick the right orientation of a sideways photo.
    const score = items.reduce((sum, i) => sum + (i.mean >= 0.8 ? i.text.replace(/[^A-Za-z0-9]/g, '').length * i.mean : 0), 0);
    rows.forEach((r) => r.items.sort((a, b) => a.left - b.left));
    return { score, text: rows.map((r) => r.items.map((i) => i.text).join(' ')).join('\n'), confidence, items: rows.flatMap((r) => r.items), rows: rows.map((r) => r.items) };
  }

  async paddleRead(pixels) {
    const run = async () => {
      const engine = await loadPaddle();
      if (!engine) return { text: '', confidence: 0, score: 0 };
      const result = await engine.detect(pixels);
      return this.linesFromPaddle(result.texts || []);
    };
    const job = paddleQueue.then(run, run);
    paddleQueue = job.catch(() => {});
    return job;
  }

  // Reads one image from memory and keeps where each piece of text sits on the page (the layout tells a label from its
  // value: the value is right of it or under it). Never throws. Returns { text, items } with items = [] when unavailable.
  async readImage(buffer) {
    let prepared;
    try { prepared = await this.prepareImage(buffer); } catch (error) { console.error('Image preparation failed, reading it as is:', error.message); }

    let paddle = { text: '', confidence: 0, score: 0 };
    if (prepared) {
      try { paddle = await this.paddleRead(prepared.pixels); } catch (error) { console.error('PaddleOCR error:', error.message); }
      // A photo taken sideways reads as garbage with low confidence: try the other turns. PaddleOCR reads upside-down
      // text almost as well as upright, so orientations that score about the same are told apart by Tesseract,
      // which only reads upright text.
      if (paddle.confidence < 0.85) {
        const options = [{ paddle, prepared }];
        for (const angle of [90, 180, 270]) {
          try {
            const turned = await this.prepareImage(buffer, angle);
            options.push({ paddle: await this.paddleRead(turned.pixels), prepared: turned });
          } catch (error) { console.error(`PaddleOCR turn ${angle} failed:`, error.message); }
        }
        const top = Math.max(...options.map((o) => o.paddle.score));
        const close = options.filter((o) => o.paddle.score >= top * 0.8 && o.paddle.score > 0);
        if (close.length > 1) {
          for (const option of close) {
            try { option.upright = (await Tesseract.recognize(option.prepared.grey, 'eng')).data.confidence || 0; } catch { option.upright = 0; }
          }
          close.sort((x, y) => y.upright - x.upright);
        } else close.sort((x, y) => y.paddle.score - x.paddle.score);
        if (close.length && close[0].paddle.score > paddle.score * 1.3) ({ paddle, prepared } = close[0]);
      }
    }

    let tess = '';
    try { tess = (await Tesseract.recognize(prepared ? prepared.grey : buffer, 'eng')).data.text || ''; } catch (error) { console.error('Tesseract error:', error.message); }
    if (!paddle.text) return { text: tess, items: [] };

    // PaddleOCR often drops the space between words ("CHAWLATARUNPRAKASH"). Tesseract keeps them, so wherever it read
    // the same letters, its spacing is used.
    const alnum = (v) => v.toLowerCase().replace(/[^a-z0-9]/g, '');
    const tessLines = tess.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => ({ line, flat: alnum(line) }));
    const respace = (fragment) => {
      const flat = alnum(fragment);
      if (flat.length < 6) return fragment;
      const spacesIn = (fragment.match(/\s/g) || []).length;
      for (const { line, flat: lineFlat } of tessLines) {
        const at = lineFlat.indexOf(flat);
        if (at === -1) continue;
        // walk the Tesseract line, keeping its spaces, over exactly the characters of this fragment
        let seen = 0; let out = ''; let started = false;
        for (const ch of line) {
          const isAlnum = /[A-Za-z0-9]/.test(ch);
          if (isAlnum) { if (seen === at) started = true; if (started && seen < at + flat.length) out += ch; seen += isAlnum ? 1 : 0; }
          else if (started && seen < at + flat.length) out += ch;
          if (started && seen >= at + flat.length) break;
        }
        out = out.trim().replace(/\s+/g, ' ');
        if ((out.match(/\s/g) || []).length > spacesIn) return out;
        break;
      }
      return fragment.replace(/([a-z])([A-Z])/g, '$1 $2');
    };
    (paddle.items || []).forEach((item) => { item.text = respace(item.text); });
    if (paddle.rows) paddle.text = paddle.rows.map((row) => row.map((i) => i.text).join(' ')).join('\n');
    else paddle.text = paddle.text.replace(/([a-z])([A-Z])/g, '$1 $2');
    const items = paddle.items || [];

    // The two readers slip on different characters, so lines only Tesseract found are added after PaddleOCR's.
    // A confident PaddleOCR read keeps its own lines first, which is where the field patterns look first.
    const norm = (v) => v.toLowerCase().replace(/[^a-z0-9+]/g, ''); // a blood group's + sign must count
    const have = norm(paddle.text);
    const extra = tess.split('\n').map((l) => l.trim()).filter((l) => norm(l).length >= 4 && !have.includes(norm(l)));
    return { text: paddle.confidence >= MIN_PADDLE_CONFIDENCE && !extra.length ? paddle.text : [paddle.text, ...extra].join('\n'), items };
  }

  async recognizeImage(buffer) {
    return (await this.readImage(buffer)).text;
  }

  // Text plus layout for a file on disk (images keep their layout; a PDF has text only).
  async extractTextAndItems(filePath) {
    if (path.extname(filePath).toLowerCase() === '.pdf') return { text: await this.extractText(filePath), items: [] };
    try { return await this.readImage(await fs.readFile(filePath)); } catch (error) {
      console.error('OCR extraction error:', error);
      throw new Error('Failed to extract text from document');
    }
  }

  // The same for an image held in memory (encrypted accounts: nothing is written to disk).
  async readBuffer(buffer, mimeType) {
    if (mimeType === 'application/pdf') return { text: await this.extractTextFromBuffer(buffer, mimeType), items: [] };
    try { return await this.readImage(buffer); } catch (error) { console.error('In-memory OCR error:', error.message); return { text: '', items: [] }; }
  }

  async extractText(filePath) {
    try {
      const ext = path.extname(filePath).toLowerCase();
      
      if (ext === '.pdf') {
        return await this.extractTextFromPDF(filePath);
      } else {
        return await this.recognizeImage(await fs.readFile(filePath));
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
      return await this.recognizeImage(buffer);
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
            allText += (await this.recognizeImage(await fs.readFile(pageImage.path))) + '\n\n';
            
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
    // Reports and statements quote a PAN and other ID numbers, but they are not the ID itself.
    if (/CREDIT\s+(?:REPORT|INFORMATION\s+REPORT|SCORE)|\bCIBIL\b|TRANSUNION|\bEXPERIAN\b|\bEQUIFAX\b|BANK\s+STATEMENT|ACCOUNT\s+STATEMENT|\bINVOICE\b|PAY\s*SLIP|SALARY\s+SLIP|FORM[\s-]*16\b/.test(t) && !/AADHAAR|UIDAI/.test(t)) return 'other';
    if (/INCOME TAX DEPARTMENT|PERMANENT ACCOUNT NUMBER/.test(t) || /\b[A-Z]{5}\d{4}[A-Z]\b/.test(t) && !/AADHAAR|UIDAI/.test(t)) return 'pan';
    if (/AADHAAR|UIDAI|UNIQUE IDENTIFICATION|आधार/.test(t)) return 'aadhaar';
    for (const m of t.matchAll(/\b([2-9]\d{3})\s?(\d{4})\s?(\d{4})\b/g)) if (this.isValidAadhaar(m[1] + m[2] + m[3])) return 'aadhaar';
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

  // OCR confuses look-alike characters (O/0, I/1, S/5, B/8). A token is only rewritten when the fixed version
  // fits the ID's own format, and for Aadhaar when it also passes the check digit, so real numbers are never altered.
  repairIdNumbers(text) {
    const toDigits = (v) => v.replace(/[Oo]/g, '0').replace(/[Il|]/g, '1').replace(/S/g, '5').replace(/B/g, '8');
    const toLetters = (v) => v.replace(/0/g, 'O').replace(/1/g, 'I').replace(/5/g, 'S').replace(/8/g, 'B');
    let out = text.replace(/\b([0-9OoIl|SB]{4})\s?([0-9OoIl|SB]{4})\s?([0-9OoIl|SB]{4})\b/g, (whole, a, b, c) => {
      if (/^\d{4}$/.test(a) && /^\d{4}$/.test(b) && /^\d{4}$/.test(c)) return whole;
      const fixed = toDigits(a + b + c);
      return this.isValidAadhaar(fixed) ? `${fixed.slice(0, 4)} ${fixed.slice(4, 8)} ${fixed.slice(8)}` : whole;
    });
    out = out.replace(/\b([A-Z0158]{5})([0-9OIlSB]{4})([A-Z01580])\b/g, (whole, a, b, c) => {
      const fixed = `${toLetters(a)}${toDigits(b)}${toLetters(c)}`;
      return /^[A-Z]{5}\d{4}[A-Z]$/.test(fixed) && /^[A-Z]{3}[ABCFGHLJPT]/.test(fixed) ? fixed : whole;
    });
    return out;
  }

  parseStructuredData(text) {
    const data = {};
    if (!text || text.length < 10 || /processing failed|Failed to extract|No text could be extracted/i.test(text)) {
      return data;
    }
    const flat = this.repairIdNumbers(text.replace(/[ \t]+/g, ' '));

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
    if (!data.fullName) {
      // Reports and statements print "CONSUMER NAME ADARSH SURADKAR DOB GENDER ..." with the next label straight after the
      // name: the name is the few words between the label and that next label.
      const inline = flat.match(/(?:^|\n)\s*(?:CONSUMER\s+|CUSTOMER\s+|APPLICANT\s+|HOLDER\s+)?NAME\s*[:\-]?\s+([A-Za-z][A-Za-z .']*?)(?=\s+(?:DOB|D\.O\.B|DATE\s+OF\s+BIRTH|GENDER|SEX|FATHER|MOTHER|SPOUSE|PAN|ADDRESS|MOBILE|PHONE|EMAIL|CREDIT|ACCOUNT)\b|\s*\n|$)/i);
      const words = inline ? inline[1].trim().split(/\s+/) : [];
      if (words.length >= 2 && words.length <= 5 && require('./documentFields').valueFitsKey('fullName', words.join(' '))) data.fullName = this.toTitleCase(words.join(' '));
    }
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

    // The first email that is the holder's: the helpdesk address printed on a card (help@uidai.gov.in) is not.
    const email = (flat.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []).find((e) => !/@(?:[\w-]+\.)*(?:gov|nic)\.in$|uidai|incometax|passportindia|parivahan/i.test(e));
    if (email) data.email = email;

    const pin = flat.match(/\b([1-9]\d{5})\b(?!\d)/);
    const clean = (a) => a.replace(/\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/g, '').replace(/VID\s*:?\s*\d[\d\s]*/gi, '')
      .replace(/Details\s+as\s+on:?\s*[\d\/-]*/gi, '').replace(/\s{2,}/g, ' ').replace(/^[\s,:-]+|[\s,:-]+$/g, '');
    const addr = flat.match(/Address\s*[:\-]?\s*([\s\S]+?)(?=\n\s*\n|\bVID\b|\bAadhaar\b|\bDOB\b|\bDate of\b|$)/i);
    // At most three lines, stopping at the next label ("Sex: Male", "Father's Name") or a heading, so a blank or
    // crowded form does not turn the whole page into an address.
    const addrLines = addr ? addr[1].split('\n').map((l) => l.trim()).filter(Boolean) : [];
    const stop = addrLines.findIndex((l, i) => i > 0 && (/[:：]/.test(l) || /\b(sex|gender|father|mother|signature|officer|date|dob|card|elector|identity|commission|government)\b/i.test(l)));
    const addrText = (stop === -1 ? addrLines : addrLines.slice(0, stop)).slice(0, 3).join('\n');
    if (addrText && clean(addrText).length > 8 && clean(addrText).length <= 250) data.address = clean(addrText).replace(/\n/g, ', ');
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
        else if (['passportNumber', 'drivingLicenseNumber'].includes(key)) { value = value.toUpperCase(); if (merged[key] || !require('./documentFields').valueFitsKey(key, value)) continue; }
        else if (key === 'panNumber') { value = value.toUpperCase(); if (!/^[A-Z]{5}\d{4}[A-Z]$/.test(value) || merged[key]) continue; }
        else if (key === 'dateOfBirth') { value = this.normalizeDate(value); if (!value || merged[key]) continue; }
        else if (key === 'pincode') { if (!/^[1-9]\d{5}$/.test(value)) continue; }
        else if (key === 'phone') { value = value.replace(/\D/g, '').slice(-10); if (!/^[6-9]\d{9}$/.test(value)) continue; }
        else if (key === 'documentType') { value = value.toLowerCase(); }
        else if (!require('./documentFields').valueFitsKey(key, value)) continue; // a paragraph is not a name, a heading is not a state
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
