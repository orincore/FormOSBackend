// Reads a document with an AI model that can see it.
//
// OCR alone is not enough for photos and busy documents (marksheets, credit reports, statements): it garbles characters
// and loses the layout. Here the model is given the picture itself (or the text layer of a PDF) and returns what kind of
// document it is, the holder's details, and EVERY labelled item on it, tables included. Nothing it says is trusted blindly:
// identity numbers must pass their own check (Aadhaar check digit, PAN format ...) and every field goes through the same
// cleaning as before.
//
// Standard accounts only. Security V2 documents are encrypted and never leave the server for a cloud model.

const sharp = require('sharp');
const aiService = require('./aiService');
const docFields = require('./documentFields');
const { maskSensitiveText } = require('./securityService');

const MAX_FIELDS = 200;
const visionModel = () => process.env.AI_VISION_MODEL || 'openai/gpt-4o';

// What the model may call a document, and what that is in FormOS terms.
const TYPE_MAP = {
  aadhaar: 'aadhaar', pan: 'pan', passport: 'passport', license: 'license', driving_license: 'license', voter: 'voter', voter_id: 'voter',
  marksheet: 'marksheet', certificate: 'certificate', degree: 'certificate',
  credit_report: 'other', bank_statement: 'bank', bank: 'bank', payslip: 'other', insurance: 'insurance', vehicle_rc: 'vehicle', vehicle: 'vehicle',
  invoice: 'other', other: 'other',
};

const SYSTEM = `You are an expert at reading Indian identity, education, financial and other personal documents from a photo, scan or text, and turning them into complete, accurate structured data.
Reply with ONLY one raw JSON object:
{
 "documentType": one of aadhaar, pan, passport, driving_license, voter_id, marksheet, certificate, credit_report, bank_statement, payslip, insurance, vehicle_rc, invoice, other,
 "documentTitle": "<short natural title, e.g. PAN Card, CBSE Class 12 Marksheet, CIBIL Credit Report, Electricity Bill>",
 "summary": "<one plain sentence saying what this document is and its most important facts, e.g. 'CIBIL credit report dated 18/10/2026 with a score of 742'>",
 "holder": { "fullName": "", "fatherName": "", "dateOfBirth": "DD/MM/YYYY", "gender": "Male|Female|Transgender", "address": "", "pincode": "", "state": "", "phone": "", "email": "" },
 "numbers": { "aadhaarNumber": "", "panNumber": "", "passportNumber": "", "drivingLicenseNumber": "" },
 "fields": [ { "label": "<label as printed, in English>", "value": "<value exactly as printed>" } ],
 "tables": [ { "name": "<what the table lists, e.g. Subjects, Accounts, Enquiries, Transactions>", "columns": ["<column heading>", "..."], "labelColumn": <0-based index of the column that names each row>, "rows": [ ["<cell>", "..."] ] } ]
}
Rules:
- Copy values exactly as printed. Never guess, never invent, never calculate. Use "" for anything that is not on the document.
- "holder" and "numbers" are about the person the document is for, and only the numbers that this document really is or prints for them. A credit report quotes a PAN as one of the person's IDs; it does not make the report a PAN card, and a number such as a control number or account number is never an Aadhaar number.
- "fields" must hold every single labelled item that is NOT part of a table: seat or roll number, exam, board, year, total, percentage, result, grade; scores, report numbers, dates, limits, totals and summary counts; issue and expiry dates; issuing authority; and so on. Do not summarise away details. Do not repeat what is already in "holder" or "numbers", and do not repeat table rows here.
- "tables" must hold every table on the document, with ALL its rows and EVERY cell copied exactly, digit for digit (a subject-wise marks table, a list of accounts or loans, enquiries, transactions). "columns" are the headings as printed. "labelColumn" is the column that names the row (the subject, the lender, the date). Each row has one cell per column; use "" for an empty cell. Never skip rows, never reorder digits.
- One row per THING, never one row per printed line. When a subject or course is printed on several lines (for example separate lines for its theory, practical, exam and internal marks) merge them into ONE row and add columns for each part, such as ["Course","Theory max","Theory obtained","Practical max","Practical obtained","Internal max","Internal obtained","Total","Credits"], or "ESE max/obtained" and "PA max/obtained". The first column is always the name of the thing (the course, the lender, the date), repeated for every line it covers, so the labelColumn is 0 and each name appears only once.
- For a credit report always give fields for: the score (for example label "CIBIL Score"), score date, control or report number, report date, number of accounts, active and closed accounts, overdue amount, total outstanding, and enquiry counts, when they are printed.
- Always capture, as fields, who issued or produced the document (the board, university, bank, company or authority, with its full name), the document, reference or certificate number, and every date printed on it.
- Never write an ID, account, card or phone number in documentTitle or summary (say "with an Aadhaar number", not the number): they are shown in lists.
- Dates as DD/MM/YYYY. People's names in Title Case. Aadhaar as 12 digits, PAN as 10 characters.
- documentType "other" is for anything that is none of the listed kinds (a bill, a certificate of any kind, a letter, a form, a receipt ...): then say exactly what it is in documentTitle and describe it in summary. Any kind of document is welcome; your job is to work out what it is and capture all of its information.`;

const cleanText = (v) => String(v ?? '').replace(/\s+/g, ' ').trim();

function parseJson(reply) {
  const text = String(reply || '');
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try { return JSON.parse(text.slice(start, end + 1)); } catch { return null; }
}

// A photo is shrunk to a size a model reads well and that does not cost a fortune.
async function imageDataUrl(buffer) {
  const jpeg = await sharp(buffer, { failOn: 'none' }).rotate().resize({ width: 2200, height: 2200, fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 88 }).toBuffer();
  return `data:image/jpeg;base64,${jpeg.toString('base64')}`;
}

// What the model is shown for this file: the picture, or the PDF itself. No OCR and no extracted text are involved; the model
// reads the pages directly, which is what keeps digits, table columns and small print right.
async function buildMessages({ buffer, mimeType, fileName }) {
  if (mimeType === 'application/pdf') {
    return {
      messages: [
        { role: 'system', content: SYSTEM },
        { role: 'user', content: [
          { type: 'text', text: `File name: ${fileName || 'document.pdf'}. Read every page of this PDF.\n\nJSON:` },
          { type: 'file', file: { filename: fileName || 'document.pdf', file_data: `data:application/pdf;base64,${buffer.toString('base64')}` } },
        ] },
      ],
      // The model takes the PDF natively (pages as images plus its own text). Only if that is refused is the provider's
      // document reader used instead.
      plugins: [{ id: 'file-parser', pdf: { engine: 'native' } }],
      fallbackPlugins: [{ id: 'file-parser', pdf: { engine: 'mistral-ocr' } }],
    };
  }
  return {
    messages: [
      { role: 'system', content: SYSTEM },
      { role: 'user', content: [
        { type: 'text', text: `File name: ${fileName || 'document'}. Read this document.\n\nJSON:` },
        { type: 'image_url', image_url: { url: await imageDataUrl(buffer), detail: 'high' } },
      ] },
    ],
    plugins: undefined,
  };
}

// The model's answer, turned into FormOS's record shape and checked field by field.
function normalize(parsed) {
  const typeKey = String(parsed.documentType || '').toLowerCase().replace(/[^a-z_]/g, '');
  const documentType = TYPE_MAP[typeKey] || 'other';
  // The title and the summary are shown in lists, so ID numbers are masked in them as they are saved (the numbers themselves are
  // kept in their own fields).
  const title = maskSensitiveText(cleanText(parsed.documentTitle)).slice(0, 80);
  const ocr = require('./ocrService');
  const known = {};
  const holder = parsed.holder && typeof parsed.holder === 'object' ? parsed.holder : {};
  const numbers = parsed.numbers && typeof parsed.numbers === 'object' ? parsed.numbers : {};

  const put = (key, raw) => {
    let value = cleanText(raw);
    if (!value) return;
    if (key === 'dateOfBirth') value = ocr.normalizeDate(value) || '';
    else if (key === 'aadhaarNumber') value = value.replace(/\D/g, '');
    else if (key === 'panNumber' || key === 'passportNumber') value = value.replace(/\s/g, '').toUpperCase();
    else if (key === 'phone') value = value.replace(/\D/g, '').replace(/^(91|0)(?=\d{10}$)/, '');
    else if (key === 'pincode') { const m = value.match(/\b[1-9]\d{5}\b/); value = m ? m[0] : ''; }
    else if (key === 'email') value = value.toLowerCase();
    else if (key === 'gender') { const m = value.match(/\b(male|female|transgender)\b/i); value = m ? m[1][0].toUpperCase() + m[1].slice(1).toLowerCase() : ''; }
    else if (key === 'fullName' || key === 'fatherName') value = value.toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
    if (value && docFields.valueFitsKey(key, value)) known[key] = value;
  };
  for (const key of ['fullName', 'fatherName', 'dateOfBirth', 'gender', 'address', 'pincode', 'state', 'phone', 'email']) put(key, holder[key]);
  for (const key of ['aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber']) put(key, numbers[key]);
  // An identity number only belongs to a document that really is that ID, or one that prints it for the holder: a PAN on a
  // credit report is fine, but an Aadhaar number on a marksheet would be a misread.
  if (known.aadhaarNumber && !['aadhaar', 'other', 'bank', 'certificate'].includes(documentType)) delete known.aadhaarNumber;

  const fields = {};
  const addField = (labelText, valueText) => {
    const label = docFields.normalizeLabel(cleanText(labelText).slice(0, 80));
    const value = cleanText(valueText).slice(0, 500);
    if (!label || !value) return;
    const key = docFields.labelToKey(label);
    if (!key) return;
    if (docFields.KNOWN_KEYS.includes(key)) { if (!known[key]) put(key, value); return; }
    if (!fields[key]) fields[key] = value;
  };
  // Each table row becomes one field: the row's name, and its other cells with their column headings. Done here, in code,
  // so no row can be lost or merged by the model.
  for (const t of (Array.isArray(parsed.tables) ? parsed.tables : []).slice(0, 8)) {
    const columns = (Array.isArray(t?.columns) ? t.columns : []).map((c) => cleanText(c));
    const at = Number.isInteger(t?.labelColumn) && t.labelColumn >= 0 && t.labelColumn < columns.length ? t.labelColumn : 0;
    const rows = (Array.isArray(t?.rows) ? t.rows : []).slice(0, 120).filter(Array.isArray).map((row) => row.map((c) => cleanText(c)));
    // A column of repeated or empty-sounding entries ("Not disclosed", "Credit card" ten times) does not name a row: those rows
    // are numbered by the table's name instead, and the column stays in the value.
    const names = rows.map((r) => r[at]).filter(Boolean);
    const generic = /^(not disclosed|n\/?a|na|-+|nil|none|yes|no)$/i;
    const meaningful = names.length > 0 && !names.some((n) => generic.test(n));
    const distinct = (list) => new Set(list.map((x) => x.toLowerCase())).size;
    // A name that repeats (a course listed once for its exam and once for its internal marks) is told apart by the other
    // columns, added one at a time until every row is different: "Management (TH ESE)", "Management (PA)".
    const tell = [];
    if (meaningful && distinct(names) < names.length) {
      const keyOf = (r) => [r[at], ...tell.map((i) => r[i] || '')].join('|');
      for (let i = 0; i < columns.length && distinct(rows.map(keyOf)) < rows.length; i++) {
        if (i === at) continue;
        const before = distinct(rows.map(keyOf));
        tell.push(i);
        if (distinct(rows.map(keyOf)) <= before) tell.pop();
      }
    }
    const nameable = meaningful && (distinct(names) >= names.length * 0.8 || (tell.length > 0 && distinct(rows.map((r) => [r[at], ...tell.map((i) => r[i] || '')].join('|'))) === rows.length));
    const tableName = cleanText(t?.name).slice(0, 40) || 'Row';
    const used = new Set();
    rows.forEach((cells, index) => {
      const extra = tell.map((i) => cells[i]).filter(Boolean).join(' ');
      let label = nameable ? (extra ? `${cells[at]} ${extra}` : cells[at]) : `${tableName} ${index + 1}`;
      if (!label) return;
      const base = label; let n = 2;
      while (used.has(label.toLowerCase())) label = `${base} ${n++}`;
      used.add(label.toLowerCase());
      const value = cells.map((c, i) => ((nameable && (i === at || tell.includes(i))) || !c ? '' : `${columns[i] ? columns[i] + ': ' : ''}${c}`)).filter(Boolean).join('; ');
      addField(label, value || 'Listed');
    });
  }
  for (const f of (Array.isArray(parsed.fields) ? parsed.fields : []).slice(0, MAX_FIELDS)) {
    addField(f?.label, f?.value);
  }
  const summary = maskSensitiveText(cleanText(parsed.summary)).slice(0, 240);
  return { documentType, documentTitle: title, documentSummary: summary, known, fields: docFields.cleanFields(fields) };
}

/**
 * @returns {Promise<null | { documentType, documentTitle, known, fields }>} null when the AI could not read it (the caller keeps its own reading)
 */
async function read({ buffer, mimeType, fileName, user }) {
  try {
    if (!buffer || !buffer.length || user?.securityVersion === 2) return null;
    if (!aiService.openrouter) return null;
    if (!['application/pdf', 'image/jpeg', 'image/png', 'image/webp'].includes(mimeType)) return null;
    const { messages, plugins, fallbackPlugins } = await buildMessages({ buffer, mimeType, fileName });
    const options = { user: { securityVersion: 1, _id: user?._id }, operation: aiService.AI_OPERATION.CLASSIFICATION, model: visionModel() };
    let reply;
    try {
      reply = await aiService.chatVision(messages, { ...options, plugins });
    } catch (error) {
      if (!fallbackPlugins) throw error;
      console.warn('[documentReader] native PDF reading refused, using the provider reader:', error.message);
      reply = await aiService.chatVision(messages, { ...options, plugins: fallbackPlugins });
    }
    const parsed = parseJson(reply);
    if (!parsed) return null;
    const out = normalize(parsed);
    // Nothing usable came back: let the caller's own reading stand.
    if (!Object.keys(out.known).length && !Object.keys(out.fields).length && out.documentType === 'other' && !out.documentTitle) return null;
    return out;
  } catch (error) {
    console.warn('[documentReader] AI reading skipped:', error.message);
    return null;
  }
}

module.exports = { read, normalize, TYPE_MAP, SYSTEM };
