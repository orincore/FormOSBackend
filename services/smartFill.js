// Smart form fill for the browser extension.
//
// The page's fields are matched to what the member has on file by the AI, but the AI only PLANS. It is shown the
// labels of the facts the member has (never their values) and the labels of the form's fields, and answers with
// "field X is fact Y". This code checks every answer and puts in the real values, so the model can never invent a
// value, and no personal detail leaves the server for it. Same rule as the WhatsApp assistant.

const aiService = require('./aiService');

const MAX_FIELDS = 80;
const MAX_OPTIONS = 14;
const BATCH = 10;

// The usual details, named the way the extension names them. `locked` ones need the sensitive-access step-up.
const STANDARD = [
  ['title', 'Title (Mr or Ms)'], ['fullName', 'Full name'], ['firstName', 'First name'], ['middleName', 'Middle name'], ['middleInitial', 'Middle initial (one letter)'], ['lastName', 'Last name (surname)'],
  ['fatherName', "Father's name"], ['email', 'Email address'], ['phone', 'Mobile number'], ['alternatePhone', 'Alternate mobile number'],
  ['dateOfBirth', 'Date of birth'], ['dobDay', 'Day of birth'], ['dobMonth', 'Month of birth'], ['dobYear', 'Year of birth'],
  ['age', 'Age in years'], ['gender', 'Gender'], ['nationality', 'Nationality'],
  ['address', 'Full address'], ['addressLine1', 'Address line 1 (house, street)'], ['addressLine2', 'Address line 2 (area, landmark)'],
  ['city', 'City or town'], ['district', 'District'], ['state', 'State'], ['zipCode', 'PIN code'], ['country', 'Country'],
  ['aadhaar', 'Aadhaar number'], ['pan', 'PAN number'], ['voterId', 'Voter ID number'], ['passportNumber', 'Passport number'],
  ['drivingLicence', 'Driving licence number'],
];
const LOCKED_WITHOUT_STEP_UP = new Set(['email', 'phone', 'alternatePhone', 'dateOfBirth', 'dobDay', 'dobMonth', 'dobYear', 'age', 'aadhaar', 'pan']);

const clean = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();

function parseDob(text) {
  const m = clean(text).match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/);
  if (!m) return null;
  const d = Number(m[1]); const mo = Number(m[2]); const y = Number(m[3]);
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  return { d, mo, y };
}

function ageFrom(dob, now = new Date()) {
  if (!dob) return null;
  let age = now.getFullYear() - dob.y;
  if (now.getMonth() + 1 < dob.mo || (now.getMonth() + 1 === dob.mo && now.getDate() < dob.d)) age--;
  return age >= 0 && age < 120 ? age : null;
}

// What the member has: key, label and value for each fact. `values` stays on the server until the plan is checked.
function buildFacts({ data, fields, includeSensitive, isSensitive }) {
  const facts = new Map();
  const dob = parseDob(data.dateOfBirth);
  const derived = { ...data };
  if (dob) {
    derived.dobDay = String(dob.d); derived.dobMonth = String(dob.mo); derived.dobYear = String(dob.y);
    const age = ageFrom(dob);
    if (age !== null) derived.age = String(age);
  }
  // Derived from details the member has: the title from their gender, the middle initial from their middle name.
  const gender = clean(derived.gender).toLowerCase();
  if (/^m/.test(gender)) derived.title = 'Mr'; else if (/^f/.test(gender)) derived.title = 'Ms';
  if (clean(derived.middleName)) derived.middleInitial = clean(derived.middleName)[0].toUpperCase();
  for (const [key, label] of STANDARD) {
    const value = clean(derived[key]);
    if (!value) continue;
    // A locked fact is still named, so a form field for it is reported as "needs sensitive access" and not silently
    // skipped, but its value stays on the server until the member has re-authenticated.
    const locked = !includeSensitive && LOCKED_WITHOUT_STEP_UP.has(key);
    facts.set(key, { key, label, value: locked ? '' : value, locked });
  }
  // Everything else the member's documents say (roll number, seat number, class of vehicle ...).
  for (const f of fields || []) {
    if (!f?.key || facts.has(f.key) || STANDARD.some(([k]) => k === f.key)) continue;
    const value = clean(f.value);
    if (!value || value.length > 300) continue;
    const locked = !includeSensitive && Boolean(isSensitive && isSensitive(f.key, f.label, value));
    facts.set(f.key, { key: f.key, label: clean(f.label) || f.key, value: locked ? '' : value, locked });
  }
  return facts;
}

// What the AI is told about one form field. Trimmed, and only what helps to tell what is being asked.
function cleanDescriptor(raw, index) {
  const id = clean(raw?.id).slice(0, 40);
  if (!id) return null;
  const label = clean(raw.label).slice(0, 120);
  const hints = (Array.isArray(raw.hints) ? raw.hints : []).map((h) => clean(h).slice(0, 80)).filter(Boolean).slice(0, 4);
  const options = (Array.isArray(raw.options) ? raw.options : []).map((o) => clean(o).slice(0, 40)).filter(Boolean);
  if (!label && !hints.length && !clean(raw.placeholder)) return null;
  return {
    id,
    label,
    hints,
    type: clean(raw.type).slice(0, 20),
    placeholder: clean(raw.placeholder).slice(0, 60),
    maxlength: Number(raw.maxlength) > 0 ? Number(raw.maxlength) : undefined,
    options: options.length ? options.slice(0, MAX_OPTIONS) : undefined,
    optionCount: options.length > MAX_OPTIONS ? options.length : undefined,
    index,
  };
}

const SYSTEM = `You match the fields of a web form to the facts a person has on file. You never see their actual details, only the names of the facts.
Reply with ONLY raw JSON: {"matches":[{"id":"<field id>","fact":"<fact key>"}]}.
Rules:
- Use only fact keys from FACTS. One fact per field.
- Be thorough: every field that asks for one of the FACTS must be matched. Leaving out a field that clearly asks for a fact is a mistake. Leave a field out only when no fact fits it, or when it is not about this person (see below).
- Match what the field ASKS FOR, using its label, hints, placeholder and choices. Prefer the most specific fact: first name or surname when only that part is asked, address line 1 for a street or house number, city for a town or city, the PIN code for "pin" or "zip", the day, month or year facts for separate date boxes, "Father/Husband name" is the father's name.
- A document number or detail in FACTS (roll number, percentage, class of vehicle ...) matches a field that asks for that same thing, even if the wording differs ("Marks obtained in %" is the percentage, "Candidate Roll No." is the roll number).
- A dropdown or a group of choices: pick the fact that answers the question (gender, state, nationality, country, month of birth ...).
- Leave out: search boxes, passwords, OTP or captcha, coupons, comments or messages, declarations and consent boxes, and details of other people (mother, spouse, nominee, referee, guardian) or of an organisation (employer, school, bank) unless a fact is for exactly that.
- A home, mobile or cell phone box is the mobile number. A work, office, fax, bank or customer-service number is not. A birth place is a town: it is never a date or an address. A title or salutation is the title fact, an initial is the initial fact.
- Never guess between two facts that mean different things. If a field is truly unclear, leave it out.`;

function parseReply(reply) {
  const start = String(reply || '').indexOf('{');
  const end = String(reply || '').lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try { return JSON.parse(reply.slice(start, end + 1)); } catch { return null; }
}

// Cheap sanity checks on the AI's choice, so an obvious mistake is dropped and the field is left for the member.
const STANDARD_KEYS = new Set(STANDARD.map(([k]) => k));
// Words that mean a field is about something other than the member's own details (a company, a card, a bank, a fax line ...).
const OTHER_THING = /\b(customer service|support|helpline|toll[- ]?free|fax|work|office|business|company|employer|bank|card|credit|debit|expir\w*|cvv|cvc|issuing|income|salary|web ?site|url|user ?id|password)\b/i;

function fits(desc, key) {
  const type = desc.type;
  const wording = [desc.label, ...(desc.hints || [])].join(' ').toLowerCase();
  const standard = STANDARD_KEYS.has(key);
  // An "alternate", "secondary" or "emergency" contact box is not the member's own number or email: the same value would be a wrong answer.
  if (['phone', 'email'].includes(key) && /\b(alternate|alternative|secondary|emergency|other|second|office|work|parent|guardian|relative|spouse|friend)\b/.test(wording)) return false;
  // A work, fax, bank or customer-service number, a card name, a company ... is not one of the member's own details.
  if (standard && OTHER_THING.test(wording)) return false;
  // A birth place is a town: never a date, an address or the town they live in.
  if (standard && /birth ?place|place of birth|town of birth|city of birth|born (?:in|at)/.test(wording)) return false;
  // A title or a salutation is Mr or Ms, and an initial is one letter: never a name.
  if (/\b(title|salutation|honorific|prefix)\b/.test(wording) && key !== 'title') return false;
  if (/\binitials?\b/.test(wording) && key !== 'middleInitial') return false;
  if (key === 'title' && !/\b(title|salutation|honorific|prefix|mr)\b/.test(wording)) return false;
  if (key === 'middleInitial' && !/\binitial/.test(wording)) return false;
  if (type === 'email' && key !== 'email') return false;
  if (type === 'tel' && !['phone', 'alternatePhone'].includes(key)) return false;
  if (type === 'date' && !['dateOfBirth'].includes(key) && !/date/i.test(key)) return false;
  if (key === 'zipCode' && desc.maxlength && desc.maxlength < 6) return false;
  if (['aadhaar', 'pan', 'voterId', 'passportNumber', 'drivingLicence'].includes(key) && desc.options) return false;
  return true;
}

/**
 * @returns {Promise<{ plan: Array<{id, key, label, value, locked}>, asked: number }>}
 */
async function planFill({ descriptors, data, fields, includeSensitive, isSensitive, user }) {
  const facts = buildFacts({ data: data || {}, fields, includeSensitive, isSensitive });
  const list = (Array.isArray(descriptors) ? descriptors : []).slice(0, MAX_FIELDS).map(cleanDescriptor).filter(Boolean);
  if (!list.length || !facts.size) return { plan: [], asked: list.length };

  const factLines = [...facts.values()].map((f) => `${f.key} | ${f.label}`).join('\n');
  const byId = new Map(list.map((d) => [d.id, d]));
  const line = (d) => JSON.stringify({ id: d.id, label: d.label, hints: d.hints.length ? d.hints : undefined, type: d.type || undefined, placeholder: d.placeholder || undefined, maxlength: d.maxlength, choices: d.options, choiceCount: d.optionCount });

  // Small batches, asked in parallel: one call with a whole page makes the model skip fields it should match.
  const ask = async (batch, recheck = false) => {
    // Matching a page's fields to the member's facts is judgement work: the stronger model does it (AI_FORM_MODEL to change it).
    const reply = await aiService.chatVision([
      { role: 'system', content: recheck ? `${SYSTEM}\nThese fields were not matched on a first pass. Look at each again and match every one that asks for any of the FACTS; leave out only the ones that truly ask for nothing in FACTS.` : SYSTEM },
      { role: 'user', content: `FACTS (key | meaning):\n${factLines}\n\nFORM FIELDS (one per line):\n${batch.map(line).join('\n')}\n\nJSON:` },
    ], {
      user: { securityVersion: 1, _id: user?._id },
      operation: aiService.AI_OPERATION.CLASSIFICATION,
      model: process.env.AI_FORM_MODEL || process.env.AI_ANSWER_MODEL || 'openai/gpt-4o',
      maxTokens: 1500,
      timeout: 45000,
    });
    const parsed = parseReply(reply);
    if (!parsed || !Array.isArray(parsed.matches)) throw Object.assign(new Error('The AI answer could not be read.'), { code: 'BAD_AI_ANSWER' });
    return parsed.matches;
  };
  const batches = [];
  for (let i = 0; i < list.length; i += BATCH) batches.push(list.slice(i, i + BATCH));
  const results = await Promise.allSettled(batches.map((b) => ask(b)));
  if (results.every((r) => r.status === 'rejected')) throw results[0].reason;

  const taken = new Set();
  const plan = [];
  const accept = (matches) => {
    for (const m of matches) {
      const id = clean(m?.id); const key = clean(m?.fact);
      const desc = byId.get(id); const fact = facts.get(key);
      if (!desc || !fact || taken.has(id)) continue;
      if (!fits(desc, key)) continue;
      taken.add(id);
      plan.push({ id, key, label: fact.label, value: fact.value, locked: fact.locked });
    }
  };
  for (const r of results) if (r.status === 'fulfilled') accept(r.value); // a batch that failed leaves its fields for the member, the rest still fill

  // A second look at what was not matched: a model that was unsure about one field in a batch often gets it right alone.
  const failedBatches = results.filter((r) => r.status === 'rejected').length;
  const left = list.filter((d) => !taken.has(d.id));
  if (left.length && left.length <= 30 && failedBatches === 0) {
    try { accept(await ask(left, true)); } catch { /* the first pass stands */ }
  }
  return { plan, asked: list.length };
}

module.exports = { planFill, buildFacts, cleanDescriptor, fits, parseDob, ageFrom, STANDARD };
