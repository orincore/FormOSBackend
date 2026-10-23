// Works out WHICH details a member asked for, so the assistant answers with only those. Used by the agent's tools
// and the vault shortcut, and enforced in code: a model that passes wrong arguments still cannot make the bot read
// out more than was asked.

// Words that name a field. Checked against the message with any "on my Aadhaar"-style source phrase removed, because
// "my address on my Aadhaar" asks for the address, not for the Aadhaar number.
const FIELD_WORDS = [
  ['address', /\b(address|addr|residen\w*|where do i live)\b/i],
  ['pincode', /\b(pin ?code|postal ?code|zip ?code|zip)\b/i],
  ['state', /\bstate\b/i],
  ['fatherName', /\b(father'?s?|s\/o|son of)\b/i],
  ['dateOfBirth', /\b(dob|d\.o\.b|date of birth|birth ?day|birth ?date|born|age|how old)\b/i],
  ['gender', /\b(gender|sex)\b/i],
  ['aadhaarNumber', /\b(aadhaa?r|aadhar|adhar|uid)\b/i],
  ['panNumber', /\bpan\b/i],
  ['passportNumber', /\bpassport\b/i],
  ['drivingLicenseNumber', /\b(driving licen[cs]e|licen[cs]e|dl)\b/i],
  ['phone', /\b(phone|mobile|cell|contact number|whatsapp number)\b/i],
  ['email', /\be-?mail\b/i],
  ['fullName', /\b(name)\b/i],
];

const DOC_WORDS = { aadhaar: /aadhaa?r|aadhar|adhar|uid/i, pan: /\bpan\b/i, passport: /passport/i, license: /licen[cs]e|\bdl\b/i };

// "on my aadhaar", "from my PAN card", "in the passport": the document the answer should come from.
const SOURCE = /\b(?:on|in|from|of|at)\s+(?:my\s+|the\s+|your\s+)?(aadhaa?r|aadhar|adhar|uid|pan|passport|driving licen[cs]e|licen[cs]e|dl)(?:\s+(?:card|copy|document|doc))?\b/i;

// Only these mean "everything". Words like "complete" or "full" alone do not ("my full address" is still the address).
const EVERYTHING = /\b(everything|all (?:of )?(?:my |the )?(?:details|info\w*|data|fields|stuff)|entire (?:profile|details|data)|whole (?:profile|details|data)|what (?:do you|all do you) know about me|my (?:full |complete )?profile)\b/i;

const DOC_NUMBER_KEYS_EARLY = new Set(['aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber']);
const KEY_DOC_EARLY = { aadhaarNumber: 'aadhaar', panNumber: 'pan', passportNumber: 'passport', drivingLicenseNumber: 'license' };
const NUMBER_WORD = /\b(number|no|num|id|card)\b/i;
const FILLER = new Set('what whats is are was were my mine me the a an of on in at from to for and or please can could you do does did i have has get got give send show tell see when where who which how about also any all with as by it its this that details detail info information data kindly pls'.split(' '));
// Someone else's name (mother, spouse...): asking for it is not asking for the member's own name.
const OTHER_PERSON = /\b(mother|mom|spouse|husband|wife|guardian|nominee|brother|sister|son|daughter|parent)s?\b/i;

function requestedFields(text) {
  const raw = String(text || '');
  const source = raw.match(SOURCE);
  let doc = source ? Object.keys(DOC_WORDS).find((k) => DOC_WORDS[k].test(source[1])) || null : null;
  const stripped = raw.replace(SOURCE, ' ');
  let keys = FIELD_WORDS.filter(([, re]) => re.test(stripped)).map(([key]) => key);
  // "father's name" is the father's name only, not also the member's own name.
  if (keys.includes('fatherName')) keys = keys.filter((k) => k !== 'fullName');
  if (OTHER_PERSON.test(stripped)) keys = keys.filter((k) => k !== 'fullName');
  // A document's name is the place to look, not the thing asked for: "when does my licence expire" asks about the date, not
  // the licence number. The number is meant only when it is asked for ("licence number") or nothing else is.
  const docKeys = keys.filter((k) => DOC_NUMBER_KEYS_EARLY.has(k));
  if (docKeys.length && !NUMBER_WORD.test(stripped)) {
    const others = keys.filter((k) => !DOC_NUMBER_KEYS_EARLY.has(k));
    const leftover = stripped.toLowerCase().replace(/[^a-z ]/g, ' ').split(/\s+/).filter((w) => w && !FILLER.has(w) && !FIELD_WORDS.some(([, re]) => re.test(w)));
    if (others.length || leftover.length) { keys = others; doc = doc || KEY_DOC_EARLY[docKeys[0]]; }
  }
  // "address" with a source phrase that is itself a number word (e.g. "aadhaar number") keeps working: the strip above
  // only removes the document when it is introduced by on/in/from/of.
  return { keys, doc, everything: EVERYTHING.test(raw) };
}

// The keys to restrict an answer to, or null when the whole profile may be shown.
function limitTo(text) {
  const { keys, everything } = requestedFields(text);
  return keys.length && !everything ? keys : null;
}

const DOC_NUMBER_KEYS = new Set(['aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber']);
const KEY_DOC = { aadhaarNumber: 'aadhaar', panNumber: 'pan', passportNumber: 'passport', drivingLicenseNumber: 'license' };

// "show my aadhaar details" asks about that document as a whole. Returns the document type, or null.
function documentDetailsFor(text) {
  const { keys, everything } = requestedFields(text);
  if (!keys.length || everything || !keys.every((k) => DOC_NUMBER_KEYS.has(k))) return null;
  if (!/\b(details?|info\w*|information|data|fields)\b/i.test(String(text))) return null;
  return KEY_DOC[keys[0]];
}

// "show my details", "everything", "my profile": the whole profile was asked for.
const BARE_EVERYTHING = /^\s*(?:please\s+)?(?:show|give|send|tell|display|list|get)?\s*(?:me\s+)?(?:all\s+)?(?:my\s+|the\s+)?(?:details?|info\w*|data|profile|everything)\s*[.?!]*\s*$/i;
const wantsEverything = (text) => EVERYTHING.test(String(text || '')) || BARE_EVERYTHING.test(String(text || ''));

module.exports = { requestedFields, limitTo, documentDetailsFor, wantsEverything, DOC_WORDS };
