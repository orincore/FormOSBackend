// Fields that come from the document itself. A driving licence has a licence number and a vehicle class, a marksheet has
// a roll number, a seat number and marks, a bank passbook has an account number: the list is never fixed. The OCR text is
// turned into whatever labelled values the document prints, stored as plain extra keys next to the usual ones
// (rollNo, classOfVehicle, ...), and a question is answered by finding the fields it asks about.
//
// Everything here runs locally except the optional AI pass (standard accounts only). Encrypted (Security V2) accounts
// use the local reader and the local matcher, so their document text never reaches a cloud service.

// ---- keys and labels --------------------------------------------------------------------------------------------
// The details FormOS already knows by name. A label that means one of them is stored under that key.
const KNOWN_KEYS = ['fullName', 'fatherName', 'dateOfBirth', 'gender', 'aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber', 'address', 'pincode', 'state', 'phone', 'email'];

// Housekeeping stored with a document: not details printed on it.
const HIDDEN_KEYS = new Set(['documentType', 'documentName', 'originalName', 'fileSize', 'securityLevel', 'yearOfBirth', 'mimeType', 'documentTitle', 'customFields']);

// Address pieces and duplicate names the address parser adds. They repeat what address/pincode already say.
const ALIAS_KEYS = new Set(['zip', 'zipCode', 'postalCode', 'addressLine1', 'addressLine2', 'streetAddress', 'street']);

const LABEL_TO_KNOWN = [
  ['fatherName', /^(?:father'?s?|fathers?)\s*(?:name)?$|^(?:s\/o|son of|d\/o|daughter of|w\/o|wife of|c\/o|care of|son\/daughter\/wife of|guardian)(?:\s+name)?$|^s[\/ ]?[dw][\/ ]?[wd]?\s*of$|^(?:s\/w\/d|s\/d\/w|sdw) of$/],
  ['fullName', /^(?:(?:full|candidate'?s?|student'?s?|holder'?s?|applicant'?s?|cardholder|account holder|card holder|employee'?s?)\s+)*name(?: of (?:the )?(?:holder|candidate|student|applicant))?$/],
  ['dateOfBirth', /^(?:dob|d\.?o\.?b\.?|date of birth|birth date|birthday)$/],
  ['gender', /^(?:gender|sex)$/],
  ['aadhaarNumber', /^(?:your )?(?:aadhaa?r|aadhar|adhar|uid)(?: (?:no|number|card no))?$/],
  ['panNumber', /^(?:pan|permanent account number)(?: (?:no|number|card no))?$/],
  ['passportNumber', /^passport (?:no|number|file no)$/],
  ['drivingLicenseNumber', /^(?:dl|driving licen[cs]e|licen[cs]e|licen[cs]ence)(?: (?:no|number))?$|^dl ?no$/],
  ['address', /^(?:permanent |present |residential |current |communication |postal |mailing )?(?:address|addr)$/],
  ['pincode', /^(?:pin ?code|pin|postal code|zip(?: code)?)$/],
  ['state', /^state(?: name)?$/],
  ['phone', /^(?:phone|mobile|mobile no|mobile number|phone no|phone number|contact|contact no|contact number|tel|telephone|cell)$/],
  ['email', /^e-?mail(?: id| address)?$/],
];

const cleanLabel = (label) => String(label || '').replace(/[|_*#~`"]/g, ' ').replace(/\s+/g, ' ').replace(/^[\s:.\-–—)(]+|[\s:.\-–—)(]+$/g, '').trim();

// "Class of Vehicle" -> classOfVehicle. Letters and digits only, at most 40 characters: the shape the app accepts.
const RESERVED_KEYS = new Set(['constructor', 'prototype', 'tostring', 'valueof', 'hasownproperty', 'isprototypeof', 'proto', 'toJSON', 'length']);
const LABEL_ALIASES = [
  [/^(?:cov|class of vehicles?|vehicle class|type of vehicle|vehicle type)$/, 'classOfVehicle'],
  [/^(?:doi|dol|d\.o\.i\.?|date of issue|issue date|issued on|date of issuance)$/, 'dateOfIssue'],
  [/^(?:valid till|valid upto|valid up to|valid through|valid until|validity|date of expiry|expiry date|expiry|expires on)$/, 'validTill'],
  [/^(?:po|post office)$/, 'postOffice'],
  [/^(?:dist(?:rict)? (?:and|&) school no\.?|dist\.? ?& ?school no\.?)$/, 'districtAndSchoolNo'],
];

function labelToKey(label) {
  // "Candidate's Mother's Name (Surname first)" -> "mother name": no possessives, no bracketed remarks.
  const clean = cleanLabel(label).toLowerCase().replace(/\([^)]*\)?/g, ' ').replace(/['’]s\b/g, '').replace(/['’]/g, '').replace(/^(?:candidate|student|applicant)\s+(?=\w+\s+name$)/, '').replace(/\s+/g, ' ').trim();
  for (const [re, key] of LABEL_ALIASES) if (re.test(clean)) return key;
  for (const [key, re] of LABEL_TO_KNOWN) if (re.test(clean)) return key;
  const words = clean.replace(/[^a-z0-9]+/g, ' ').trim().split(' ').filter(Boolean);
  if (!words.length) return null;
  const key = words.map((w, i) => (i === 0 ? w : w[0].toUpperCase() + w.slice(1))).join('').slice(0, 40);
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key)) return null; // must start with a letter
  // names that clash with the app's own keys, or with JavaScript object internals, get a suffix
  return KNOWN_KEYS.includes(key) || HIDDEN_KEYS.has(key) || RESERVED_KEYS.has(key) ? `${key}Detail`.slice(0, 40) : key;
}

// The reverse, for showing a key to a person: classOfVehicle -> Class Of Vehicle (same as the app's own pretty-printer).
const ACRONYMS = new Set(['vid', 'vtc', 'dl', 'dob', 'doi', 'cov', 'id', 'pan', 'uid', 'ifsc', 'rto', 'cgpa', 'sgpa', 'gpa', 'ssc', 'hsc', 'cif', 'micr', 'prn', 'epic', 'rc', 'nt']);
const keyToLabel = (key) => String(key).replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase()).trim().split(' ').map((w) => (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w)).join(' ');

const KNOWN_LABEL = {
  fullName: 'Name', fatherName: "Father's name", dateOfBirth: 'Date of birth', gender: 'Gender', aadhaarNumber: 'Aadhaar number',
  panNumber: 'PAN number', passportNumber: 'Passport number', drivingLicenseNumber: 'Licence number', address: 'Address',
  pincode: 'PIN code', state: 'State', phone: 'Phone', email: 'Email',
};
const labelOf = (key) => KNOWN_LABEL[key] || keyToLabel(key);

// ---- reading labelled values out of OCR text (local) ------------------------------------------------------------
// Words that start a label on identity, education, vehicle, bank, insurance and similar documents. Used only for lines
// that have no colon ("Seat No 123456"); lines with a colon are read as label: value whatever the label is.
const VOCAB = [
  'dl no', 'dl number', 'licence no', 'license no', 'licence number', 'license number', 'driving licence no', 'driving license no',
  'date of issue', 'issue date', 'issued on', 'date of expiry', 'expiry date', 'valid till', 'valid upto', 'valid up to', 'valid from', 'validity',
  'validity nt', 'validity tr', 'class of vehicle', 'cov', 'vehicle class', 'vehicle type', 'type of vehicle', 'blood group', 'issuing authority', 'authority',
  'roll no', 'roll number', 'seat no', 'seat number', 'enrolment no', 'enrollment no', 'registration no', 'registration number', 'reg no', 'prn no', 'prn',
  'exam', 'examination', 'exam name', 'centre', 'center', 'centre no', 'college', 'school', 'university', 'board', 'institute', 'course', 'stream', 'branch',
  'percentage', 'percent', 'total marks', 'marks obtained', 'total', 'result', 'grade', 'cgpa', 'sgpa', 'gpa', 'division', 'class obtained', 'year of passing',
  'passing year', 'month and year of passing', 'date of result', 'date of declaration', 'certificate no', 'serial no', 'sr no', 'application no', 'form no',
  'mother name', "mother's name", 'mothers name', 'father name', "father's name", 'fathers name', 'guardian name', 'nationality', 'religion', 'category', 'caste', 'sub caste',
  'mobile no', 'mobile number', 'phone no', 'email id', 'email', 'account no', 'account number', 'a/c no', 'ifsc', 'ifsc code', 'bank', 'bank name', 'branch name',
  'customer id', 'cif no', 'micr', 'policy no', 'policy number', 'sum assured', 'premium', 'nominee', 'vehicle no', 'vehicle number', 'registration date', 'chassis no',
  'engine no', 'owner name', 'owner', 'fuel', 'fuel type', 'make', 'model', 'colour', 'color', 'manufacturing date', 'seating capacity', 'epic no', 'voter id', 'part no',
  'assembly constituency', 'ration card no', 'card no', 'card number', 'employee id', 'employee no', 'designation', 'department', 'date of joining', 'valid through',
  'name', 'date of birth', 'dob', 'gender', 'sex', 'address', 'pin code', 'pincode', 'state', 'city', 'district', 'taluka', 'country',
  'doi', 'dist & school no', 'district & school no', 'month & year of exam', 'month and year of exam', 'sr no of statement', 'serial no of statement',
  'candidate full name', 'full name', 'mothers name', 'enrolment no', 'your aadhaar no', 'aadhaar no', 'vid', 'vtc', 'po', 'sub district',
];
const VOCAB_SORTED = [...new Set(VOCAB)].sort((a, b) => b.length - a.length);

// Labels whose values are free text: without a colon they are only trusted for a short value (or one with a digit), so a
// heading like "STATE BOARD OF SECONDARY EDUCATION" is not read as State = "BOARD OF ...".
const FREE_TEXT_LABELS = new Set(['state', 'name', 'branch', 'board', 'college', 'school', 'university', 'institute', 'course', 'stream', 'department', 'bank', 'owner', 'authority', 'exam', 'examination', 'category', 'caste', 'religion', 'nationality', 'address', 'city', 'district', 'country', 'make', 'model', 'fuel', 'colour', 'color', 'owner name', 'bank name', 'branch name']);
const shortOrNumeric = (value) => /\d/.test(value) || value.trim().split(/\s+/).length <= 3;
// Marks tables: "Mathematics 92" or "Science 88 / 100" on a document that is a marksheet.
const MARKSHEET = /\b(marksheet|mark sheet|statement of marks|grade card|marks obtained|total marks|result)\b/i;
const SUBJECT_LINE = /^([A-Za-z][A-Za-z &.'()-]{2,40}?)\s+(\d{1,3}(?:\.\d{1,2})?(?:\s*\/\s*\d{1,3})?)$/;

const MARKS_ROW = /^(?:([A-Za-z0-9\u00C0-\u00FF]{1,3})\s+(?=[A-Z]{4}))?([A-Za-z][A-Za-z0-9 &().,/'-]{2,48}?)\s+(\d{2,3}|\*)\s+([A-Za-z0-9]{2,4}|[A-F][+]?)(?:\s+([A-Za-z ]+))?$/;
const GRADE_ROW = /^(?:([A-Za-z0-9\u00C0-\u00FF]{1,3})\s+(?=[A-Z]{4}))?([A-Za-z][A-Za-z &().,/'-]{3,48}?)\s+()(?:\*\s+)?([A-F][+]?)$/;

// Number words as printed on a marksheet: "SEVENTYSEVEN" -> 77 (the OCR often runs them together).
const UNITS = { zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19 };
const TENS = { twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70, eighty: 80, ninety: 90 };
function wordsToNumber(text) {
  let rest = String(text || '').toLowerCase().replace(/[^a-z]/g, '');
  if (!rest) return null;
  let total = 0; let guard = 0;
  const names = [...Object.keys(UNITS), ...Object.keys(TENS), 'hundred', 'and'].sort((a, b) => b.length - a.length);
  while (rest && guard++ < 12) {
    const w = names.find((n) => rest.startsWith(n));
    if (!w) return null;
    rest = rest.slice(w.length);
    if (w === 'hundred') total = (total || 1) * 100; else if (w in TENS) total += TENS[w]; else if (w in UNITS) total += UNITS[w];
  }
  return rest ? null : total;
}

// Subject names the OCR ran together ("DECORATIVEPIECESFROMWASTE") are split with the common school-subject words.
const SUBJECT_WORDS = ['english', 'hindi', 'marathi', 'sindhi', 'gujarati', 'urdu', 'sanskrit', 'tamil', 'telugu', 'kannada', 'malayalam', 'bengali', 'punjabi', 'mathematics', 'maths', 'science', 'sciences', 'technology', 'social', 'studies', 'history', 'geography', 'civics', 'economics', 'physics', 'chemistry', 'biology', 'computer', 'applications', 'education', 'health', 'physical', 'personality', 'development', 'information', 'communication', 'decorative', 'pieces', 'from', 'waste', 'service', 'work', 'experience', 'art', 'arts', 'drawing', 'music', 'language', 'lang', 'first', 'second', 'third', 'environmental', 'general', 'moral', 'value', 'values', 'and', 'of', 'the', 'tec', 'tech', 'accountancy', 'commerce', 'business', 'organisation', 'management', 'secretarial', 'practice', 'book', 'keeping', 'statistics', 'political', 'sociology', 'psychology', 'philosophy', 'electronics', 'engineering', 'vocational', 'agriculture', 'sports', 'yoga', 'craft', 'handicraft', 'cooking', 'sewing'];
function unglue(word) {
  const w = String(word).toLowerCase();
  if (w.length <= 12 || /[^a-z]/.test(w)) return word;
  const best = new Array(w.length + 1).fill(null); best[0] = [];
  for (let i = 0; i < w.length; i++) {
    if (!best[i]) continue;
    for (const s of SUBJECT_WORDS) if (w.startsWith(s, i) && (!best[i + s.length] || best[i + s.length].length > best[i].length + 1)) best[i + s.length] = [...best[i], s];
  }
  return best[w.length] ? best[w.length].join(' ') : word;
}
const subjectName = (raw) => raw.replace(/&/g, ' & ').split(/\s+/).filter(Boolean).filter((w, i) => !(i === 0 && /^[A-Za-z]{0,2}\d+[A-Za-z]?$/.test(w))).map(unglue).join(' ').replace(/\s+/g, ' ').toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());

// A place name is a value, never a label: "Maharashtra 411016" is an address line, not a field called Maharashtra.
const PLACE_NAMES = new Set(['andhrapradesh', 'arunachalpradesh', 'assam', 'bihar', 'chhattisgarh', 'goa', 'gujarat', 'haryana', 'himachalpradesh', 'jharkhand', 'karnataka', 'kerala', 'madhyapradesh', 'maharashtra', 'manipur', 'meghalaya', 'mizoram', 'nagaland', 'odisha', 'orissa', 'punjab', 'rajasthan', 'sikkim', 'tamilnadu', 'telangana', 'tripura', 'uttarpradesh', 'uttarakhand', 'westbengal', 'delhi', 'newdelhi', 'mumbai', 'pune', 'chennai', 'kolkata', 'bangalore', 'bengaluru', 'hyderabad', 'ahmedabad', 'jammuandkashmir', 'ladakh', 'chandigarh', 'puducherry', 'india', 'bharat']);

const NOISE_WORDS = ['note', 'date', 'place', 'page', 'name', 'sign', 'photo', 'seal'];
const NOISE_LABEL = /^(?:note|notes|instructions?|terms|signature|photo|date|place|page|sr|no|sl)$/i;

// ---- rejecting noise ----------------------------------------------------------------------------------------------
// OCR of a blank form or a poor photo produces fake "fields": placeholders (XXXX, <FIRST>, DD/MM/YYYY), broken words and
// whole headings. A pair is kept only when its label reads like a real label and its value like a real value.
const PLACEHOLDER_VALUE = /^(?:[Xx*#_]+[\s\-\/.]*)+$|[<>]|^(?:dd|mm|yyyy)\b|^[\s\-_.\/]*$/i;
function wordLooksReal(word) {
  const w = word.replace(/[^A-Za-z]/g, '');
  if (!w) return true;
  if (w.length > 14) return false;
  if (/^[a-z]+[A-Z]/.test(w)) return false;                    // oateName, electorSName: letters glued by OCR
  if (w.length >= 4 && !/[aeiouyAEIOUY]/.test(w)) return false;  // no vowel
  if (/[^aeiouyAEIOUY]{6,}/.test(w)) return false;              // long consonant run
  if (/^(.)\1{2,}$/i.test(w)) return false;                    // XXXX, aaaa
  if (w.length >= 5) { const counts = {}; for (const ch of w.toLowerCase()) counts[ch] = (counts[ch] || 0) + 1; if (Math.max(...Object.values(counts)) / w.length > 0.5) return false; } // xxxxixxixx
  return true;
}
const SHORT_OK = new Set(['no', 'of', 'id', 'dl', 'to', 'po', 'in', 'on', 'dob', 'doi', 'a/c', 's/o', 'd/o', 'w/o', 's/d/w', '&', 'pf', 'pan', 'uid', 'vid', 'vtc', 'cov', 'sr']);
function labelLooksReal(label) {
  const words = label.split(' ').filter(Boolean);
  if (words.length > 5) return false;
  if (label.length > 36) return false;
  if (words.length > 1 && words.some((w) => w.replace(/[^A-Za-z]/g, '').length <= 2 && !SHORT_OK.has(w.toLowerCase().replace(/[.:]+$/, '')))) return false; // "be Division": a stray fragment before the label
  const letters = label.replace(/[^A-Za-z]/g, '').length;
  const odd = label.replace(/[A-Za-z\s/&.'-]/g, '').length; // digits and symbols other than the usual label punctuation
  if (letters < 2 || odd / label.replace(/\s/g, '').length > 0.2) return false;
  return words.every(wordLooksReal);
}
function valueLooksReal(value) {
  if (PLACEHOLDER_VALUE.test(value)) return false;
  const alnum = value.replace(/[^A-Za-z0-9\u0900-\u097F]/g, '').length;
  return alnum >= 1 && (alnum / value.length >= 0.55 || (value.length <= 4 && alnum >= 1));
}
// A value that does not fit what its (known) key holds is dropped: an address for a name, a sentence for a date.
const NAME_STOP = /\b(sex|male|female|case|card|change|signature|officer|address|date|number|form|photo|government|india|department|election|commission|identity)\b/i;
function valueFitsKey(key, value) {
  const v = value.trim();
  switch (key) {
    case 'fullName': case 'fatherName': return /^[A-Za-z][A-Za-z .'-]{1,60}$/.test(v) && v.split(/\s+/).length <= 6 && !NAME_STOP.test(v) && v.replace(/[^A-Za-z]/g, '').length >= 3 && v.split(/\s+/).every((w) => w.length < 3 || /[aeiouyAEIOUY]/.test(w));
    case 'dateOfBirth': return /\d{1,2}\s*[\/.-]\s*\d{1,2}\s*[\/.-]\s*\d{4}|^\d{4}$/.test(v);
    case 'gender': return /^(?:male|female|transgender|m|f|other)$/i.test(v);
    case 'pincode': return /^[1-9]\d{5}$/.test(v);
    case 'phone': return /^(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}$/.test(v);
    case 'email': return /^[^\s@]+@[^\s@]+\.[A-Za-z]{2,}$/.test(v);
    case 'address': return v.length >= 8 && v.length <= 250 && v.split(/[\s,]+/).filter(Boolean).length >= 3 && !/^(?:identity|card|government|election|name|date|signature|father|mother)\b/i.test(v) && (/\b[1-9]\d{5}\b/.test(v) || !NAME_STOP.test(v.split(/[,\n]/)[0]));
    case 'state': return /^[A-Za-z .&-]{2,40}$/.test(v) && !/board|education|commission/i.test(v);
    default: return true;
  }
}

// A subject name on a marks table: letters (a few digits like "Paper 2" are fine), never a code such as "PR ESE 025010023".
function subjectLabelLooksReal(label) {
  const letters = label.replace(/[^A-Za-z]/g, '').length;
  return letters >= 3 && !/\d{3,}/.test(label) && label.split(' ').length <= 6 && letters / label.replace(/[\s&.()'-]/g, '').length >= 0.8;
}

function acceptPair(label, value, { subject = false } = {}) {
  if (/\([^)]*$/.test(String(label)) || /^[^(]*\)/.test(String(label))) return null; // a torn bracket ("BANDRA (EAST")
  const l = normalizeLabel(label);
  let v = String(value || '').replace(/\s+/g, ' ').replace(/^[\s:.,;\-–—|\\/]+|[\s|\\/_,;]+$/g, '').trim();
  if (!l || !v) return null;
  // a field called "... Name" holds a name: letters only, a few words, no digits or sentence words
  if (/\bname$/i.test(l) && !(/^[A-Za-z][A-Za-z .'-]{1,60}$/.test(v) && v.split(/\s+/).length <= 6 && !NAME_STOP.test(v) && !/\b(for|of|the|and|in|at|to)\b/i.test(v.replace(/\bof\b(?=\s+[A-Z])/g, '')))) return null;
  if (l.length < 2 || l.length > 38 || l.split(' ').length > 5) return null;
  if (!/[A-Za-z]/.test(l) || NOISE_LABEL.test(l)) return null;
  const compact = compactLetters(l);
  const firstWord = l.split(' ')[0].toLowerCase();
  const lastWord = l.split(' ').pop().toLowerCase();
  if (/\([^)]*$/.test(l) || /^[^(]*\)/.test(l)) return null;                                   // an unbalanced bracket: a torn fragment
  if (PLACE_NAMES.has(compact)) return null;                                                      // a state or city is a value, not a label
  if (/^[1-9]\d{5}$/.test(v) && !/\b(pin|postal|zip|code)\b/i.test(l)) return null;                // a bare PIN code under some other label
  if (['and', 'or', 'the', 'a', 'an', 'on', 'is', 'of', 'to', 'in', 'by', 'as', 'at', 'for', 'with'].includes(firstWord) || ['and', 'or', 'the', 'of', 'to', 'is', 'on', 'in'].includes(lastWord)) return null;
  if (compact.length <= 3 && !VOCAB_COMPACT.has(compact) && !SHORT_OK.has(l.toLowerCase())) return null; // "qar": too short to be a label
  if (compact.length >= 4 && NOISE_WORDS.some((n) => n.length === compact.length && [...n].filter((c, i) => c !== compact[i]).length <= 1)) return null; // "oate" for "date": a mis-read noise label
  if (v.length < 1 || v.length > 200) return null;
  if (/^[^A-Za-z0-9]+$/.test(v)) return null;
  if (VOCAB_SORTED.includes(v.toLowerCase())) return null; // a value that is itself a label: the pairing slipped
  if ((subject ? !subjectLabelLooksReal(l) : !labelLooksReal(l)) || !valueLooksReal(v)) return null;
  return { label: l, value: v };
}

// Lines read as "Label : value", several to a line ("Roll No : 123   Seat No : 456"), "Label value" for known label
// words, and a label on one line with its value on the next.
function genericPairs(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/).map((l) => l.replace(/[ \t]+/g, ' ').trim()).filter(Boolean);
  const isMarksheet = MARKSHEET.test(String(text || ''));
  const startsWithLabel = (line) => VOCAB_SORTED.find((w) => line.toLowerCase() === w || line.toLowerCase().startsWith(`${w} `) || line.toLowerCase().startsWith(`${w}:`));

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // label : value (possibly several on one line)
    if (/[:：]/.test(line)) {
      const re = /([A-Za-z][A-Za-z0-9 ./()'&-]{1,38}?)\s*[:：]\s*([^:：]+?)(?=\s+[A-Za-z][A-Za-z0-9 ./()'&-]{1,38}\s*[:：]|$)/g;
      let m; let any = false;
      while ((m = re.exec(line))) { const p = acceptPair(m[1], m[2]); if (p) { out.push(p); any = true; } }
      if (any) continue;
      // "Address:" alone with the value on the next line(s)
      const lone = line.match(/^([A-Za-z][A-Za-z0-9 ./()'&-]{1,38}?)\s*[:：]\s*$/);
      if (lone && lines[i + 1] && !/[:：]\s*$/.test(lines[i + 1])) {
        const next = [lines[i + 1]];
        if (/address|addr/i.test(lone[1]) && lines[i + 2] && !/[:：]/.test(lines[i + 2]) && !startsWithLabel(lines[i + 2])) next.push(lines[i + 2]);
        const p = acceptPair(lone[1], next.join(', '));
        if (p) { out.push(p); i += next.length; }
        continue;
      }
    }

    // "Seat No 123456": a known label word, then its value on the same line
    const word = startsWithLabel(line);
    if (word && line.length > word.length + 1) {
      const value = line.slice(word.length).replace(/^[\s:.\-–—]+/, '');
      if (!FREE_TEXT_LABELS.has(word) || shortOrNumeric(value)) {
        const p = acceptPair(line.slice(0, word.length), value);
        if (p) { out.push(p); continue; }
      }
    }

    // a marks table row: "03 ENGLISH(1ST LANG) 100 067 SIXTY SEVEN" or a grade-only subject "P1 HEALTH & PHYSICAL EDUCATION * B"
    if (isMarksheet) {
      const cleaned = line.replace(/[¢©®°•¥£€§¦|]/g, ' ').replace(/\s+/g, ' ').trim();
      const row = cleaned.match(MARKS_ROW) || cleaned.match(GRADE_ROW);
      const subjectText = row ? row[2].replace(/\(.*$/, '').replace(/\s+/g, ' ').trim() : '';
      // the result row ("PASS 78.40 Total Marks 500 392") is not a subject
      if (row && !/\b(total|result|percentage|pass|fail|marks|grade|figures|words)\b|\d\.\d|%/i.test(subjectText)) {
        const subject = subjectText;
        // The printed words ("SEVENTY SEVEN") back up, or rescue, figures the OCR misread ("OTT").
        const figures = String(row[4] || row[3] || '').replace(/[Oo]/g, '0').replace(/[Il]/g, '1');
        const gradeOnly = /^[A-F][+]?$/.test(String(row[4] || row[3] || ''));
        const fromWords = row[5] ? wordsToNumber(row[5]) : null;
        const obtained = gradeOnly ? String(row[4] || row[3]) : (/^\d{2,3}$/.test(figures) ? figures : (fromWords !== null ? String(fromWords) : null));
        if (obtained === null) continue;
        const value = /^\d+$/.test(obtained) ? `${Number(obtained)}${/^\d+$/.test(row[3] || '') ? ` / ${Number(row[3])}` : ''}` : obtained;
        const p = acceptPair(subjectName(subject), value, { subject: true });
        if (p) { out.push(p); continue; }
      }
    }

    // subject marks on a marksheet
    if (isMarksheet && !word) {
      const sub = line.match(SUBJECT_LINE);
      if (sub && !NOISE_LABEL.test(sub[1].trim())) { const p = acceptPair(sub[1], sub[2]); if (p) { out.push(p); continue; } }
    }

    // a label on its own line, its value on the next
    if (word && line.toLowerCase() === word && lines[i + 1] && !startsWithLabel(lines[i + 1]) && lines[i + 1].length <= 120) {
      const p = acceptPair(line, lines[i + 1]);
      if (p) { out.push(p); i += 1; }
    }
  }
  return out;
}

// { key: value } for every labelled value found, never overwriting a key already set.
function genericFields(text, into = {}) {
  const fields = {};
  for (const { label, value } of genericPairs(text)) {
    const key = labelToKey(label);
    if (!key || fields[key] !== undefined || into[key]) continue;
    if (KNOWN_KEYS.includes(key) && !valueFitsKey(key, value)) continue;
    fields[key] = value.slice(0, 500);
  }
  return fields;
}

// A short title for the document ("Driving Licence", "Statement of Marks"): the first heading-like line, else a guess.
const TITLE_WORDS = /\b(driving licen[cs]e|licen[cs]e|marksheet|mark sheet|statement of marks|grade card|certificate|passbook|passport|aadhaar|aadhar|permanent account number|pan card|voter|election|ration card|registration certificate|insurance|policy|invoice|receipt|admit card|hall ticket|degree|transcript|diploma|identity card|id card|bank statement|cheque)\b/i;
function titleFor(text, typeLabel = '', fileName = '') {
  const lines = String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 14);
  const head = lines.join(' ');
  if (/statement of marks|mark\s*-?sheet|grade ?card/i.test(head)) return 'Statement Of Marks';
  const cleanTitle = (l) => l.length <= 70 && !/[:：]/.test(l) && l.split(/\s+/).length <= 9 && l.split(/\s+/).every(wordLooksReal) && !/\b(government|authority|department|ministry|republic|commission|unique|identification)\b/i.test(l);
  const line = lines.find((l) => TITLE_WORDS.test(l) && cleanTitle(l));
  if (line) return line.replace(/\s+/g, ' ').toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase()).slice(0, 80);
  if (typeLabel && typeLabel !== 'Document') return typeLabel;
  return String(fileName || '').replace(/\.[A-Za-z0-9]{2,4}$/, '').replace(/[_-]+/g, ' ').replace(/\b[a-z]/g, (c) => c.toUpperCase()).slice(0, 60);
}

// ---- value typing ------------------------------------------------------------------------------------------------
// Each field is tidied and checked for what it should hold, so a date is a date, a blood group looks like one, and trailing
// logo or form text that the OCR boxes ran together ("14-08-2044 (NT) FORM 7") is cut off.
const DATE_RE = /\b(\d{1,2})\s*[-/.]\s*(\d{1,2})\s*[-/.]\s*(\d{4}|\d{2})\b(?:\s*\((?:NT|T|TR|NTR)\))?/i;
const DATE_KEYS = new Set(['dateOfBirth', 'dateOfIssue', 'validTill', 'dateOfExpiry', 'registrationDate', 'dateOfJoining', 'dateOfResult']);
const isDateLabel = (key, label) => DATE_KEYS.has(key) || /\b(date|dob|doi|valid|expiry|issued)\b/i.test(label);
const MONTHS = /\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[\s,.-]*(\d{2,4})\b/i;

// Returns { value, score } or null. score: 2 = fits the field's type exactly, 1 = plausible, 0 = weak.
function tidyValue(key, label, raw) {
  let v = String(raw || '').replace(/\s+/g, ' ').replace(/^[\s:.\-–—|]+|[\s|]+$/g, '').trim();
  if (!v) return null;
  if (/blood\s*group/i.test(label) || key === 'bloodGroup') {
    const m = v.match(/\b(AB|A|B|O)\s*([+-]|pos(?:itive)?|neg(?:ative)?)?(?=\s|$)/i);
    if (!m) return null;
    const sign = m[2] ? (/^p|\+/i.test(m[2]) ? '+' : '-') : '';
    return { value: `${m[1].toUpperCase()}${sign}`, score: sign ? 2 : 0 };
  }
  if (/month\s*(?:and|&)?\s*year/i.test(label)) {
    const m = v.match(MONTHS);
    return m ? { value: v.slice(0, 30), score: 2 } : { value: v.slice(0, 30), score: 0 };
  }
  if (isDateLabel(key, label)) {
    const m = v.match(DATE_RE);
    if (!m) return /^\d{4}$/.test(v) ? { value: v, score: 1 } : null;
    const [, d, mo, y] = m;
    if (Number(mo) < 1 || Number(mo) > 12 || Number(d) < 1 || Number(d) > 31) return null;
    const year = y.length === 2 ? y : y; // a two-digit year is left as printed: the century cannot be guessed
    const suffix = (m[0].match(/\((?:NT|T|TR|NTR)\)/i) || [''])[0].toUpperCase();
    return { value: `${d.padStart(2, '0')}/${mo.padStart(2, '0')}/${year}${suffix ? ` ${suffix}` : ''}`, score: 2 };
  }
  if (/^(?:percentage|percent|cgpa|sgpa|gpa|aggregate|total)\b/i.test(label) || ['percentage', 'gpa', 'cgpa', 'sgpa', 'total'].includes(key)) {
    // a figure, not the heading text that came after it in the same box ("83.00 71.33 MAHARASHTRA STATE BOARD...")
    const m = v.match(/^\d+(?:\.\d+)?(?:\s*\/\s*\d+(?:\.\d+)?)?(?:\s+\d+(?:\.\d+)?){0,2}/);
    return m ? { value: m[0].trim(), score: 2 } : null;
  }
  if (key === 'aadhaarNumber') {
    const d = v.replace(/\D/g, '');
    const ocr = require('./ocrService');
    return /^[2-9]\d{11}$/.test(d) && ocr.isValidAadhaar(d) ? { value: `${d.slice(0, 4)} ${d.slice(4, 8)} ${d.slice(8)}`, score: 2 } : null;
  }
  if (key === 'panNumber') { const m = v.toUpperCase().match(/\b[A-Z]{5}\d{4}[A-Z]\b/); return m ? { value: m[0], score: 2 } : null; }
  if (key === 'pincode') { const m = v.match(/\b[1-9]\d{5}\b/); return m ? { value: m[0], score: 2 } : null; }
  if (key === 'phone') { const d = v.replace(/\D/g, '').replace(/^(91|0)(?=\d{10}$)/, ''); return /^[6-9]\d{9}$/.test(d) ? { value: d, score: 2 } : null; }
  if (key === 'email') { const m = v.match(/[^\s@]+@[^\s@]+\.[A-Za-z]{2,}/); return m ? { value: m[0].toLowerCase(), score: 2 } : null; }
  if (key === 'gender') { const m = v.match(/\b(male|female|transgender)\b/i); return m ? { value: m[1][0].toUpperCase() + m[1].slice(1).toLowerCase(), score: 2 } : null; }
  if (KNOWN_KEYS.includes(key) && !valueFitsKey(key, v)) return null;
  if (key === 'fullName' || key === 'fatherName') return { value: v.replace(/\s+/g, ' ').toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase()), score: 1 };
  return { value: v.slice(0, 500), score: 1 };
}

// ---- layout-aware reading ---------------------------------------------------------------------------------------
// The OCR engine reports where every piece of text sits. A label is followed by its value on the right or just under it,
// and a table is a row of labels with the values below. Reading the page that way separates the fields cleanly, where
// reading flattened text runs neighbouring boxes together. Boxes can hold a whole table row, so rows are also split.
const LABEL_SUFFIX = /\b(?:no\.?|number|name|date|year|code|class|group|address|type|status|id|validity|authority|result|percentage|total|grade|division|dob|doi|cov)\s*\.?\s*:?$/i;
const stripRemarks = (t) => String(t).replace(/[(（][^)）]*[)）]?/g, ' ').replace(/\s+/g, ' ').trim();

// "नामांकन क्रम/ Enrolment No." -> "Enrolment No.", "IH / Name" -> "Name", but "S/D/W of" and "A/C No" stay whole.
function englishPart(text) {
  const t = String(text || '').replace(/[ऀ-ॿ]+/g, ' ').replace(/\s+/g, ' ').trim();
  const parts = t.split('/').map((p) => p.trim()).filter(Boolean);
  if (parts.length < 2) return t;
  // a first half that is OCR noise from another script ("3HGGRIET 3TS TA/CANDIDATE'S MOTHER'S NAME") is dropped
  const noisy = (p) => (/\d/.test(p) && /[A-Za-z]/.test(p)) || !p.split(' ').every(wordLooksReal);
  if (noisy(parts[0]) && parts.length >= 2) return parts.slice(1).join('/');
  const last = parts[parts.length - 1];
  const lastLower = stripRemarks(last).toLowerCase().replace(/[:.]+$/, '').trim();
  const lastIsLabel = VOCAB_SORTED.includes(lastLower) || LABEL_SUFFIX.test(stripRemarks(last));
  const shortLetters = parts.slice(0, -1).every((p) => /^[A-Za-z]$/.test(p));
  if (lastIsLabel && !shortLetters) return last;
  return t;
}

const compactLetters = (s) => s.toLowerCase().replace(/[^a-z]/g, '');
const VOCAB_COMPACT = new Map(VOCAB_SORTED.map((w) => [compactLetters(w), w]));
const titleCase = (w) => w.replace(/\b[a-z]/g, (c) => c.toUpperCase());

// Fixes labels OCR broke: "Addre SS" -> "Address", "DOl" -> "DOI". Unknown labels are returned as they are.
function normalizeLabel(raw) {
  const label = cleanLabel(stripRemarks(englishPart(raw)));
  const compact = compactLetters(label);
  if (VOCAB_COMPACT.has(compact)) return titleCase(VOCAB_COMPACT.get(compact));
  if (compact.length >= 3 && compact.length <= 20) {
    const near = [...VOCAB_COMPACT.keys()].filter((v) => v.length === compact.length && [...v].filter((c, i) => c !== compact[i]).length === 1);
    if (near.length === 1) return titleCase(VOCAB_COMPACT.get(near[0]));
  }
  return label;
}

function isLabelItem(text) {
  const t = String(text || '').trim();
  if (!t || /\d{3,}/.test(t)) return false;
  const label = cleanLabel(stripRemarks(englishPart(t)));
  if (!label || label.split(' ').length > 4 || !labelLooksReal(label)) return false;
  if (VOCAB_COMPACT.has(compactLetters(label))) return true;
  return /[:：]\s*$/.test(t) || LABEL_SUFFIX.test(label);
}

// A piece of text that reads as a real value: not a heading in another script, not OCR noise.
const looksLikeValue = (text) => valueLooksReal(text) && String(text).split(/\s+/).every((w) => wordLooksReal(w));

// "CANDIDATE'S MOTHER'S NAME JAYA" -> { label: "Mother Name", value: "JAYA" }: a label word group at the start, then the value.
function splitInline(text) {
  const english = stripRemarks(englishPart(text)).replace(/['’]s/gi, '').replace(/['’]/g, '');
  const tokens = english.split(/\s+/).filter(Boolean);
  for (let k = Math.min(5, tokens.length - 1); k >= 1; k--) {
    const head = tokens.slice(0, k).join(' ');
    let compact = compactLetters(head).replace(/^(?:candidate|student|applicant)(?=.)/, '');
    if (!VOCAB_COMPACT.has(compact)) continue;
    const value = tokens.slice(k).join(' ');
    if (value.length >= 2 && !isLabelItem(value)) return { label: titleCase(VOCAB_COMPACT.get(compact)), value };
  }
  return null;
}

// Longest known label words found one after another in a run of text: "COV DOI" -> [cov, doi]. Each label keeps the
// character position it starts at so its column can be placed on the page.
function headerLabels(text) {
  const flat = []; // letters only, remembering where each came from
  [...String(text)].forEach((ch, i) => { if (/[A-Za-z]/.test(ch)) flat.push({ ch: ch.toLowerCase(), at: i }); });
  const compact = flat.map((f) => f.ch).join('');
  const labels = [];
  let i = 0; let covered = 0;
  while (i < compact.length) {
    let hit = null;
    for (const [word, phrase] of VOCAB_COMPACT) { if (word.length >= 3 && compact.startsWith(word, i) && (!hit || word.length > hit.word.length)) hit = { word, phrase }; }
    if (hit) { labels.push({ label: titleCase(hit.phrase), at: flat[i].at, end: flat[Math.min(compact.length - 1, i + hit.word.length - 1)].at }); i += hit.word.length; covered += hit.word.length; } else i += 1;
  }
  return { labels, coverage: compact.length ? covered / compact.length : 0 };
}

const tokensWithPositions = (text) => { const out = []; const re = /\S+/g; let m; while ((m = re.exec(text))) out.push({ text: m[0], at: m.index }); return out; };

function itemFields(items, known = {}) {
  if (!Array.isArray(items) || items.length < 3) return { fields: {}, candidates: {} };
  const its = items.map((i, n) => ({ ...i, n, h: Math.max(1, i.bottom - i.top), cy: (i.top + i.bottom) / 2 }));
  const colonAt = (t) => { const m = /[:：]/.exec(t); return m && m.index > 0 && m.index < 44 ? m.index : -1; };
  const hasPair = (i) => colonAt(i.text) !== -1 && /[:：]\s*\S/.test(i.text);
  const headerOf = its.map((i) => { if (hasPair(i) || /\d{3,}/.test(i.text)) return null; const h = headerLabels(i.text); return h.labels.length >= 2 && h.coverage >= 0.7 ? h : null; });
  const labelLike = its.map((i, n) => !hasPair(i) && !headerOf[n] && isLabelItem(i.text));
  const used = new Set();
  const candidates = {};

  const put = (rawLabel, rawValue, source = 'layout') => {
    const label = normalizeLabel(rawLabel);
    if (!label || !labelLooksReal(label)) return false;
    const key = labelToKey(label);
    if (!key || (known[key] && !KNOWN_KEYS.includes(key))) return false;
    const tidy = tidyValue(key, label, rawValue);
    if (!tidy || !valueLooksReal(tidy.value)) return false;
    const pair = acceptPair(label, tidy.value);
    if (!pair) return false;
    (candidates[key] = candidates[key] || []).push({ value: tidy.value.slice(0, 500), score: tidy.score, source });
    return true;
  };

  // The value for a label: to its right on the same row, else the nearest fitting line under it. `fits` skips lines that
  // cannot be the answer (a name field skips a garbled line in another script).
  const valueFor = (i, fits) => {
    const ok = (j) => j.n !== i.n && !used.has(j.n) && !labelLike[j.n] && !headerOf[j.n] && !hasPair(j) && looksLikeValue(j.text) && (!fits || fits(j.text));
    const right = its.filter((j) => ok(j) && Math.abs(j.cy - i.cy) < Math.max(i.h, j.h) * 0.6 && j.left >= i.right - i.h * 0.3 && j.left - i.right <= i.h * 8).sort((a, b) => a.left - b.left)[0];
    if (right) return right;
    return its.filter((j) => ok(j) && j.top >= i.bottom - i.h * 0.4 && j.top - i.bottom <= i.h * 4.5 && j.left <= i.right + i.h && j.right >= i.left - i.h).sort((a, b) => a.top - b.top)[0] || null;
  };
  const fitsFor = (label) => { const key = labelToKey(label); return key && KNOWN_KEYS.includes(key) ? (t) => valueFitsKey(key, t) && t.replace(/[^A-Za-z]/g, '').length >= 3 : null; };

  // an address goes on over the next line or two
  const continueAddress = (value, fromItem, startX) => {
    let out = value; let last = fromItem;
    for (let k = 0; k < 2; k++) {
      const more = its.filter((j) => !used.has(j.n) && j.n !== last.n && !labelLike[j.n] && !headerOf[j.n] && !hasPair(j) && looksLikeValue(j.text) && j.top >= last.bottom - last.h * 0.2 && j.top - last.bottom <= last.h * 1.8 && Math.abs(j.left - startX) <= last.h * 2.5).sort((a, b) => a.top - b.top)[0];
      if (!more) break;
      out += `, ${more.text}`; last = more; used.add(more.n);
    }
    return out;
  };

  for (const i of its) {
    if (used.has(i.n)) continue;
    const t = String(i.text);

    // header rows (COV DOI, SEAT NO. CENTRE NO. ...): the values below fill the columns, in order
    if (headerOf[i.n]) {
      const labels = headerOf[i.n].labels;
      const rows = []; let last = i;
      for (let k = 0; k < 8; k++) {
        const next = its.filter((j) => !used.has(j.n) && j.n !== last.n && !labelLike[j.n] && !headerOf[j.n] && !hasPair(j) && j.top >= last.bottom - last.h * 0.2 && j.top - last.bottom <= last.h * 2.2 && j.right >= i.left && j.left <= i.right + i.h).sort((a, b) => a.top - b.top)[0];
        if (!next) break;
        const toks = tokensWithPositions(next.text).filter((x) => !/^[|]+$/.test(x.text));
        if (!toks.length || toks.length > labels.length) break;
        rows.push(toks.map((x) => x.text)); used.add(next.n); last = next;
      }
      labels.forEach((l, col) => {
        const values = rows.map((r) => r[col]).filter(Boolean);
        const joined = [...new Set(values)].join(', ');
        if (joined) put(l.label, joined);
      });
      used.add(i.n);
      continue;
    }

    // "Label: value", possibly several in one box ("DL No:… DOI:…")
    if (hasPair(i)) {
      let any = false;
      for (const p of genericPairs(t)) { if (put(p.label, p.value)) any = true; }
      if (any) used.add(i.n);
      continue;
    }

    // the recipient line of a letter: "To", then the name under it
    if (/^to\s*:?$/i.test(t.trim())) {
      const v = valueFor(i, (x) => /^[A-Za-z][A-Za-z .'-]{2,60}$/.test(x) && x.replace(/[^A-Za-z]/g, '').length >= 3);
      if (v && put('Name', v.text)) used.add(v.n);
      continue;
    }

    // a label with its value in the same box and no colon ("CANDIDATE'S MOTHER'S NAME JAYA")
    if (!labelLike[i.n]) {
      const inline = splitInline(t);
      if (inline && (!FREE_TEXT_LABELS.has(inline.label.toLowerCase()) || shortOrNumeric(inline.value))) { if (put(inline.label, inline.value)) used.add(i.n); }
      continue;
    }

    // a label on its own: its value is beside it or under it
    const label = normalizeLabel(t.replace(/[:：]\s*$/, ''));
    const v = valueFor(i, fitsFor(label));
    if (!v) continue;
    const startX = v.left;
    const value = /address|addr/i.test(label) ? continueAddress(v.text, v, startX) : v.text;
    if (put(label, value)) used.add(v.n);
  }

  // an address given as "Address: …" in one box continues on the next lines too
  for (const i of its) {
    if (!/^(?:address|addr)\b/i.test(normalizeLabel(String(i.text).split(/[:：]/)[0])) || !hasPair(i)) continue;
    const estStart = i.left + ((colonAt(i.text) + 1) / Math.max(1, String(i.text).length)) * (i.right - i.left);
    const extra = continueAddress('', i, estStart).replace(/^, /, '');
    if (extra && candidates.address) candidates.address[0].value = `${candidates.address[0].value.replace(/[.,\s]+$/, '')}, ${extra}`.slice(0, 500);
  }
  return { fields: {}, candidates };
}

// Result, percentage and totals sit in one crowded row on many marksheets; their words are distinctive enough to read from text.
function marksheetSummary(text, into) {
  const t = String(text || '');
  if (!MARKSHEET.test(t)) return {};
  const out = {};
  const result = t.match(/\b(PASS(?:ED)?|FAIL(?:ED)?|ATKT|FIRST CLASS|DISTINCTION)\b/);
  if (result && !into.result) out.result = result[1];
  const pct = t.match(/percentage[^\d\n]{0,30}(\d{2,3}\.\d{1,2})/i) || t.match(/\b(\d{2}\.\d{2})\b(?=[^\n]{0,15}total)/i);
  if (pct && !into.percentage) out.percentage = pct[1];
  const total = t.match(/total\s+marks[^\d\n]{0,6}(\d{3,4})\s+(\d{2,4})\b/i);
  if (total && !into.totalMarks) { const a = Number(total[1]); const b = Number(total[2]); out.totalMarks = `${Math.min(a, b)} / ${Math.max(a, b)}`; }
  return out;
}

// ---- reading the AI's reply ---------------------------------------------------------------------------------------
// Models sometimes return JSON with a stray comma, a cut-off tail or a sentence around it. Strict parsing first; if that
// fails, the pieces that are well formed (label/value pairs, the remove list, title and type) are picked out one by one.
function parseAiJson(reply) {
  const text = String(reply || '');
  const start = text.indexOf('{'); const end = text.lastIndexOf('}');
  if (start !== -1 && end > start) {
    const body = text.slice(start, end + 1);
    for (const attempt of [body, body.replace(/,\s*([}\]])/g, '$1')]) { try { return JSON.parse(attempt); } catch { /* try the next */ } }
  }
  const str = '"((?:[^"\\\\]|\\\\.)*)"';
  const unescape = (v) => v.replace(/\\"/g, '"').replace(/\\n/g, ' ').replace(/\\\\/g, '\\');
  const fields = [];
  for (const m of text.matchAll(new RegExp(`"label"\\s*:\\s*${str}\\s*,\\s*"value"\\s*:\\s*${str}`, 'g'))) fields.push({ label: unescape(m[1]), value: unescape(m[2]) });
  const remove = [];
  const rem = text.match(/"remove"\s*:\s*\[([^\]]*)\]?/);
  if (rem) for (const m of rem[1].matchAll(new RegExp(str, 'g'))) remove.push(unescape(m[1]));
  const pick = (name) => { const m = text.match(new RegExp(`"${name}"\\s*:\\s*${str}`)); return m ? unescape(m[1]) : ''; };
  if (!fields.length && !remove.length && !pick('documentTitle')) return null;
  return { documentType: pick('documentType'), documentTitle: pick('documentTitle'), fields, remove };
}

// ---- optional AI reading (standard accounts only) ---------------------------------------------------------------
const squash = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
// A value is kept only if it is really in the document text, so the AI cannot invent one.
function grounded(value, text) {
  const t = squash(text); const v = squash(value);
  if (!v) return false;
  if (t.includes(v)) return true;
  const digits = String(value).replace(/\D/g, '');
  if (digits.length >= 5 && String(text).replace(/\D/g, '').includes(digits)) return true;
  const words = String(value).toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 1);
  return words.length > 1 && words.filter((w) => t.includes(w)).length / words.length >= 0.8;
}

async function aiPairs(text, aiService, user) {
  if (!aiService?.isConfigured?.() || !text || text.length < 30) return { title: '', pairs: [] };
  const system = `You read OCR text from a personal or official document (identity card, driving licence, marksheet, certificate, bank or insurance paper, vehicle papers, and so on) and list EVERY labelled item printed on it.
Rules: copy labels and values exactly as printed (labels in English). Never guess or invent a value. Skip boilerplate, instructions and long paragraphs. For a table of subjects and marks, give one item per subject (label = the subject, value = the marks). Fix an obvious OCR slip only when the value's own format makes it certain.
Output ONLY one raw JSON object: {"documentTitle": "<short title of the document>", "fields": [{"label": "<label as printed>", "value": "<value as printed>"}]}. At most 60 fields.`;
  try {
    const reply = await aiService.chat(system, `OCR TEXT:\n${text.slice(0, 7000)}\n\nJSON:`, {
      user: { ...(user?.toObject ? user.toObject() : user || {}), securityVersion: 1 },
      operation: aiService.AI_OPERATION.CLASSIFICATION,
    });
    const parsed = parseAiJson(reply);
    if (!parsed) return { title: '', pairs: [] };
    const pairs = (Array.isArray(parsed.fields) ? parsed.fields : [])
      .map((f) => acceptPair(f?.label, f?.value))
      .filter((p) => p && grounded(p.value, text));
    return { title: typeof parsed.documentTitle === 'string' ? parsed.documentTitle.trim().slice(0, 60) : '', pairs };
  } catch (error) {
    console.warn('AI field reading skipped:', error.message);
    return { title: '', pairs: [] };
  }
}

// All the fields for one document: { documentTitle, fields }. `known` are the values the fixed readers already found; they
// are never replaced. With `aiService` the AI reads the text too (standard accounts); without it, the local reader only.
async function extractFields({ text, items = [], known = {}, aiService = null, user = null, typeLabel = '', fileName = '' }) {
  // Every reader proposes values; for each field the best-fitting one is kept. Layout first (most exact), then the AI,
  // then the text reader. A value that fits the field's type beats one that does not, whatever its source.
  const layout = itemFields(items, known).candidates;
  const candidates = {};
  const add = (key, value, source, label) => {
    if (!key || (known[key] && !KNOWN_KEYS.includes(key))) return;
    const tidy = tidyValue(key, label || keyToLabel(key), value);
    if (!tidy) return;
    (candidates[key] = candidates[key] || []).push({ value: tidy.value, score: tidy.score, source });
  };
  for (const [key, list] of Object.entries(layout)) list.forEach((c) => (candidates[key] = candidates[key] || []).push(c));

  let title = '';
  if (aiService) {
    const ai = await aiPairs(text, aiService, user);
    title = !/[<>]/.test(ai.title) && ai.title.replace(/[^A-Za-z]/g, '').length >= 4 && !/^(short|natural|title)\b/i.test(ai.title) ? (/[a-z]/.test(ai.title) ? ai.title : titleCase(ai.title.toLowerCase())) : ''; // a real title, not SHOUTING or a placeholder
    for (const { label, value } of ai.pairs) add(labelToKey(normalizeLabel(label)), value, 'ai', normalizeLabel(label));
  }
  for (const p of genericPairs(text)) add(labelToKey(normalizeLabel(p.label)), p.value, 'text', normalizeLabel(p.label));

  const fields = {};
  for (const [key, list] of Object.entries(candidates)) {
    const order = { layout: 0, ai: 1, text: 2 };
    list.sort((a, b) => b.score - a.score || order[a.source] - order[b.source]);
    fields[key] = list[0].value;
  }
  Object.assign(fields, marksheetSummary(text, { ...known, ...fields }));
  return { documentTitle: title || titleFor(text, typeLabel, fileName), fields: cleanFields(fields) };
}

// ---- the final check before anything is saved -------------------------------------------------------------------
// One shape for every document: keys are letters and digits only (at most 40), values are plain trimmed text (at most
// 500), nothing is empty, a placeholder or a repeat, and the order is stable. This is what the app and the WhatsApp
// assistant both read back, so it must be clean.
function cleanFields(fields) {
  const out = {};
  for (const key of Object.keys(fields).sort()) {
    if (!/^[A-Za-z][A-Za-z0-9]{0,39}$/.test(key) || HIDDEN_KEYS.has(key) || ALIAS_KEYS.has(key) || RESERVED_KEYS.has(key.toLowerCase())) continue;
    const raw = fields[key];
    if (raw === undefined || raw === null || typeof raw === 'object') continue;
    const value = String(raw).replace(/\s+/g, ' ').trim().slice(0, 500);
    if (!value || PLACEHOLDER_VALUE.test(value)) continue;
    out[key] = value;
  }
  // OCR noise sometimes glues a stray prefix onto a real field ("wl7Mathematics" beside "mathematics"): the clean one stays.
  for (const key of Object.keys(out)) {
    const twin = Object.keys(out).find((other) => other !== key && other.length < key.length && key.toLowerCase().endsWith(other.toLowerCase()) && key.length - other.length <= 5 && out[other] === out[key]);
    if (twin) delete out[key];
  }
  return out;
}

// ---- AI review before saving (standard accounts only) -----------------------------------------------------------
// The readers above are fast and careful but still make mistakes OCR makes: a heading read as a label, a value glued to the
// next box, a field under the wrong name. Before anything is saved, the AI looks at the whole record next to the document's
// own text and returns it corrected. It can rename, drop, merge and fix; it cannot invent: every value it returns must be
// found in the document's text (a date or a name may be reformatted), or it is discarded.
// Encrypted (Security V2) accounts never use this: their document text is not sent to a cloud service.
const DOC_TYPES = new Set(['aadhaar', 'pan', 'passport', 'license', 'voter', 'marksheet', 'certificate', 'bank', 'vehicle', 'insurance', 'other']);

async function reviewWithAI({ text, record, aiService, user }) {
  const unchanged = { record, reviewed: false };
  if (!aiService?.isConfigured?.() || !text || text.length < 30 || user?.securityVersion === 2) return unchanged;
  // The address pieces (zip, city, address lines...) are derived from the address for form filling: the AI does not see or change them.
  const PROTECTED = (k) => ALIAS_KEYS.has(k) || k === 'city';
  const current = Object.entries(record).filter(([k, v]) => !HIDDEN_KEYS.has(k) && !PROTECTED(k) && k !== 'documentType' && typeof v === 'string').map(([k, v]) => ({ label: labelOf(k), value: v }));
  const system = `You check structured data that was read from a personal or official document by OCR, and return it corrected and well structured.
You get the document's OCR text and the CURRENT FIELDS (label and value). Fix the record:
- Remove fields that are not real details of the document: headings, boilerplate, instructions, torn OCR fragments, a label with no real value, placeholders such as XXXX or <NAME>.
- Fix labels to the plain English label the document uses (for example "Class of Vehicle", "Date of Issue", "Seat No").
- Fix a value only when the OCR text proves the correct one (a glued extra word, a misread character that the text elsewhere shows correctly). Never guess and never add information that is not in the text.
- Merge duplicates (same fact under two labels) into one.
- Add a field only if the text clearly prints it with its label and it is missing.
- Dates as DD/MM/YYYY. People's names in Title Case. Numbers, codes and addresses exactly as printed. Marks as "obtained / maximum".
- documentType is one of: ${[...DOC_TYPES].join(', ')}. documentTitle is a short natural title like "Driving Licence" or "SSC Statement of Marks".
Output ONLY one raw JSON object: {"documentType": "<one type from the list>", "documentTitle": "<short natural title>", "fields": [{"label": "<corrected label>", "value": "<corrected value>"}], "remove": ["<label of a field to delete>"]}.
"fields" lists the corrected or added fields; fields you leave out of both lists stay as they are.`;
  let parsed;
  try {
    const reply = await Promise.race([
      aiService.chat(system, `OCR TEXT:\n${text.slice(0, 7000)}\n\nCURRENT FIELDS:\n${JSON.stringify(current)}\n\nJSON:`, {
        user: { ...(user?.toObject ? user.toObject() : user || {}), securityVersion: 1 },
        operation: aiService.AI_OPERATION.CLASSIFICATION,
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timed out')), 60000)),
    ]);
    parsed = parseAiJson(reply);
    if (!parsed) return unchanged;
  } catch (error) {
    console.warn('AI review skipped:', error.message);
    return unchanged;
  }

  const out = { ...record };
  const stats = { removed: 0, corrected: 0, added: 0, rejected: 0 };
  const keyFor = (name) => {
    const wanted = String(name || '').trim().toLowerCase();
    if (!wanted) return null;
    const viaLabel = labelToKey(normalizeLabel(name));
    return Object.keys(out).find((k) => k.toLowerCase() === wanted || labelOf(k).toLowerCase() === wanted || k === viaLabel) || null;
  };

  // removals: a usual field is only removed when its value really is junk; the AI cannot delete a good name or number
  const removals = (Array.isArray(parsed.remove) ? parsed.remove : []).slice(0, 40);
  for (const name of removals) {
    const key = keyFor(name);
    if (!key || HIDDEN_KEYS.has(key) || PROTECTED(key) || key === 'documentType') continue;
    if (KNOWN_KEYS.includes(key) && valueFitsKey(key, out[key]) && !PLACEHOLDER_VALUE.test(out[key])) { stats.rejected += 1; continue; }
    delete out[key]; stats.removed += 1;
  }

  // corrections and additions: each value has to be in the document's text and fit its field
  for (const f of (Array.isArray(parsed.fields) ? parsed.fields : []).slice(0, 80)) {
    const label = normalizeLabel(f?.label);
    const key = label ? labelToKey(label) : null;
    if (!key || HIDDEN_KEYS.has(key) || PROTECTED(key) || key === 'documentType' || !label || !labelLooksReal(label) || PLACE_NAMES.has(compactLetters(label))) { stats.rejected += 1; continue; }
    const tidy = tidyValue(key, label, f.value);
    if (!tidy || !valueLooksReal(tidy.value) || !(grounded(tidy.value, text) || grounded(f.value, text))) { stats.rejected += 1; continue; }
    if (KNOWN_KEYS.includes(key) && !valueFitsKey(key, tidy.value)) { stats.rejected += 1; continue; }
    const before = out[key];
    if (before === undefined) { out[key] = tidy.value; stats.added += 1; continue; }
    if (before === tidy.value) continue;
    // a changed value is accepted when it fits its field at least as well as the old one
    const old = tidyValue(key, label, before);
    if (!old || tidy.score >= old.score) { out[key] = tidy.value; stats.corrected += 1; } else stats.rejected += 1;
  }

  const type = String(parsed.documentType || '').toLowerCase();
  if (DOC_TYPES.has(type) && (!out.documentType || out.documentType === 'other')) out.documentType = type;
  const title = String(parsed.documentTitle || '').replace(/\s+/g, ' ').trim();
  const titleOk = title && !/[<>]/.test(title) && title.replace(/[^A-Za-z]/g, '').length >= 4 && title.length <= 80 && title.split(' ').length <= 9 && title.split(' ').every(wordLooksReal) && !/^(short|natural|title|document title)\b/i.test(title);
  const known = {}; const extra = {};
  for (const [k, v] of Object.entries(out)) { if (k === 'documentType' || KNOWN_KEYS.includes(k)) known[k] = v; else if (!HIDDEN_KEYS.has(k)) extra[k] = v; }
  const record2 = assembleStructured({ known, fields: extra, documentTitle: titleOk ? (/[a-z]/.test(title) ? title : titleCase(title.toLowerCase())) : (record.documentTitle || '') });
  console.log(`[ocr] AI review: ${stats.corrected} corrected, ${stats.added} added, ${stats.removed} removed, ${stats.rejected} suggestions rejected`);
  return { record: record2, reviewed: true, stats };
}

// ---- a local search of the document's own text -------------------------------------------------------------------
// When no stored field answers a question, the label the question names ("seat number", "enrolment no") is looked for in the
// raw text, even in the middle of a line, and the value printed after it is returned. No AI involved.
function findInText(question, text) {
  const qTokens = [...new Set(tokens(question))];
  if (!qTokens.length || !text) return [];
  const lines = String(text).split(/\r?\n/);
  const found = [];
  for (const phrase of VOCAB_SORTED) {
    const pt = [...new Set(tokens(phrase))];
    if (!pt.length || !pt.some((t) => !GENERIC_TOKENS.has(t)) || !pt.every((t) => qTokens.some((q) => sameToken(q, t)))) continue;
    const words = phrase.split(/\s+/).map((w) => w.replace(/[^a-z0-9]/gi, '')).filter(Boolean);
    const numeric = /\b(no|number|id)$/i.test(phrase);
    if (!numeric) continue; // only number-type labels: free text after a label in raw text is too easily a legend or a heading
    const value = numeric ? '([A-Za-z]{0,2}\\d[\\d/.\\-]*(?:[A-Za-z]\\d[\\d/.\\-]*)*)' : '([A-Za-z0-9][A-Za-z0-9/.\\-]*(?:\\s[A-Za-z0-9/.\\-]+){0,2})';
    const re = new RegExp(`${words.join('[\\s.\\-]*')}[\\s:.\\-–]*${value}`, 'i');
    for (const line of lines) {
      const m = line.match(re);
      if (!m) continue;
      const label = titleCase(phrase);
      const key = labelToKey(label);
      const tidy = key ? tidyValue(key, label, m[1].split(/\s{2,}/)[0]) : null;
      if (tidy && valueLooksReal(tidy.value) && !VOCAB_SORTED.includes(tidy.value.toLowerCase()) && (!numeric || /\d/.test(tidy.value))) { found.push({ key, label: labelOf(key), value: tidy.value, score: pt.length }); break; }
    }
  }
  // the most specific label wins ("seat no" over "no")
  found.sort((a, b) => b.score - a.score);
  return found.slice(0, 1);
}

// ---- finding the fields a question asks about -------------------------------------------------------------------
const STOP = new Set(('what whats is are was were my mine me the a an of on in at from to for and or please can could you do does did i have has get got give gave send show tell ' +
  'when where who whom whose why does did will shall would see know want need let which that this these those it its how about also any all with as by be been being there their them your yours our us just only exact exactly kindly pls plz details detail info information data value values field fields').split(' '));
const SYNONYM = {
  dob: ['date', 'birth'], birthday: ['date', 'birth'], birthdate: ['date', 'birth'],
  license: ['licence'], licence: ['licence'], dl: ['licence'], licences: ['licence'],
  aadhar: ['aadhaar'], aadhaar: ['aadhaar'], adhar: ['aadhaar'], uid: ['aadhaar'],
  mobile: ['phone'], cell: ['phone'], telephone: ['phone'], contact: ['phone'], tel: ['phone'],
  validity: ['valid'], expiry: ['valid'], expires: ['valid'], expire: ['valid'], expiration: ['valid'], upto: ['valid'], till: ['valid'], valid: ['valid'],
  issued: ['issue'], issue: ['issue'], doi: ['issue'], issuance: ['issue'],
  number: ['no'], num: ['no'], nbr: ['no'], no: ['no'], id: ['no'], '#': ['no'],
  type: ['class'], category: ['class'], kind: ['class'], cov: ['class', 'vehicle'], class: ['class'],
  marks: ['marks'], mark: ['marks'], score: ['marks'], scored: ['marks'], obtained: ['marks'], percent: ['percentage'], percentage: ['percentage'], pct: ['percentage'],
  seat: ['seat'], roll: ['roll'], enrollment: ['enrolment'], enrolment: ['enrolment'], registration: ['registration'], reg: ['registration'],
  college: ['college'], university: ['university'], school: ['school'], board: ['board'],
  bloodgroup: ['blood', 'group'], blood: ['blood'], group: ['group'],
  pincode: ['pin'], zip: ['pin'], postal: ['pin'], pin: ['pin'],
  addr: ['address'], residence: ['address'], mother: ['mother'], mothers: ['mother'], fathers: ['father'], father: ['father'],
  acc: ['account'], account: ['account'], ac: ['account'], ifsc: ['ifsc'], bank: ['bank'], branch: ['branch'],
  vehicle: ['vehicle'], vehicles: ['vehicle'], car: ['vehicle'], bike: ['vehicle'],
  maths: ['mathematics'], math: ['mathematics'], issuing: ['issue'], issuer: ['issue'], rto: ['authority'], authority: ['authority'], sci: ['science'],
  grade: ['grade'], result: ['result'], cgpa: ['cgpa'], division: ['division'], year: ['year'], passing: ['passing'],
};
const GENERIC_TOKENS = new Set(['no', 'name', 'date', 'of', 'class']);

function tokens(text) {
  const out = [];
  for (const raw of String(text || '').toLowerCase().replace(/[^a-z0-9#]+/g, ' ').split(' ')) {
    if (!raw || STOP.has(raw)) continue;
    const base = raw.length > 3 && raw.endsWith('s') && !SYNONYM[raw] ? raw.slice(0, -1) : raw;
    out.push(...(SYNONYM[raw] || SYNONYM[base] || [base]));
  }
  return out;
}

const edit1 = (a, b) => {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1 || a.length < 5) return false;
  let i = 0; let j = 0; let diff = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++diff > 1) return false;
    if (a.length > b.length) i++; else if (a.length < b.length) j++; else { i++; j++; }
  }
  return diff + (a.length - i) + (b.length - j) <= 1;
};
const sameToken = (a, b) => a === b || edit1(a, b);

// How well one field's label answers a question (0 to 1). The label's words must be covered by the question.
function scoreLabel(qTokens, label, qRaw = []) {
  const l = [...new Set(tokens(label))];
  if (!l.length || !qTokens.length) return 0;
  const used = new Set();
  let matched = 0; let strong = 0;
  for (const lt of l) {
    const at = qTokens.findIndex((qt, i) => !used.has(i) && sameToken(qt, lt));
    if (at !== -1) { used.add(at); matched += 1; if (!GENERIC_TOKENS.has(lt)) strong += 1; }
  }
  if (!matched || !strong) return 0; // only "number"/"name"-style words matched: not enough
  const coverage = matched / l.length;
  const precision = used.size / qTokens.length;
  // The question's own word appearing in the label unchanged ("science" in Science & Technology) beats a stemmed match ("Sciences").
  const exact = qRaw.length && String(label).toLowerCase().split(/[^a-z0-9]+/).some((w) => w.length > 3 && qRaw.includes(w)) ? 0.08 : 0;
  return 0.7 * coverage + 0.3 * precision + exact;
}

const NUMBERISH = /\b(licen[cs]e|aadhaa?r|pan|passport|account|a\/c|voter|epic|policy|card|enrol\w*|registration|chassis|engine|cif|customer|prn)\b/i;
// Numbers that identify a person are masked until the member confirms their PIN.
function isSensitive(key, label, value) {
  if (['aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber'].includes(key)) return true;
  const v = String(value || '');
  if (/^\d{4}\s?\d{4}\s?\d{4}$/.test(v.trim()) || /^[A-Z]{5}\d{4}[A-Z]$/.test(v.trim())) return true;
  return NUMBERISH.test(label) && /\b(no|number|id|num)\b/i.test(label) && v.replace(/[^A-Za-z0-9]/g, '').length >= 6;
}
const maskValue = (value) => `****${String(value).replace(/\s/g, '').slice(-4)}`;

// docs: [{ name, title, type, fields: { key: value } }]. Returns the fields the question asks for, best first.
// A question that names a document ("on my driving licence") is answered from that document.
function searchFields(question, docs) {
  const parts = String(question || '').split(/\s*(?:,|&|\band\b|\balso\b|\bplus\b|\+)\s*/i).map((p) => p.trim()).filter(Boolean);
  const queries = parts.length ? parts : [String(question || '')];
  const results = [];
  const seen = new Set();

  for (const part of queries) {
    const qTokens = tokens(part);
    if (!qTokens.length) continue;
    const qRaw = part.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 3 && !STOP.has(w));

    // Does this part name one of the documents? ("licence" -> the licence, "marksheet" -> the marksheet)
    const named = docs.filter((d) => {
      const docTokens = tokens(`${d.title || ''} ${d.name || ''} ${d.type || ''}`);
      return docTokens.some((dt) => !GENERIC_TOKENS.has(dt) && qTokens.some((qt) => sameToken(qt, dt)));
    });

    const scan = (pool, drop = false) => {
      const hits = [];
      for (const doc of pool) {
        // The document's own name in the question ("expire on my licence") says where to look, not what to look for.
        let qt = qTokens;
        if (drop) {
          const docTokens = tokens(`${doc.title || ''} ${doc.name || ''} ${doc.type || ''}`);
          const rest = qTokens.filter((t) => GENERIC_TOKENS.has(t) || !docTokens.some((dt) => sameToken(t, dt)));
          if (rest.some((t) => !GENERIC_TOKENS.has(t))) qt = rest;
        }
        for (const [key, value] of Object.entries(doc.fields || {})) {
          if (HIDDEN_KEYS.has(key) || ALIAS_KEYS.has(key) || value === undefined || value === null || String(value).trim() === '') continue;
          const label = labelOf(key);
          const score = scoreLabel(qt, label, qRaw);
          if (score <= 0) continue;
          // a typed value (a percentage, a date) saved with stray text after it is shown as just the figure
          const tidy = tidyValue(key, label, String(value));
          if (tidy) hits.push({ doc, key, label, value: tidy.value, score });
        }
      }
      return hits;
    };

    // The part may be only a document name ("my licence"): nothing field-like left once the document words are removed.
    let hits = scan(named.length ? named : docs, named.length > 0);
    if (!hits.length && named.length) hits = scan(docs);
    if (!hits.length) continue;
    const best = Math.max(...hits.map((h) => h.score));
    if (best < 0.55) continue;
    for (const h of hits.filter((x) => x.score >= Math.max(0.55, best * 0.92)).sort((a, b) => b.score - a.score)) {
      const id = `${h.doc.name}|${h.key}`;
      if (seen.has(id)) continue;
      seen.add(id);
      results.push(h);
    }
  }
  // The same value found in several documents is shown once.
  const byValue = new Set();
  return results.filter((h) => { const id = `${h.doc.name}|${squash(h.value)}`; if (byValue.has(id)) return false; byValue.add(id); return true; });
}

// WhatsApp text for the matches: just the asked values. When they come from different documents each group is named.
function formatMatches(matches, { reveal = false } = {}) {
  const docsInvolved = [...new Set(matches.map((m) => m.doc.name))];
  const line = (m) => `*${m.label}*: ${!reveal && isSensitive(m.key, m.label, m.value) ? maskValue(m.value) : m.value}`;
  const masked = !reveal && matches.some((m) => isSensitive(m.key, m.label, m.value));
  const body = docsInvolved.length > 1
    ? docsInvolved.map((name) => { const own = matches.filter((m) => m.doc.name === name); return `_${own[0].doc.title || name}_\n${own.map(line).join('\n')}`; }).join('\n\n')
    : matches.map(line).join('\n');
  return masked ? `${body}\n\nThe number is masked. Say *full* to see it (I will ask for your PIN).` : body;
}

// Labels only (never values) go to the AI, so it can say which fields a differently-worded question means. Standard
// accounts only. Returns [{ doc, key }] picked from the real fields.
async function pickFieldsWithAI(question, docs, aiService, user) {
  if (!aiService?.isConfigured?.()) return [];
  const menu = docs.map((d, i) => `[${i}] ${d.title || d.name}: ${Object.keys(d.fields || {}).filter((k) => !HIDDEN_KEYS.has(k) && d.fields[k]).map(labelOf).join(' | ')}`).join('\n');
  if (!menu.trim()) return [];
  const system = 'You match a question to the document fields it asks for. Reply with ONLY raw JSON: {"matches":[{"doc":number,"label":"exact label from the list"}]}. Choose only fields that directly answer the question. If none do, return {"matches":[]}.';
  try {
    const reply = await aiService.chat(system, `FIELDS:\n${menu}\n\nQUESTION: ${String(question).slice(0, 300)}\n\nJSON:`, {
      user: { ...(user?.toObject ? user.toObject() : user || {}), securityVersion: 1 },
      operation: aiService.AI_OPERATION.CLASSIFICATION,
    });
    const start = reply.indexOf('{'); const end = reply.lastIndexOf('}');
    if (start === -1 || end <= start) return [];
    const picked = [];
    for (const m of (JSON.parse(reply.slice(start, end + 1)).matches || []).slice(0, 6)) {
      const doc = docs[Number(m.doc)];
      const key = doc && Object.keys(doc.fields || {}).find((k) => labelOf(k).toLowerCase() === String(m.label).toLowerCase());
      if (doc && key && doc.fields[key]) picked.push({ doc, key, label: labelOf(key), value: String(doc.fields[key]), score: 1 });
    }
    return picked;
  } catch (error) {
    console.warn('AI field matching skipped:', error.message);
    return [];
  }
}

// Everything that gets saved for a document, in one shape: the usual fields (already validated by the OCR reader) first,
// then whatever else the document prints, then the title. Nothing outside this shape is stored.
function assembleStructured({ known = {}, fields = {}, documentTitle = '' }) {
  const out = {};
  const keep = (key, value) => { if (value !== undefined && value !== null && String(value).trim() !== '' && typeof value !== 'object') out[key] = typeof value === 'string' ? value.trim() : value; };
  if (known.documentType) keep('documentType', known.documentType);
  for (const key of KNOWN_KEYS) {
    const a = known[key]; const b = fields[key];
    // the same value read more completely ("42 MODEL COLONY, PUNE." vs "... PUNE, MAHARASHTRA 411016") replaces the shorter one
    const v = typeof a === 'string' && typeof b === 'string' && b.length > a.length && squash(b).includes(squash(a)) ? b : (a ?? b);
    if (typeof v === 'string' && (PLACEHOLDER_VALUE.test(v) || !valueFitsKey(key, v))) { if (typeof b === 'string' && b !== v && !PLACEHOLDER_VALUE.test(b) && valueFitsKey(key, b)) keep(key, b); continue; }
    keep(key, v);
  }
  // address pieces the address parser derived (city, ...) stay with the known values; they are not "document fields"
  for (const [key, value] of Object.entries(known)) { if (!(key in out) && !KNOWN_KEYS.includes(key) && !HIDDEN_KEYS.has(key) && key !== 'documentType' && !PLACEHOLDER_VALUE.test(String(value))) keep(key, value); }
  const extra = cleanFields(Object.fromEntries(Object.entries(fields).filter(([k]) => !KNOWN_KEYS.includes(k) && !(k in out))));
  for (const [key, value] of Object.entries(extra)) keep(key, value);
  if (documentTitle) keep('documentTitle', String(documentTitle).slice(0, 80));
  return out;
}

// Cleans a record that was saved by an older version without ever throwing good data away: every usual field stays, a dynamic field
// stays only if it passes today's rules (a real label, a value that fits it), typed values are tidied, and fields the fresh reading
// found that the old record lacks are added. `fresh` is a new reading of the same document.
function repairRecord(old, fresh = {}) {
  const out = {};
  const notes = { removed: [], tidied: [], added: [], replaced: [] };
  for (const [key, value] of Object.entries(old || {})) {
    if (typeof value !== 'string') continue;
    if (key === 'documentTitle') continue;
    if (key === 'documentType' || KNOWN_KEYS.includes(key) || ALIAS_KEYS.has(key) || key === 'city' || HIDDEN_KEYS.has(key)) { out[key] = value; continue; }
    const label = keyToLabel(key);
    const tidy = labelLooksReal(label) && !PLACE_NAMES.has(compactLetters(label)) ? tidyValue(key, label, value) : null;
    if (!tidy || !valueLooksReal(tidy.value)) { notes.removed.push(key); continue; }
    if (tidy.value !== value) notes.tidied.push(key);
    out[key] = tidy.value;
  }
  for (const key of KNOWN_KEYS) if (typeof out[key] === 'string' && (PLACEHOLDER_VALUE.test(out[key]) || !valueFitsKey(key, out[key]))) { notes.removed.push(key); delete out[key]; }
  for (const [key, value] of Object.entries(fresh)) {
    if (key === 'documentTitle' || key === 'documentType' || typeof value !== 'string') continue;
    if (!(key in out)) { out[key] = value; notes.added.push(key); continue; }
    // an identifier saved without any digit ("****STER" for an enrolment number) is replaced by a reading that has one
    if (!KNOWN_KEYS.includes(key) && /\b(no|number|id)$/i.test(keyToLabel(key)) && !/\d/.test(out[key]) && /\d/.test(value)) { out[key] = value; notes.replaced.push(key); }
  }
  if (!out.documentType && fresh.documentType) out.documentType = fresh.documentType;
  return { record: cleanFields_keepKnown(out), notes };
}

// cleanFields drops the usual keys' special handling, so the repair keeps them as they are and only tidies the rest.
function cleanFields_keepKnown(record) {
  const known = {}; const rest = {};
  for (const [k, v] of Object.entries(record)) { if (k === 'documentType' || KNOWN_KEYS.includes(k) || ALIAS_KEYS.has(k) || k === 'city') known[k] = v; else if (!HIDDEN_KEYS.has(k)) rest[k] = v; }
  return { ...known, ...cleanFields(rest) };
}

module.exports = {
  repairRecord, findInText, parseAiJson, reviewWithAI, assembleStructured, wordsToNumber, unglue, itemFields, marksheetSummary, cleanFields, tidyValue, normalizeLabel, KNOWN_KEYS, HIDDEN_KEYS, ALIAS_KEYS, labelToKey, keyToLabel, labelOf, genericFields, genericPairs, titleFor, extractFields,
  searchFields, formatMatches, pickFieldsWithAI, isSensitive, maskValue, tokens, scoreLabel,
};
