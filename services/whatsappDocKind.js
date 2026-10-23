// What kind of document was just uploaded, in the words a member uses: guessed from what was read, confirmed with the
// member in the chat, and corrected when they say it is something else.

const KINDS = {
  aadhaar: { label: 'Aadhaar card', words: /aadhaa?r|aadhar|adhar|\buid\b/i },
  pan: { label: 'PAN card', words: /\bpan\b|permanent account/i },
  passport: { label: 'Passport', words: /passport/i },
  license: { label: 'Driving licence', words: /licen[cs]e|\bdl\b|driving/i },
  voter: { label: 'Voter ID card', words: /voter|\bepic\b|election card|electors?\b/i },
  vehicle: { label: 'Vehicle registration (RC)', words: /\brc\b|registration certificate|certificate of registration|rc book|vehicle/i },
  marksheet: { label: 'Marksheet', words: /mark\s*-?sheet|statement of marks|grade ?card|report card|result|\b(?:10th|12th|ssc|hsc|cbse|icse)\b/i },
  marriage: { label: 'Marriage certificate', words: /marriage|wedding/i },
  birth: { label: 'Birth certificate', words: /birth certificate/i },
  certificate: { label: 'Certificate', words: /certificate|diploma|degree/i },
  bank: { label: 'Bank document', words: /pass\s*book|bank|cheque|statement of account/i },
  insurance: { label: 'Insurance document', words: /insurance|policy/i },
};
// The order matters: "registration certificate" is a vehicle paper, not just a certificate.
const ORDER = ['passport', 'aadhaar', 'pan', 'license', 'voter', 'vehicle', 'marksheet', 'bank', 'insurance', 'marriage', 'birth', 'certificate'];

const kindOf = (key, labelOverride) => (KINDS[key] ? { key, label: labelOverride || KINDS[key].label } : null);

// A kind from words the member typed ("it is my pan", "marksheet", "driving license"). Null when no known kind is named.
function kindFromText(text) {
  const t = String(text || '').replace(/[_-]+/g, ' '); // file names: my_rc_book -> my rc book
  const key = ORDER.find((k) => KINDS[k].words.test(t));
  return key ? kindOf(key) : null;
}

// ---- recognising a document from its OCR text -----------------------------------------------------------------------
// Each kind has phrases that appear on that document and almost nowhere else. The text is scored against all of them; the
// kind with the clearly highest score wins. Weights: 3 = names the document itself, 2 = printed on it, 1 = hints.
const SIGNS = {
  aadhaar: [[3, /unique identification authority/i], [3, /\buidai\b/i], [3, /aadhaa?r|aadhar/i], [2, /\bVID\s*:?\s*\d/i], [2, /enrol(?:l)?ment no/i], [2, /आधार/], [1, /proof of identity,? not of citizenship/i], [1, /\b[2-9]\d{3}\s\d{4}\s\d{4}\b/]],
  pan: [[3, /income tax department/i], [3, /permanent account number/i], [2, /\b[A-Z]{5}\d{4}[A-Z]\b/], [1, /father'?s name/i], [1, /आयकर/]],
  passport: [[3, /\bpassport\b/i], [3, /\bP<IND/], [2, /republic of india/i], [2, /place of (?:birth|issue)/i], [1, /nationality/i], [1, /date of expiry/i]],
  license: [[3, /driving licen[cs]e/i], [3, /motor driving/i], [2, /\bDL\s*(?:no|number)\b/i], [2, /\bcov\b|class of vehicle|authori[sz]ation to drive/i], [1, /valid till|validity/i], [1, /blood group/i], [1, /\bform\s*7\b/i]],
  voter: [[3, /election commission/i], [3, /elector'?s? (?:photo )?identity|electors? name|\bepic\b/i], [2, /assembly constituency|electoral registration/i], [1, /voter/i]],
  vehicle: [[3, /certificate of registration|registration certificate/i], [3, /chassis no|engine no/i], [2, /regn\.? ?(?:no|date)|registration (?:no|date)/i], [2, /fuel type|seating capacity|manufactur/i], [1, /owner'?s? name/i]],
  marksheet: [[3, /statement of marks|mark\s*-?sheet|grade ?card|report card/i], [2, /seat\s*no/i], [2, /total marks|marks obtained|percentage/i], [2, /subject (?:code|name)/i], [1, /examination|board of (?:secondary )?education/i], [1, /\b(?:result|grade|division)\b/i]],
  bank: [[3, /pass\s*book|statement of account/i], [2, /\bifsc\b/i], [2, /account (?:no|number)|a\/c no/i], [1, /\bbranch\b|\bbank\b/i], [1, /\bcheque\b|balance/i]],
  insurance: [[3, /insurance/i], [2, /policy (?:no|number)/i], [2, /sum assured|premium/i], [1, /nominee|insured/i]],
  marriage: [[3, /marriage/i], [2, /bride(?:groom)?|priest|kazi|solemni[sz]ed/i], [1, /certif/i]],
  birth: [[3, /birth certificate|certificate of birth/i], [2, /registrar of (?:births|births and deaths)/i], [1, /place of birth|name of (?:the )?child/i]],
  certificate: [[3, /this is to certify/i], [2, /\bcertificate\b/i], [2, /\b(?:degree|diploma)\b/i], [1, /university|college|institute/i]],
};

// The kind the text most clearly belongs to, or null when no kind stands out (a blank or unfamiliar document).
function kindFromOcrText(text) {
  const t = String(text || '');
  if (t.length < 15) return null;
  const scores = Object.entries(SIGNS).map(([key, signs]) => [key, signs.reduce((sum, [weight, re]) => sum + (re.test(t) ? weight : 0), 0)]).sort((x, y) => y[1] - x[1]);
  const [best, second] = scores;
  // The winner needs real evidence (not one stray word) and a clear lead over the runner-up.
  if (!best || best[1] < 3 || best[1] - (second ? second[1] : 0) < 2) return null;
  return kindOf(best[0]);
}

// The guess for a document that was just read. The OCR text decides; the reader's own type and the printed title back it up
// when the text alone is not clear enough.
function guessKind({ documentType, documentTitle, text }) {
  const fromText = kindFromOcrText(text);
  if (fromText) return fromText;
  if (documentType && KINDS[documentType]) return kindOf(documentType);
  return kindFromText(documentTitle);
}

const EXAMPLES = 'Aadhaar card, PAN card, driving licence, marksheet';

const confirmQuestion = (kind) => (kind
  ? `That looks like your *${kind.label}*. Is that correct? Reply *yes*, or tell me what it is (for example ${EXAMPLES}).`
  : `I could not tell what kind of document this is. What is it? (for example ${EXAMPLES})`);

const YES = /^\s*(?:yes|y|yep|yeah|yup|correct|right|ok|okay|sure|haan|ha|sahi|that'?s (?:right|correct)|it is|yes it is|yes correct)\s*[.!]*\s*$/i;
const NO = /^\s*(?:no|n|nope|nah|wrong|not correct|incorrect|galat|not right|that'?s wrong)\s*[.!]*\s*$/i;

// A free-text name for a document type we have no word for ("electricity bill"): short, letters only.
function customLabel(text) {
  if (/[?]|^\s*(?:what|how|when|where|who|why|can|could|please|show|send|tell|give|is|are|do|does)\b/i.test(String(text || ''))) return null; // a question or request, not a name
  const t = String(text || '').trim().replace(/^(?:it(?:'s| is)|this is|that is|its|a|an|my)\s+/i, '').replace(/[.!?]+$/, '');
  if (!/^[A-Za-z][A-Za-z &'-]{2,38}$/.test(t) || t.split(/\s+/).length > 5) return null;
  return t.toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
}

module.exports = { KINDS, kindOf, kindFromText, kindFromOcrText, guessKind, confirmQuestion, customLabel, YES, NO, EXAMPLES };
