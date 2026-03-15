// ============================================================
// services/mlService.js — Naive Bayes ML Classifier
// This replaces pure keyword matching with a trained ML model.
// Uses the 'natural' npm library for Naive Bayes classification.
// Your report mentions ML — this delivers it properly.
// ============================================================
const natural = require('natural');

const classifier = new natural.BayesClassifier();
let trained = false;

// ── Training data ─────────────────────────────────────────────
// Phishing examples (label: 'phishing')
const PHISHING_SAMPLES = [
  'verify your account immediately click here your account suspended',
  'congratulations you won million dollars claim prize now urgent',
  'update payment information bank account details required immediately',
  'security alert unusual login activity confirm identity reset password',
  'nigerian prince wire transfer million dollars bank account details',
  'your account will be closed verify credentials login attempt detected',
  'free gift claim your prize limited time offer act now urgent action',
  'paypal account suspended update payment method confirm your identity',
  'dear customer your account has been compromised click here immediately',
  'IRS tax refund pending verify social security number bank details',
  'amazon order suspended verify account payment update required urgent',
  'microsoft windows virus detected call support number immediately',
  'your credit card declined update billing information click here now',
  'lottery winner notification claim your prize send bank account number',
  'CEO message urgent wire transfer confidential do not tell anyone',
  'your password expires today reset now or lose access immediately',
  'suspicious activity detected on your account verify now or be locked',
  'HSBC security alert please verify your online banking credentials',
  'DHL package delivery failed provide payment click link confirm address',
  'Netflix account suspended update payment information renew subscription'
];

// Safe email examples (label: 'safe')
const SAFE_SAMPLES = [
  'meeting tomorrow at 10am please confirm your attendance team sync',
  'project update quarterly report attached please review feedback',
  'invoice attached for services rendered payment due next month',
  'happy birthday celebration dinner friday evening family gathering',
  'newsletter monthly digest latest news articles company updates',
  'job application thank you interview scheduled next week position',
  'flight confirmation booking reference departure gate information',
  'recipe ideas for dinner party weekend cooking suggestions',
  'university lecture notes study materials exam preparation schedule',
  'gym class schedule yoga pilates swimming pool timetable booking',
  'annual leave request holiday approval team calendar availability',
  'project proposal deadline submission requirements stakeholder review',
  'customer feedback positive review product service satisfaction',
  'training workshop registration confirmation venue details agenda',
  'photography portfolio creative work exhibition gallery showcase',
  'book club meeting reading list discussion questions next chapter',
  'dental appointment reminder checkup thursday morning reception',
  'software update release notes new features bug fixes changelog',
  'conference call agenda participants dial in details recording',
  'team lunch reservation restaurant booking friday afternoon casual'
];

function trainModel() {
  if (trained) return;
  PHISHING_SAMPLES.forEach(text => classifier.addDocument(text, 'phishing'));
  SAFE_SAMPLES.forEach(text => classifier.addDocument(text, 'safe'));
  classifier.train();
  trained = true;
}

// ── ML classification ─────────────────────────────────────────
// Returns { label: 'phishing'|'safe', confidence: 0-1 }
function classifyText(text) {
  trainModel();
  const cleaned = (text || '').toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (!cleaned || cleaned.length < 10) {
    return { label: 'safe', confidence: 0.5 };
  }

  const label      = classifier.classify(cleaned);
  const scores     = classifier.getClassifications(cleaned);
  const phishScore = scores.find(s => s.label === 'phishing')?.value || 0;
  const safeScore  = scores.find(s => s.label === 'safe')?.value || 0;
  const total      = Math.abs(phishScore) + Math.abs(safeScore) || 1;
  const confidence = Math.min(0.99, Math.abs(phishScore) / total);

  return { label, confidence: parseFloat(confidence.toFixed(3)) };
}

// ── NLP feature extraction ────────────────────────────────────
// Extracts meaningful features from email text for analysis
function extractNLPFeatures(text) {
  const tokenizer = new natural.WordTokenizer();
  const tokens    = tokenizer.tokenize((text || '').toLowerCase());
  const stemmer   = natural.PorterStemmer;

  const stemmed = tokens.map(t => stemmer.stem(t));
  const urgencyStems = ['urgent', 'immedi', 'verifi', 'confirm', 'suspend',
                        'click', 'login', 'account', 'password', 'secur'].map(w => stemmer.stem(w));

  const urgencyCount = stemmed.filter(s => urgencyStems.includes(s)).length;
  const uniqueTokens = new Set(tokens).size;
  const repetition   = tokens.length > 0 ? (tokens.length - uniqueTokens) / tokens.length : 0;

  return {
    tokenCount:    tokens.length,
    uniqueTokens,
    repetitionRate: parseFloat(repetition.toFixed(3)),
    urgencyCount,
    hasUrgencyLanguage: urgencyCount > 2
  };
}

module.exports = { classifyText, extractNLPFeatures, trainModel };
