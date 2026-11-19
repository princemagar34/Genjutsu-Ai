// ============================================================
// services/groqModel.js — which Groq model Genjutsu uses
// ------------------------------------------------------------
// Groq shut down llama-3.3-70b-versatile on 16 Aug 2026; its
// recommended replacement is openai/gpt-oss-120b. Change model
// later with GROQ_MODEL in .env — no code changes needed.
//
// gpt-oss models "think" before answering and that thinking counts
// toward the token limit, so we ask for low reasoning effort, hide the
// reasoning from the response, and allow a bigger completion budget.
// ============================================================
const DEFAULT_MODEL = 'openai/gpt-oss-120b';

function groqRequestOptions({ answerTokens, temperature }) {
  const model = process.env.GROQ_MODEL || DEFAULT_MODEL;
  const body  = { model, temperature };
  if (model.startsWith('openai/gpt-oss')) {
    body.reasoning_effort      = 'low';
    body.include_reasoning     = false;
    body.max_completion_tokens = answerTokens + 1024;   // room for reasoning + answer
  } else {
    body.max_completion_tokens = answerTokens;
  }
  return body;
}

module.exports = { groqRequestOptions, DEFAULT_MODEL };
