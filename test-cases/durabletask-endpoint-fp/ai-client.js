// Ordinary AI SDK client code. Nothing malicious here.
const OPENAI_BASE = "https://api.openai.com";
const GEMINI_BASE = "https://generativelanguage.googleapis.com";

export async function listModels() {
  const res = await fetch(`${OPENAI_BASE}/v1/models`);
  return res.json();
}

export async function listGeminiModels() {
  const res = await fetch(`${GEMINI_BASE}/v1/models`);
  return res.json();
}

export const healthPath = "/api/public/version";
export const chime = "/audio.mp3";
