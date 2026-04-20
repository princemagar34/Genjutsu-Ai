require("dotenv").config();
const Groq = require("groq-sdk");

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

async function test() {
  try {
    const result = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "Say hello in one sentence." }],
      temperature: 0.2,
    });
    console.log("✓ Groq connected successfully");
    console.log("Response:", result.choices[0].message.content);
  } catch (e) {
    console.error("✗ Connection failed:", e.message);
  }
}

test();
