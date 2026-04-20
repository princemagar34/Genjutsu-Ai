require("dotenv").config();
const nodemailer = require("nodemailer");
const fs         = require("fs");

// ── Config ────────────────────────────────────────────────────
const RECIPIENT   = "princemagar338@gmail.com";
const SENDER_MAIL = "princemagar122222@gmail.com";
const APP_PASS    = process.env.GMAIL_APP_PASSWORD; // add to .env

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: SENDER_MAIL,
    pass: APP_PASS,
  },
});

async function sendEmail(sample, index, total) {
  const mailOptions = {
    from:    `"${sample.from_name}" <${SENDER_MAIL}>`,
    to:      RECIPIENT,
    subject: sample.subject,
    text:    sample.body,
    headers: {
      "X-Genjutsu-Sample": "true",
      "X-Sample-Label":    sample.label,
      "X-Sample-Index":    String(index),
    },
  };

  await transporter.sendMail(mailOptions);
}

async function main() {
  if (!APP_PASS) {
    console.error("✗ GMAIL_APP_PASSWORD not set in .env");
    process.exit(1);
  }

  let samples;
  try {
    samples = JSON.parse(fs.readFileSync("test-samples.json", "utf-8"));
  } catch (e) {
    console.error("✗ Could not read test-samples.json:", e.message);
    process.exit(1);
  }

  // ── Send phishing emails only ─────────────────────────────────
  const phishingOnly = samples.filter(s => s.label === "phishing");

  console.log("========================================");
  console.log(" Genjutsu — Phishing Sample Sender");
  console.log(`  Sending ${phishingOnly.length} phishing emails to ${RECIPIENT}`);
  console.log(`  (${samples.length - phishingOnly.length} legitimate emails skipped)`);
  console.log("========================================\n");

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < phishingOnly.length; i++) {
    const sample = phishingOnly[i];
    try {
      await sendEmail(sample, i + 1, phishingOnly.length);
      passed++;
      console.log(`  ✓ [${i + 1}/${phishingOnly.length}] [PHISHING] ${sample.subject}`);
      // 2 second delay to avoid Gmail rate limiting on large batches
      await new Promise(r => setTimeout(r, 2000));
    } catch (e) {
      failed++;
      console.error(`  ✗ Failed: ${sample.subject} — ${e.message}`);
    }
  }

  console.log("\n========================================");
  console.log(` Done: ${passed} sent, ${failed} failed`);
  console.log(` Check inbox: ${RECIPIENT}`);
  console.log(" Now open Genjutsu and scan your inbox");
  console.log(" to measure detection accuracy!");
  console.log("========================================");
}

main();
