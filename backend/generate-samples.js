require("dotenv").config();
const Groq = require("groq-sdk");
const fs = require("fs");

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const phishingTypes = [
  // ── Original 10 ──────────────────────────────────────────────
  "PayPal account suspended, verify immediately",
  "Bank transaction alert, click to confirm",
  "Prize winner notification, claim your reward",
  "Netflix payment failed, update billing",
  "IRS tax refund pending, submit details",
  "Apple ID locked, verify your account",
  "DHL package held at customs, pay fee",
  "LinkedIn account access from new device",
  "Microsoft 365 storage full, upgrade now",
  "Crypto wallet suspicious login detected",

  // ── Social Media Phishing ─────────────────────────────────────
  "WhatsApp account verification code request",
  "Instagram account suspended, verify now",
  "Facebook account hacked, reset password urgently",
  "Twitter account locked, confirm your identity",
  "TikTok creator account disabled, appeal now",
  "YouTube channel terminated, click to restore",
  "Snapchat account compromised, verify immediately",
  "Pinterest account flagged, update credentials",
  "Reddit account banned, submit appeal now",
  "Telegram account blocked, verify phone number",

  // ── Delivery & Shipping ───────────────────────────────────────
  "FedEx package undeliverable, confirm address",
  "UPS delivery failed, reschedule immediately",
  "Royal Mail package held, pay customs fee",
  "Amazon package delayed, update delivery address",
  "USPS delivery attempt failed, claim parcel",
  "Aramex shipment stuck at customs, pay now",
  "TNT courier package seized, verify recipient",
  "Lazada order held at warehouse, confirm details",
  "Shopify order cancelled, reconfirm payment",
  "eBay purchase dispute, respond immediately",

  // ── Financial & Banking ───────────────────────────────────────
  "HSBC online banking suspended, verify identity",
  "Barclays unusual transaction detected, confirm",
  "Chase Bank account locked, update details now",
  "Citibank credit card declined, verify payment",
  "Wells Fargo security alert, login to confirm",
  "Standard Chartered account flagged, act now",
  "NIC Asia bank OTP required, verify transaction",
  "Binance withdrawal request confirmation required",
  "Coinbase wallet access restricted, verify now",
  "Western Union money transfer waiting for you",

  // ── Government & Tax ──────────────────────────────────────────
  "IRS final notice tax payment overdue",
  "HMRC tax refund approved, submit bank details",
  "Social Security number compromised, call immediately",
  "Government COVID relief fund, claim payment",
  "Passport renewal urgent, submit documents now",
  "Driving license suspended, pay fine online",
  "Immigration visa application update required",
  "Police cybercrime unit notice, respond immediately",
  "Court summons issued, download attached notice",
  "Medicare benefits expiring, update information",

  // ── Tech & Software ───────────────────────────────────────────
  "Google account unusual activity detected",
  "Your Zoom account has been suspended",
  "Dropbox storage full, upgrade immediately",
  "Adobe subscription expired, renew now",
  "Spotify premium payment failed, update billing",
  "Steam account trade hold, verify identity",
  "Norton antivirus subscription expired, renew",
  "McAfee virus detected on your device, act now",
  "Windows license expired, activate immediately",
  "iCloud storage full, upgrade or lose data",

  // ── Email & Workspace ─────────────────────────────────────────
  "Gmail account storage full, upgrade now",
  "Outlook account will be deactivated, verify",
  "Google Workspace admin action required",
  "Yahoo Mail account compromised, reset password",
  "Hotmail account flagged for spam, verify now",
  "Protonmail account suspended, confirm identity",
  "Office 365 license expired, renew immediately",
  "Slack workspace access revoked, verify email",
  "Notion account deleted, restore within 24 hours",
  "Trello board shared maliciously, take action",

  // ── Healthcare & Insurance ────────────────────────────────────
  "Health insurance claim rejected, appeal now",
  "COVID vaccine certificate expired, renew online",
  "Medical prescription fraud detected, verify",
  "Hospital bill overdue, pay immediately online",
  "Life insurance policy lapsing, update payment",
  "Dental plan benefits expiring, claim now",
  "Pharmacy order held, verify prescription details",
  "NHS appointment cancelled, reschedule urgent",
  "Blood test results available, login to view",
  "Emergency medical alert, update contact details",

  // ── Utilities & Services ──────────────────────────────────────
  "Electricity bill overdue, pay or face disconnection",
  "Internet service suspended, update payment",
  "Water bill final notice, pay immediately",
  "Gas supply disconnection warning, pay now",
  "Mobile phone contract expired, renew urgently",
  "Netflix subscription cancelled, reactivate now",
  "Amazon Prime membership expired, renew today",
  "Disney+ account suspended, update billing",
  "Hulu payment failed, reactivate subscription",
  "HBO Max account deactivated, verify payment",

  // ── Job & HR Scams ────────────────────────────────────────────
  "You have been selected for a remote job offer",
  "HR department payroll update, submit bank details",
  "Work from home opportunity, claim $500 daily",
  "CEO urgent wire transfer request, act now",
  "Salary increment approval, verify your details",
  "Employee benefits portal update required",
  "Job interview scheduled, confirm personal details",
  "LinkedIn recruiter found your profile, apply now",
  "Freelance project payment pending, verify account",
  "University scholarship awarded, claim immediately",

  // ── Romance & Personal ────────────────────────────────────────
  "Secret admirer wants to connect, click to reveal",
  "Dating site match found, verify to connect",
  "Inheritance from distant relative, claim now",
  "Nigerian prince investment opportunity, respond",
  "Lottery won abroad, submit passport to claim",
  "Charity donation confirmation, verify bank details",
  "Friend stranded abroad needs emergency funds",
  "Military officer overseas needs financial help",
  "Someone shared a compromising photo of you",
  "Your device has been hacked, pay ransom now",

  // ── Extra 10 to reach 120 total ───────────────────────────────
  "Suspicious login to your Google Drive, verify now",
  "Your Amazon seller account suspended, appeal now",
  "Fake Microsoft Teams meeting invite with malicious link",
  "DocuSign document requires your urgent signature",
  "Fake Airbnb booking confirmation, verify payment",
  "Uber account suspended, verify driving license",
  "Fake antivirus popup, your PC is infected call now",
  "Cryptocurrency airdrop, claim free tokens now",
  "Fake HR onboarding email, submit SSN and bank details",
  "Phishing via fake Google Forms survey with credential harvest"
];

const legitimateTypes = [
  "Weekly team meeting agenda",
  "Project update from colleague",
  "Invoice from a vendor",
  "Newsletter subscription confirmation",
  "Password reset you requested",
  "Order confirmation from Amazon",
  "Flight booking confirmation",
  "Bank statement available",
  "Job application acknowledgement",
  "University assignment submission confirmed"
];

async function generateEmail(type, isPhishing) {
  const prompt = isPhishing
    ? `Generate a realistic phishing email for this scenario: "${type}".
       Include a FROM name, FROM email address, SUBJECT line, and BODY with urgency,
       suspicious links (make up fake URLs), and social engineering tactics.
       Respond ONLY with a valid JSON object, no markdown, no explanation, no code fences.
       Format: { "from_name": "", "from_email": "", "subject": "", "body": "", "label": "phishing" }`
    : `Generate a realistic legitimate professional email for this scenario: "${type}".
       Include a FROM name, FROM email address, SUBJECT line, and a normal professional BODY.
       Respond ONLY with a valid JSON object, no markdown, no explanation, no code fences.
       Format: { "from_name": "", "from_email": "", "subject": "", "body": "", "label": "legitimate" }`;

  const result = await groq.chat.completions.create({
    model: "llama-3.3-70b-versatile",
    messages: [{ role: "user", content: prompt }],
    temperature: 0.7,
  });

  const text = result.choices[0].message.content;
  const clean = text.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

async function main() {
  const samples = [];
  let passed = 0;
  let failed = 0;

  console.log("========================================");
  console.log(" Genjutsu — Test Sample Generator");
  console.log(` Total phishing types: ${phishingTypes.length}`);
  console.log("========================================\n");

  console.log("Generating phishing samples...\n");
  for (let i = 0; i < phishingTypes.length; i++) {
    const type = phishingTypes[i];
    try {
      const email = await generateEmail(type, true);
      samples.push(email);
      passed++;
      console.log(`  ✓ [${i + 1}/${phishingTypes.length}] [PHISHING] ${email.subject}`);
      await new Promise(r => setTimeout(r, 600)); // slightly longer delay for 120 requests
    } catch (e) {
      failed++;
      console.error(`  ✗ Failed: ${type} — ${e.message}`);
    }
  }

  console.log("\nGenerating legitimate samples...\n");
  for (const type of legitimateTypes) {
    try {
      const email = await generateEmail(type, false);
      samples.push(email);
      passed++;
      console.log(`  ✓ [LEGIT]    ${email.subject}`);
      await new Promise(r => setTimeout(r, 600));
    } catch (e) {
      failed++;
      console.error(`  ✗ Failed: ${type} — ${e.message}`);
    }
  }

  fs.writeFileSync(
    "test-samples.json",
    JSON.stringify(samples, null, 2)
  );

  const phishingCount  = samples.filter(s => s.label === "phishing").length;
  const legitCount     = samples.filter(s => s.label === "legitimate").length;

  console.log("\n========================================");
  console.log(` Done: ${passed} generated, ${failed} failed`);
  console.log(` Phishing: ${phishingCount} | Legitimate: ${legitCount}`);
  console.log(` Saved to: test-samples.json`);
  console.log("========================================");
}

main();
