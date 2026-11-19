// Looking inside attachments + QR codes, on real files built in tests/_files.js
const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const { inspect } = req('services/fileInspector');
const scanner = req('services/attachmentScanner');
const { analyseEmail } = req('services/threatService');
const db = req('database/db');
const { files } = require('./_files');
const lv = (r) => r.findings.map(f => f.level);

test('dangerous files are caught by what is inside them, not just the name', () => {
  const cases = [
    ['salary.pdf', files.pdfAutoJs(), /JavaScript automatically/],
    ['invoice.docm', files.docmAutoMacro(), /macros that run by themselves/],
    ['letter.docx', files.docxRemoteTemplate(), /downloads content from the internet/],
    ['documents.zip', files.zipWithExe(), /contains a program/],
    ['secure-message.html', files.htmlLogin(), /asks for a password/],
    ['logo.svg', files.svgScript(), /hidden code/],
    ['invoice.pdf', files.exeAsPdf(), /really a program/],
    ['budget.xls', files.oleMacro(), /macros/],
  ];
  for (const [name, buf, re] of cases) {
    const r = inspect(buf, name);
    assert.ok(lv(r).includes('dangerous'), name);
    assert.ok(r.findings.some(f => re.test(f.text)), name);
    assert.match(r.sha256, /^[0-9a-f]{64}$/);
  }
});
test('clean files stay clean; locked archives are a warning, not a verdict', () => {
  for (const [name, buf] of [['timetable.pdf', files.pdfClean()], ['notes.docx', files.docxClean()], ['trip.zip', files.zipClean()]])
    assert.deepEqual(inspect(buf, name).findings, [], name);
  assert.deepEqual(lv(inspect(files.zipLocked(), 'scan.zip')), ['suspicious']);
});
test('links hidden inside compressed PDFs are found', () => {
  assert.deepEqual(inspect(files.pdfHiddenLink(), 'statement.pdf').urls, ['http://paypa1-verify.co/login']);
});
test('QR codes are read from PNG and JPEG images', async () => {
  assert.deepEqual(inspect(await files.qrPng('http://esewa-kyc.top/verify'), 'poster.png').qr, ['http://esewa-kyc.top/verify']);
  assert.deepEqual(inspect(await files.qrJpeg('https://fonepay-refund.xyz/claim'), 'photo.jpg').urls, ['https://fonepay-refund.xyz/claim']);
});
test('a QR-code scam email is dangerous, and the QR link goes through the normal link checks', async () => {
  const email = { id: 'q1', from: 'eSewa <support@esewa-wallet-np.com>', subject: 'Scan to keep your wallet active', body: 'Scan the QR code in the attached notice.', links: [], attachments: [{ filename: 'KYC.png' }] };
  scanner.attach(email, 'KYC.png', inspect(await files.qrPng('http://esewa-kyc.top/verify'), 'KYC.png'));
  const r = await analyseEmail(email, { domainAge: false });
  assert.equal(r.level, 'dangerous'); assert.equal(r.subType, 'phishing');
  assert.ok(r.reasons.some(x => /Look-alike link domain: esewa-kyc\.top/.test(x)));
  assert.ok(r.reasons.some(x => /^QR code in "KYC\.png" opens/.test(x)));
});
test('downloads are limited, results are cached, file bytes are never kept', async () => {
  const saved = [];
  Object.assign(db, { query: async (sql, p) => { if (/INSERT INTO attachment_scans/.test(sql)) saved.push(p); return { rows: [] }; } });
  let calls = 0;
  const getAttachment = async () => { calls++; return files.docmAutoMacro(); };
  const emails = Array.from({ length: 10 }, (_, i) => ({ id: 'e' + i, attachments: Array.from({ length: 6 }, (_, k) => ({ filename: `f${k}.docm`, size: 900, attachmentId: 'a' + k })) }));
  const r = await scanner.prepare({ id: 'u1', provider: 'google' }, emails, { getAttachment });
  assert.equal(r.downloaded, scanner.PER_SCAN); assert.equal(calls, scanner.PER_SCAN);
  assert.ok(emails[0].fileFindings.length <= scanner.PER_EMAIL);
  assert.ok(saved.every(p => !String(p[3]).includes('AutoOpen')), 'only results are stored, not the file');
  // second scan: everything comes from the cache, nothing is downloaded
  const cachedResult = JSON.stringify({ kind: 'zip', sha256: 'x', findings: [{ level: 'dangerous', text: 'has macros' }], urls: [], qr: [] });
  Object.assign(db, { query: async (sql, p) => /SELECT cache_key/.test(sql) ? { rows: p[0].map(k => ({ cache_key: k, result: cachedResult })) } : { rows: [] } });
  calls = 0;
  const again = [{ id: 'e1', attachments: [{ filename: 'f0.docm', size: 900, attachmentId: 'a0' }] }];
  await scanner.prepare({ id: 'u1', provider: 'google' }, again, { getAttachment });
  assert.equal(calls, 0); assert.equal(again[0].fileFindings[0].findings[0].text, 'has macros');
  // files over 10 MB are never downloaded
  calls = 0;
  await scanner.prepare({ id: 'u1', provider: 'google' }, [{ id: 'big', attachments: [{ filename: 'huge.pdf', size: 50 * 1024 * 1024, attachmentId: 'z' }] }], { getAttachment });
  assert.equal(calls, 0);
});
