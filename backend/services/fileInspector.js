// services/fileInspector.js — looks INSIDE a file without ever opening or running it.
// Works on the raw bytes only (Node's zlib for compressed parts). Returns:
//   { kind, sha256, findings: [{ level: 'dangerous'|'suspicious'|'info', text }], urls: [], qr: [] }
// Covers: programs disguised as documents, PDFs (auto-run JavaScript, launch actions,
// embedded files, links), Word/Excel/PowerPoint (macros, auto-run, remote templates, DDE,
// external links), old .doc/.xls macros, ZIP archives (programs inside, password-locked),
// attached web pages and SVG images (password forms, scripts) and QR codes in images.
const crypto = require('crypto');
const zlib = require('zlib');

const MAX_INFLATE = 8 * 1024 * 1024;           // never unpack more than 8 MB (zip-bomb guard)
const PROGRAM_EXT = /\.(exe|scr|com|pif|bat|cmd|msi|msp|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|cpl|jar|lnk|reg|dll|apk|app|dmg|pkg|sh|iso|img|vhd|vhdx)$/i;
const ARCHIVE_EXT = /\.(zip|rar|7z|tar|gz|tgz|cab|ace|arj)$/i;
const DOC_EXT = /\.(pdf|docx?|docm|xlsx?|xlsm|xlsb|pptx?|pptm|rtf|txt|jpg|jpeg|png|gif)$/i;

function sniff(buf) {
  const h = buf.subarray(0, 8), s = h.toString('latin1');
  if (s.startsWith('%PDF')) return 'pdf';
  if (h[0] === 0x50 && h[1] === 0x4b && (h[2] === 3 || h[2] === 5 || h[2] === 7)) return 'zip';
  if (h.readUInt32BE(0) === 0xd0cf11e0) return 'ole';
  if (s.startsWith('MZ')) return 'exe';
  if (h[0] === 0x7f && s.slice(1, 4) === 'ELF') return 'elf';
  if (h.readUInt32BE(0) === 0x89504e47) return 'png';
  if (h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff) return 'jpeg';
  if (s.startsWith('GIF8')) return 'gif';
  if (s.startsWith('Rar!')) return 'rar';
  if (h[0] === 0x37 && h[1] === 0x7a && h[2] === 0xbc && h[3] === 0xaf) return '7z';
  if (s.startsWith('{\\rtf')) return 'rtf';
  const head = buf.subarray(0, 2048).toString('utf8').toLowerCase();
  if (/<svg[\s>]/.test(head)) return 'svg';
  if (/<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]|<script[\s>]|<form[\s>]/.test(head)) return 'html';
  return 'unknown';
}

const urlRe = /https?:\/\/[^\s"'<>()\\\]\[{}]{4,300}/gi;
const uniq = (a) => [...new Set(a)];

// ── ZIP (also .docx/.xlsx/.pptx) ─────────────────────────────
function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 66000); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10), cdOff = buf.readUInt32LE(eocd + 16);
  const entries = [];
  let p = cdOff;
  for (let i = 0; i < Math.min(count, 5000) && p + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const flags = buf.readUInt16LE(p + 8), method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    entries.push({ name: buf.subarray(p + 46, p + 46 + nlen).toString('utf8'), encrypted: !!(flags & 1), method, csize, usize, local });
    p += 46 + nlen + xlen + clen;
  }
  let budget = MAX_INFLATE;
  const read = (e) => {
    if (e.encrypted || e.usize > budget) return null;
    const lp = e.local;
    if (lp + 30 > buf.length || buf.readUInt32LE(lp) !== 0x04034b50) return null;
    const start = lp + 30 + buf.readUInt16LE(lp + 26) + buf.readUInt16LE(lp + 28);
    const data = buf.subarray(start, start + e.csize);
    try {
      const out = e.method === 0 ? data : e.method === 8 ? zlib.inflateRawSync(data, { maxOutputLength: Math.min(budget, 4 * 1024 * 1024) }) : null;
      if (out) budget -= out.length;
      return out;
    } catch (_) { return null; }
  };
  return { entries, read };
}

function inspectOffice(zip, add) {
  const names = zip.entries.map(e => e.name.toLowerCase());
  const isOffice = names.some(n => n === '[content_types].xml');
  if (!isOffice) return false;
  const hasMacros = names.some(n => /vbaproject\.bin$/.test(n));
  if (hasMacros) {
    const vba = zip.entries.find(e => /vbaproject\.bin$/i.test(e.name));
    const body = vba ? (zip.read(vba) || Buffer.alloc(0)).toString('latin1') : '';
    if (/auto_?open|document_open|workbook_open|autoexec|autoclose|document_close/i.test(body))
      add('dangerous', 'has macros that run by themselves when the file is opened');
    else add('dangerous', 'has macros (hidden code). Real documents almost never need them');
  }
  for (const e of zip.entries.filter(x => /\.rels$/i.test(x.name))) {
    const xml = (zip.read(e) || Buffer.alloc(0)).toString('utf8');
    for (const m of xml.matchAll(/<Relationship\b[^>]*>/gi)) {
      const tag = m[0];
      if (!/TargetMode="External"/i.test(tag)) continue;
      const target = (tag.match(/Target="([^"]+)"/i) || [])[1] || '';
      if (/attachedTemplate|oleObject|frame/i.test(tag) && /^(https?|file|\\\\)/i.test(target))
        add('dangerous', `downloads content from the internet when opened (${target.slice(0, 120)})`);
      if (/^https?:/i.test(target)) add('url', target);
    }
  }
  for (const e of zip.entries.filter(x => /(document|sheet\d*|slide\d*)\.xml$/i.test(x.name)).slice(0, 40)) {
    const xml = (zip.read(e) || Buffer.alloc(0)).toString('utf8');
    if (/\bDDEAUTO\b|<w:instrText[^>]*>\s*DDE\b/i.test(xml)) add('dangerous', 'uses DDE, a trick to run commands when the file is opened');
  }
  if (names.some(n => /activex|embeddings\/.*\.(bin|exe)/.test(n))) add('suspicious', 'contains embedded objects (ActiveX or embedded files)');
  return true;
}

function inspectArchive(zip, add) {
  const files = zip.entries.filter(e => !e.name.endsWith('/'));
  if (files.some(e => e.encrypted)) add('suspicious', 'is password-locked, so security scanners cannot look inside. A common trick to hide malware');
  const programs = files.filter(e => PROGRAM_EXT.test(e.name));
  if (programs.length) add('dangerous', `contains a program: ${programs.slice(0, 3).map(e => e.name.split('/').pop()).join(', ')}`);
  const disguised = files.filter(e => /\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|lnk)$/i.test(e.name));
  if (disguised.length) add('dangerous', `hides a program behind a document name: ${disguised[0].name.split('/').pop()}`);
  if (files.some(e => ARCHIVE_EXT.test(e.name))) add('suspicious', 'contains another archive inside (often used to slip past scanners)');
  return files;
}

// ── PDF ──────────────────────────────────────────────────────
function inspectPdf(buf, add) {
  let text = buf.toString('latin1');
  let budget = MAX_INFLATE, n = 0;
  for (const m of text.matchAll(/stream\r?\n/g)) {
    if (++n > 300 || budget <= 0) break;
    const start = m.index + m[0].length, end = text.indexOf('endstream', start);
    if (end < 0) continue;
    const dict = text.slice(Math.max(0, m.index - 300), m.index);
    if (!/FlateDecode/.test(dict)) continue;
    try { const out = zlib.inflateSync(buf.subarray(start, end), { maxOutputLength: Math.min(budget, 2 * 1024 * 1024) }); budget -= out.length; text += '\n' + out.toString('latin1'); } catch (_) {}
  }
  const has = (re) => re.test(text);
  const js = has(/\/(JavaScript|JS)\b/), auto = has(/\/(OpenAction|AA)\b/);
  if (has(/\/Launch\b/)) add('dangerous', 'tries to start another program when opened (/Launch)');
  if (js && auto) add('dangerous', 'runs JavaScript automatically when opened');
  else if (js) add('suspicious', 'contains JavaScript');
  if (has(/\/EmbeddedFile\b/)) {
    const names = [...text.matchAll(/\/F\s*\(([^)]{1,120})\)/g)].map(x => x[1]);
    if (names.some(x => PROGRAM_EXT.test(x))) add('dangerous', `has a program hidden inside: ${names.find(x => PROGRAM_EXT.test(x))}`);
    else add('suspicious', 'has other files hidden inside');
  }
  if (has(/\/SubmitForm\b/)) add('suspicious', 'has a form that sends what you type to a website');
  if (has(/\/XFA\b/)) add('suspicious', 'uses XFA forms (rare, often abused)');
  for (const m of text.matchAll(/\/URI\s*\(([^)]{4,400})\)/g)) add('url', m[1].replace(/\\([()\\])/g, '$1'));
}

// ── Web pages and SVG ────────────────────────────────────────
function inspectMarkup(buf, kind, add) {
  const t = buf.subarray(0, 2 * 1024 * 1024).toString('utf8');
  if (/<input[^>]+type\s*=\s*["']?password/i.test(t)) add('dangerous', 'is a web page that asks for a password. Real companies never send login pages as attachments');
  else if (/<form[^>]+action\s*=\s*["']?https?:/i.test(t)) add('suspicious', 'is a web page with a form that sends data to a website');
  const script = /<script[\s>]|\bon(load|error|click|mouseover)\s*=/i.test(t);
  if (kind === 'svg' && script) add('dangerous', 'is an image with hidden code (scripts in SVG are a known phishing trick)');
  else if (script && /(window|document|top)\.location|location\.(href|replace)|atob\(|eval\(|unescape\(|fromCharCode/i.test(t)) add('suspicious', 'runs code that sends you to another website');
  if (/<meta[^>]+http-equiv\s*=\s*["']?refresh/i.test(t)) add('suspicious', 'redirects you to another website as soon as it opens');
  for (const m of t.matchAll(urlRe)) add('url', m[0]);
}

// ── Old Word/Excel (.doc/.xls) ───────────────────────────────
function inspectOle(buf, add) {
  const latin = buf.toString('latin1'), u16 = buf.toString('utf16le');
  const macros = /_VBA_PROJECT|VBA\b/.test(u16) || /Attribute VB_/.test(latin);
  if (macros) {
    if (/auto_?open|document_open|workbook_open|autoexec/i.test(latin) || /auto_?open|document_open|workbook_open/i.test(u16))
      add('dangerous', 'has macros that run by themselves when the file is opened');
    else add('dangerous', 'has macros (hidden code). Real documents almost never need them');
  }
}

// ── QR codes in images ───────────────────────────────────────
function readQr(buf, kind) {
  try {
    let img;
    if (kind === 'png') { const png = require('pngjs').PNG.sync.read(buf); img = { data: png.data, width: png.width, height: png.height }; }
    else if (kind === 'jpeg') { img = require('jpeg-js').decode(buf, { useTArray: true, maxMemoryUsageInMB: 256, maxResolutionInMP: 40 }); }
    else return null;
    if (img.width * img.height > 40e6) return null;
    const jsQR = require('jsqr');
    const code = jsQR(new Uint8ClampedArray(img.data.buffer, img.data.byteOffset, img.data.length), img.width, img.height, { inversionAttempts: 'attemptBoth' });
    return code?.data || null;
  } catch (_) { return null; }
}

function inspect(buf, filename = '', mimeType = '') {
  const name = String(filename || '');
  const kind = sniff(buf);
  const out = { kind, sha256: crypto.createHash('sha256').update(buf).digest('hex'), findings: [], urls: [], qr: [] };
  const add = (level, text) => {
    if (level === 'url') { if (/^https?:\/\//i.test(text) && !/^https?:\/\/(www\.)?(w3\.org|schemas\.(openxmlformats|microsoft)\.(org|com)|ns\.adobe\.com|purl\.org)\//i.test(text)) out.urls.push(text.slice(0, 500)); return; }
    if (!out.findings.some(f => f.text === text)) out.findings.push({ level, text });
  };
  // a program pretending to be something else
  if ((kind === 'exe' || kind === 'elf') && !PROGRAM_EXT.test(name)) add('dangerous', `is really a program, although its name says "${name}"`);
  else if (kind === 'exe' || kind === 'elf') add('dangerous', 'is a program');
  if (DOC_EXT.test(name) && ['zip', 'ole', 'pdf', 'png', 'jpeg', 'gif', 'rtf', 'unknown', 'exe', 'elf', 'html'].indexOf(kind) < 0)
    add('suspicious', `is not what its name says (it is ${kind.toUpperCase()}, not ${name.split('.').pop().toUpperCase()})`);
  if (/\.pdf$/i.test(name) && kind === 'html') add('suspicious', 'is a web page pretending to be a PDF');

  if (kind === 'pdf') inspectPdf(buf, add);
  else if (kind === 'zip') { const z = readZip(buf); if (z && !inspectOffice(z, add)) inspectArchive(z, add); }
  else if (kind === 'ole') inspectOle(buf, add);
  else if (kind === 'html' || kind === 'svg') inspectMarkup(buf, kind, add);
  else if (kind === 'rar' || kind === '7z') add('suspicious', `is a ${kind.toUpperCase()} archive that Genjutsu can't look inside. Be careful with what is in it`);
  else if (kind === 'rtf' && /\\objdata|\\objupdate|\\object/i.test(buf.subarray(0, 4e6).toString('latin1'))) add('dangerous', 'has an embedded object that can run code (a known Word exploit trick)');
  else if (kind === 'png' || kind === 'jpeg') {
    const q = readQr(buf, kind);
    if (q) { out.qr.push(q.slice(0, 500)); if (/^https?:\/\//i.test(q)) out.urls.push(q.slice(0, 500)); }
  }
  out.urls = uniq(out.urls).slice(0, 50);
  return out;
}

module.exports = { inspect, sniff, readZip, readQr, PROGRAM_EXT };
