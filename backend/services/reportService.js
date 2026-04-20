// ============================================================
// services/reportService.js — PDF Report Generator (PDFKit)
// Called when user clicks "Generate Report" button on threats page
// Produces a clean, simple per-user PDF with their scan data
// ============================================================
const PDFDocument = require('pdfkit');

function generateUserReport(res, user, reportData) {
  const doc = new PDFDocument({ margin: 50, size: 'A4' });

  const filename = `genjutsu-report-${(user.email || 'user').replace('@','_')}-${Date.now()}.pdf`;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  doc.pipe(res);

  const stats  = reportData.stats || { total: 0, threats: 0, safe: 0 };
  const emails = reportData.emails || [];
  const threats = emails.filter(e => e.is_phishing === 1 || e.is_phishing === true);

  // ── Nepal time formatter ──────────────────────────────────────
  const nepalTime = new Date().toLocaleString('en-GB', {
    timeZone: 'Asia/Kathmandu',
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false
  });

  // ── COVER BAND ────────────────────────────────────────────────
  doc.rect(0, 0, 595, 175).fill('#0f172a');
  doc.fontSize(26).fillColor('#f8fafc').text('Genjutsu Security Report', 50, 55, { align: 'center' });
  doc.fontSize(12).fillColor('#94a3b8').text('Gmail Security System — Per User Analysis', { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(10).fillColor('#64748b').text(`Generated: ${nepalTime} (NPT)`, { align: 'center' });

  doc.y = 195;

  // ── ACCOUNT INFO ──────────────────────────────────────────────
  sectionHeader(doc, 'Account Information');
  infoRow(doc, 'Gmail Address', user.email || 'N/A');
  infoRow(doc, 'Display Name',  user.name  || 'N/A');
  infoRow(doc, 'Report Period', 'All scanned emails in database');
  infoRow(doc, 'System',        'Genjutsu Gmail Security System v3.0');
  doc.moveDown(1);

  // ── SCAN SUMMARY ──────────────────────────────────────────────
  sectionHeader(doc, 'Scan Summary');
  const safeCount  = stats.safe || Math.max(0, (stats.total || 0) - (stats.threats || 0));
  const threatRate = stats.total > 0
    ? ((stats.threats / stats.total) * 100).toFixed(1) + '%' : '0%';

  // Use effective counts from emails array (overrides applied)
  const effectiveDangerous  = emails.filter(e => e.threat_type === 'dangerous').length;
  const effectiveSuspicious = emails.filter(e => e.threat_type === 'suspicious').length;
  const effectiveThreats    = effectiveDangerous + effectiveSuspicious;
  const effectiveSafe       = emails.length - effectiveThreats;
  const effectiveRate       = emails.length > 0
    ? ((effectiveThreats / emails.length) * 100).toFixed(1) + '%' : '0%';

  infoRow(doc, 'Total Emails Scanned',  String(emails.length));
  infoRow(doc, 'Dangerous Emails',      String(effectiveDangerous),  '#ef4444');
  infoRow(doc, 'Suspicious Emails',     String(effectiveSuspicious), '#f59e0b');
  infoRow(doc, 'Safe Emails',           String(effectiveSafe),       '#10b981');
  infoRow(doc, 'Threat Detection Rate', effectiveRate);
  doc.moveDown(1);

  // ── THREAT EMAILS LIST ───────────────────────────────────────
  // Use effective level (override takes priority over scanner result).
  // Exactly mirrors what user sees in Genjutsu — safe emails excluded.
  const dangerous  = emails.filter(e => e.threat_type === 'dangerous');
  const suspicious = emails.filter(e => e.threat_type === 'suspicious');
  // Emails reclassified to safe are excluded entirely (not shown)

  sectionHeader(doc, `Threat Emails  (${dangerous.length} dangerous · ${suspicious.length} suspicious)`);

  if (dangerous.length === 0 && suspicious.length === 0) {
    doc.fontSize(11).fillColor('#10b981')
      .text('No threats found. Your inbox is clean!');
  } else {
    // ── Dangerous ─────────────────────────────────────────────
    if (dangerous.length > 0) {
      doc.fontSize(10).fillColor('#ef4444').font('Helvetica-Bold')
        .text(`DANGEROUS (${dangerous.length})`, 50, doc.y, { width: 495, align: 'center' });
      doc.font('Helvetica');
      doc.moveDown(0.3);
      drawThreatTableHeader(doc);
      dangerous.forEach((t, i) => {
        if (doc.y > 720) { doc.addPage(); drawThreatTableHeader(doc); }
        drawThreatTableRow(doc, i + 1, t);
      });
      doc.moveDown(1);
    }

    // ── Suspicious ────────────────────────────────────────────
    if (suspicious.length > 0) {
      if (doc.y > 680) doc.addPage();
      doc.fontSize(10).fillColor('#f59e0b').font('Helvetica-Bold')
        .text(`SUSPICIOUS (${suspicious.length})`, 50, doc.y, { width: 495, align: 'center' });
      doc.font('Helvetica');
      doc.moveDown(0.3);
      drawThreatTableHeader(doc);
      suspicious.forEach((t, i) => {
        if (doc.y > 720) { doc.addPage(); drawThreatTableHeader(doc); }
        drawThreatTableRow(doc, i + 1, t);
      });
    }
  }

  doc.end();
}

// ── Helpers ───────────────────────────────────────────────────

function sectionHeader(doc, title) {
  doc.fontSize(13).fillColor('#0f172a').font('Helvetica-Bold').text(title);
  doc.font('Helvetica');
  doc.moveTo(50, doc.y + 1).lineTo(545, doc.y + 1).strokeColor('#cbd5e1').lineWidth(0.5).stroke();
  doc.moveDown(0.6);
}

function infoRow(doc, label, value, valueColor = '#1e293b') {
  const y = doc.y;
  doc.fontSize(10).fillColor('#64748b').font('Helvetica').text(label + ':', 50, y, { width: 210 });
  doc.fontSize(10).fillColor(valueColor).text(value, 270, y, { width: 275 });
  doc.y = y + 16;
}

// ── Threat table header ───────────────────────────────────────
function drawThreatTableHeader(doc) {
  const y = doc.y;
  doc.rect(50, y, 495, 20).fill('#0f172a');
  doc.fontSize(8).fillColor('#f8fafc').font('Helvetica-Bold')
    .text('#',        56,  y + 6, { width: 20 })
    .text('Subject',  80,  y + 6, { width: 200 })
    .text('Sender',   284, y + 6, { width: 155 })
    .text('Score',    443, y + 6, { width: 45 })
    .text('Level',    491, y + 6, { width: 60 });
  doc.font('Helvetica');
  doc.y = y + 24;
}

// ── Threat table row ──────────────────────────────────────────
function drawThreatTableRow(doc, index, threat) {
  const y      = doc.y;
  const bg     = index % 2 === 0 ? '#f8fafc' : '#ffffff';
  const score  = Math.round((threat.confidence_score || 0) * 100);
  const level  = threat.threat_type || 'suspicious';
  const subj   = (threat.subject      || '(No Subject)').substring(0, 38);
  const sender = (threat.sender_email || 'Unknown').substring(0, 30);
  const scoreColor = score >= 60 ? '#ef4444' : '#f59e0b';
  const levelColor = level === 'dangerous' ? '#ef4444' : '#f59e0b';

  doc.rect(50, y - 1, 495, 17).fill(bg);
  doc.fontSize(8).fillColor('#334155')
    .text(String(index), 56,  y + 3, { width: 20 })
    .text(subj,          80,  y + 3, { width: 200 })
    .text(sender,        284, y + 3, { width: 155 });
  doc.fillColor(scoreColor).text(`${score}/100`, 443, y + 3, { width: 45 });
  doc.fillColor(levelColor).text(level,          491, y + 3, { width: 60 });
  doc.y = y + 17;
}

module.exports = { generateUserReport };
