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

  const stats    = reportData.stats    || { total: 0, threats: 0, safe: 0 };
  const honeypot = reportData.honeypot || { sessions: 0, minutes: 0 };
  const emails   = reportData.emails   || [];
  const threats  = emails.filter(e => e.is_phishing === 1 || e.is_phishing === true);

  // ── COVER BAND ────────────────────────────────────────────────
  doc.rect(0, 0, 595, 175).fill('#0f172a');
  doc.fontSize(26).fillColor('#f8fafc').text('Genjutsu Security Report', 50, 55, { align: 'center' });
  doc.fontSize(12).fillColor('#94a3b8').text('Gmail Security System — Per User Analysis', { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(10).fillColor('#64748b').text(`Generated: ${new Date().toLocaleString('en-GB')}`, { align: 'center' });

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

  infoRow(doc, 'Total Emails Scanned',  String(stats.total   || 0));
  infoRow(doc, 'Threats Detected',      String(stats.threats || 0), '#ef4444');
  infoRow(doc, 'Safe Emails',           String(safeCount),          '#10b981');
  infoRow(doc, 'Threat Detection Rate', threatRate);
  doc.moveDown(1);

  // ── HONEYPOT ACTIVITY ─────────────────────────────────────────
  sectionHeader(doc, 'Honeypot Activity');
  infoRow(doc, 'Scammer Sessions Engaged',       String(honeypot.sessions || 0));
  infoRow(doc, 'Time Wasted for Scammers',       `${honeypot.minutes || 0} minutes`);
  doc.moveDown(1);

  // ── THREAT DETAILS TABLE ──────────────────────────────────────
  sectionHeader(doc, `Detected Threats  (${threats.length} found)`);

  if (threats.length === 0) {
    doc.fontSize(11).fillColor('#10b981')
      .text('No threats found in your scanned emails. Your inbox is clean!');
  } else {
    doc.moveDown(0.3);
    drawTableHeader(doc);
    threats.slice(0, 30).forEach((t, i) => {
      if (doc.y > 730) { doc.addPage(); drawTableHeader(doc); }
      drawTableRow(doc, i + 1, t);
    });
    if (threats.length > 30) {
      doc.moveDown(0.5);
      doc.fontSize(9).fillColor('#64748b')
        .text(`... and ${threats.length - 30} more. Re-scan your inbox for the latest data.`);
    }
  }

  // Footer removed

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

function drawTableHeader(doc) {
  const y = doc.y;
  doc.rect(50, y, 495, 20).fill('#1e293b');
  doc.fontSize(8).fillColor('#f8fafc').font('Helvetica-Bold')
    .text('#',       56,  y + 5, { width: 18 })
    .text('Subject', 78,  y + 5, { width: 185 })
    .text('Sender',  268, y + 5, { width: 150 })
    .text('Score',   423, y + 5, { width: 45 })
    .text('Level',   473, y + 5, { width: 65 });
  doc.font('Helvetica');
  doc.y = y + 24;
}

function drawTableRow(doc, index, threat) {
  const y       = doc.y;
  const bg      = index % 2 === 0 ? '#f8fafc' : '#ffffff';
  const score   = Math.round((threat.confidence_score || 0) * 100);
  const level   = threat.threat_type || 'phishing';
  const subject = (threat.subject     || '(No Subject)').substring(0, 38);
  const sender  = (threat.sender_email || 'Unknown').substring(0, 28);
  const scoreColor = score >= 60 ? '#ef4444' : '#f59e0b';
  const levelColor = level === 'dangerous' ? '#ef4444' : '#f59e0b';

  doc.rect(50, y - 1, 495, 17).fill(bg);
  doc.fontSize(8).fillColor('#334155')
    .text(String(index), 56,  y + 2, { width: 18 })
    .text(subject,       78,  y + 2, { width: 185 })
    .text(sender,        268, y + 2, { width: 150 });
  doc.fillColor(scoreColor).text(`${score}/100`, 423, y + 2, { width: 45 });
  doc.fillColor(levelColor).text(level,          473, y + 2, { width: 65 });
  doc.y = y + 17;
}

module.exports = { generateUserReport };
