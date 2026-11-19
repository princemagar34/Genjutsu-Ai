// services/adminReport.js — one-page monthly PDF for the whole system
// (for a school, an investor or a pitch). Numbers only, no email contents.
const PDFDocument = require('pdfkit');

const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
const COUNTRY = (code) => { try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(code); } catch { return code; } };
const n = (x) => Number(x || 0).toLocaleString('en-US');
const plural = (x, one, many) => `${n(x)} ${Number(x) === 1 ? one : (many || one + 's')}`;
const hours = (min) => min >= 60 ? `${Math.floor(min / 60)}h ${min % 60}m` : `${min} min`;

function monthlyPdf(res, d, { year, month, by }) {
  const label = `${MONTHS[month - 1]} ${year}`;
  const doc = new PDFDocument({ size: 'A4', margin: 50, info: { Title: `Genjutsu — ${label}`, Author: 'Genjutsu' } });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="genjutsu-report-${year}-${String(month).padStart(2, '0')}.pdf"`);
  doc.pipe(res);

  const ink = '#15171C', muted = '#5B6170', red = '#B42318', line = '#E4E0D6';
  const W = doc.page.width - 100;
  const t = d.totals || {};
  const threats = (t.dangerous || 0) + (t.suspicious || 0);

  doc.fillColor(muted).fontSize(9).text('GENJUTSU · EMAIL SECURITY', 50, 50, { characterSpacing: 1 });
  doc.fillColor(ink).fontSize(26).font('Helvetica-Bold').text(`Monthly report — ${label}`, 50, 66);
  doc.font('Helvetica').fontSize(12).fillColor('#3F4450').moveDown(0.5)
    .text(threats
      ? `Genjutsu checked ${plural(t.scanned, 'email')} for ${plural(t.users, 'person', 'people')} and stopped ${plural(threats, 'phishing email')}. ` +
        `${plural(d.quarantined, 'dangerous email was', 'dangerous emails were')} moved out of inboxes automatically, and Nami kept scammers busy for ${hours(d.honeypot?.minutes || 0)}.`
      : `Genjutsu checked ${plural(t.scanned, 'email')} for ${plural(t.users, 'person', 'people')}. No phishing emails were found this month.`,
      { width: W, lineGap: 3 });

  // Big numbers
  const y0 = doc.y + 20, cw = W / 4;
  const stats = [[n(t.scanned), 'emails checked'], [n(t.dangerous), 'dangerous'], [n(t.suspicious), 'suspicious'], [hours(d.honeypot?.minutes || 0), 'scammer time wasted']];
  doc.moveTo(50, y0).lineTo(50 + W, y0).strokeColor(line).stroke();
  stats.forEach(([v, l], i) => {
    doc.font('Helvetica-Bold').fontSize(22).fillColor(i === 1 ? red : ink).text(v, 50 + i * cw, y0 + 14, { width: cw - 10 });
    doc.font('Helvetica').fontSize(9).fillColor(muted).text(l, 50 + i * cw, y0 + 44, { width: cw - 10 });
  });
  doc.moveTo(50, y0 + 66).lineTo(50 + W, y0 + 66).strokeColor(line).stroke();
  doc.y = y0 + 84;

  const heading = (s) => { doc.x = 50; doc.moveDown(0.6).font('Helvetica-Bold').fontSize(13).fillColor(ink).text(s, 50); doc.moveDown(0.3).font('Helvetica').fontSize(10).fillColor('#3F4450'); };
  const bars = (rows, labelOf, valueOf) => {
    const max = Math.max(1, ...rows.map(valueOf));
    rows.forEach(r => {
      const y = doc.y;
      doc.fillColor('#3F4450').fontSize(10).text(labelOf(r), 50, y, { width: 170, ellipsis: true, lineBreak: false });
      doc.rect(225, y + 2, Math.max(2, (W - 215) * valueOf(r) / max), 8).fill(red);
      doc.fillColor(muted).text(n(valueOf(r)), 50 + W - 40, y, { width: 40, align: 'right' });
      doc.y = y + 16;
    });
  };

  heading('Who attacked');
  if (d.attackers?.length) bars(d.attackers, r => r.domain, r => r.users);
  else doc.text('No attacking domains this month.');
  doc.fontSize(8).fillColor(muted).text('Bars show how many different people each domain targeted.', 50);

  heading('Where attacks were sent from');
  if (d.countries?.length) bars(d.countries, r => r.country === '??' ? 'Unknown' : COUNTRY(r.country), r => r.n);
  else doc.text('No data yet.');
  doc.fontSize(8).fillColor(muted).text("From the sending server's IP address. Scammers can use VPNs, so this is a hint, not proof.", 50);

  const mitre = {};
  for (const r of d.mitreRows || []) { try { for (const m of JSON.parse(r.mitre || '[]')) mitre[m.id] = mitre[m.id] || { ...m, n: 0 }, mitre[m.id].n++; } catch (_) {} }
  const top = Object.values(mitre).sort((a, b) => b.n - a.n).slice(0, 5);
  if (top.length) { heading('Attack techniques (MITRE ATT&CK)'); top.forEach(m => doc.text(`${m.id}  ${m.name} — ${plural(m.n, 'email')}`, 50)); }

  heading('Other numbers');
  doc.text(`New users: ${n(d.newUsers)}   ·   Honeypot conversations: ${n(d.honeypot?.sessions)}   ·   Emails users said were safe after a warning: ${n(d.disputes)}`, 50, doc.y, { width: W });

  doc.fontSize(8).fillColor(muted).text(`Made by Genjutsu on ${new Date().toISOString().slice(0, 10)} for ${by}. Contains totals only, no email contents.`,
    50, doc.page.height - 70, { width: W });
  doc.end();
}

module.exports = { monthlyPdf };
