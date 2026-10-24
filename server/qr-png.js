const QRCode = require('qrcode');
const { Buffer } = require('node:buffer');

function pngChunk(type, data = Buffer.alloc(0)) {
  const typeBytes = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
  const crcInput = Buffer.concat([typeBytes, data]);
  let crc = 0xffffffff;
  for (const byte of crcInput) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0); }
  const checksum = Buffer.alloc(4); checksum.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
  return Buffer.concat([length, typeBytes, data, checksum]);
}

async function createQrPng(code, scale = 4, margin = 4) {
  const modules = QRCode.create(String(code)).modules;
  const side = (modules.size + margin * 2) * scale;
  const pixels = Buffer.alloc((side + 1) * side, 255);
  for (let y = 0; y < side; y++) {
    const rowOffset = y * (side + 1); pixels[rowOffset] = 0;
    const moduleY = Math.floor(y / scale) - margin;
    if (moduleY < 0 || moduleY >= modules.size) continue;
    for (let x = 0; x < side; x++) {
      const moduleX = Math.floor(x / scale) - margin;
      if (moduleX >= 0 && moduleX < modules.size && modules.data[moduleY * modules.size + moduleX]) pixels[rowOffset + x + 1] = 0;
    }
  }
  const stream = new CompressionStream('deflate');
  const writer = stream.writable.getWriter(); await writer.write(pixels); await writer.close();
  const compressed = Buffer.from(await new Response(stream.readable).arrayBuffer());
  const header = Buffer.alloc(13); header.writeUInt32BE(side, 0); header.writeUInt32BE(side, 4); header[8] = 8; header[9] = 0;
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), pngChunk('IHDR', header), pngChunk('IDAT', compressed), pngChunk('IEND')]);
}

module.exports = { createQrPng };
