import { createHash } from 'node:crypto';
import { constants, createReadStream, createWriteStream, openSync, fstatSync, closeSync, chmodSync, renameSync, unlinkSync } from 'node:fs';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const MAX_BINARY_BYTES = 512 * 1024 * 1024;

// These helpers are shipped in both dependency-free launchers; CI checks parity.
export function parseChecksum(text) {
  const match = /^([a-fA-F0-9]{64})(?:[ \t]+\*?[^\r\n]+)?\s*$/.exec(text);
  if (!match || text.length > 1024) throw new Error('Missing or malformed SHA-256 checksum');
  return match[1].toLowerCase();
}

export async function getExpectedHash(url, fetcher = fetch) {
  const parsed = new URL(url);
  if (parsed.origin !== 'https://downloads.getmaxim.ai') throw new Error('Untrusted download origin');
  const response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Checksum download failed (${response.status}); refusing to execute`);
  let text = '';
  for await (const bytes of response.body) {
    text += Buffer.from(bytes).toString('utf8');
    if (text.length > 1024) throw new Error('Oversized checksum response');
  }
  return parseChecksum(text);
}

export async function verifyFile(path, expected) {
  if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error('Invalid expected checksum');
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_BINARY_BYTES) throw new Error('Invalid binary file');
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(path, { fd: descriptor, autoClose: false })) hash.update(chunk);
    if (hash.digest('hex') !== expected) throw new Error('Binary checksum mismatch; refusing to execute');
  } finally {
    closeSync(descriptor);
  }
}

export async function downloadVerified(url, destination, expected, fetcher = fetch) {
  if (new URL(url).origin !== 'https://downloads.getmaxim.ai') throw new Error('Untrusted download origin');
  const temporary = `${destination}.download-${process.pid}-${Date.now()}`;
  let created = false;
  try {
    const response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(120000) });
    if (!response.ok || !response.body) throw new Error(`Binary download failed (${response.status})`);
    let size = 0;
    const limit = new Transform({ transform(chunk, encoding, done) {
      size += chunk.length;
      done(size > MAX_BINARY_BYTES ? new Error('Binary download exceeds size limit') : null, chunk);
    } });
    const output = createWriteStream(temporary, { flags: 'wx', mode: 0o600 });
    output.once('open', () => { created = true; });
    await pipeline(Readable.fromWeb(response.body), limit, output);
    await verifyFile(temporary, expected);
    chmodSync(temporary, 0o755);
    renameSync(temporary, destination);
    created = false;
  } finally {
    if (created) unlinkSync(temporary);
  }
}
