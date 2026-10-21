import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const payload = Buffer.from('synthetic harmless executable fixture');
const digest = createHash('sha256').update(payload).digest('hex');
const url = 'https://downloads.getmaxim.ai/bifrost/v1.2.3/linux/amd64/bifrost-http';
for (const packageName of ['bifrost', 'bifrost-cli']) {
  const security = await import(`../../npx/${packageName}/verify.js`);
  test(`${packageName}: absent or malformed checksums fail closed`, async () => {
    for (const text of ['', 'not-a-hash', `${digest}\n${digest}`, 'x'.repeat(1025)]) {
      assert.throws(() => security.parseChecksum(text));
    }
    assert.equal(security.parseChecksum(`${digest}  binary\n`), digest);
    await assert.rejects(security.getExpectedHash(`${url}.sha256`, async () => new Response('', { status: 404 })));
    await assert.rejects(security.getExpectedHash(`${url}.sha256`, async () => new Response('x'.repeat(2048))));
    await assert.rejects(security.getExpectedHash('https://attacker.invalid/checksum'));
  });
  test(`${packageName}: failed verification preserves the installed file`, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'bifrost-verification-'));
    const destination = join(directory, 'binary');
    try {
      writeFileSync(destination, 'previous approved release');
      await assert.rejects(security.downloadVerified(url, destination, digest, async (_, options) => {
        assert.equal(options.redirect, 'error');
        return new Response('substituted bytes');
      }));
      assert.equal(readFileSync(destination, 'utf8'), 'previous approved release');
      assert.deepEqual(readdirSync(directory), ['binary']);
      await security.downloadVerified(url, destination, digest, async () => new Response(payload));
      await security.verifyFile(destination, digest);
      writeFileSync(destination, 'tampered cache');
      await assert.rejects(security.verifyFile(destination, digest));
      symlinkSync(destination, join(directory, 'link'));
      await assert.rejects(security.verifyFile(join(directory, 'link'), digest));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
test('both separately published launchers use identical verification code', () => {
  assert.deepEqual(readFileSync(new URL('../../npx/bifrost/verify.js', import.meta.url)),
                   readFileSync(new URL('../../npx/bifrost-cli/verify.js', import.meta.url)));
});
