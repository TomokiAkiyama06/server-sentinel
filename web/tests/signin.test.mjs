import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { compile } from './compile.mjs';
import { buildAll, checkShellInputs, listFiles, SHELL_BUDGET } from '../scripts/build.mjs';
import { CONTENT_TYPES } from '../scripts/policy.mjs';

await compile('src/signin/code.ts', 'build/signin-code.mjs');
await compile('src/shared/webauthn.ts', 'build/shared-webauthn.mjs');
const { normalizeInvitationCode, credentialLabel } = await import('../build/signin-code.mjs');
const wire = await import('../build/shared-webauthn.mjs');

// --- Invitation code normalization ---------------------------------------
// Derived from server/app/auth/invitation_code.py: ALPHABET
// "0123456789ABCDEFGHJKMNPQRSTVWXYZ", 20 bytes -> 32 characters, groups of 4
// joined by "-", and parse_invitation_code accepting only that exact form
// (_CANONICAL). The server-side cross-check (feeding these outputs to
// parse_invitation_code) is left to S5b, which owns server/ tests.
const SERVER_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const SERVER_CANONICAL = /^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){7}$/;

/** A transcription of invitation_code._encode, for vectors beyond the fixed ones. */
function serverEncode(secret) {
  let value = BigInt(`0x${Buffer.from(secret).toString('hex') || '0'}`);
  let plain = '';
  for (let index = 0; index < 32; index++) { plain = SERVER_ALPHABET[Number(value & 31n)] + plain; value >>= 5n; }
  return plain.match(/.{4}/g).join('-');
}

// Vectors printed by invitation_code.format_invitation_code on main.
const SERVER_VECTORS = [
  ['0000000000000000000000000000000000000000', '0000-0000-0000-0000-0000-0000-0000-0000'],
  ['ffffffffffffffffffffffffffffffffffffffff', 'ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ'],
  ['000102030405060708090a0b0c0d0e0f10111213', '000G-40R4-0M30-E209-185G-R38E-1W81-24GK'],
  ['c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb', 'S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPV'],
];

test('the encoder transcription reproduces the server vectors', () => {
  for (const [hex, display] of SERVER_VECTORS) assert.equal(serverEncode(Buffer.from(hex, 'hex')), display);
});

const CANONICAL = 'S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPV';
const NORMALIZATION = [
  [CANONICAL, CANONICAL],
  ['s34w-njyc-sq7c-zm6h-tb9x-9nep-tzcd-kppv', CANONICAL],
  ['S34WNJYCSQ7CZM6HTB9X9NEPTZCDKPPV', CANONICAL],
  ['  S34W NJYC SQ7C ZM6H TB9X 9NEP TZCD KPPV  ', CANONICAL],
  ['S3-4WN-JYCSQ7CZM6HTB9X9NEPTZCD-KPP-V', CANONICAL],
  ['S34W\tNJYC\nSQ7C ZM6H TB9X 9NEP TZCD KPPV', CANONICAL],
  // Full-width input from a Japanese IME (NFKC), its space and dash forms.
  ['Ｓ３４Ｗ－ＮＪＹＣ　ＳＱ７Ｃ－ＺＭ６Ｈ－ＴＢ９Ｘ－９ＮＥＰ－ＴＺＣＤ－ＫＰＰＶ', CANONICAL],
  ['S34Wー NJYC‐SQ7C–ZM6H—TB9X−9NEP-TZCD-KPPV', CANONICAL],
  // Crockford aliases: O -> 0, I and L -> 1, either case.
  ['OOOO-oooo-0000-0000-0000-0000-0000-0000', '0000-0000-0000-0000-0000-0000-0000-0000'],
  ['IiLl-1111-0000-0000-0000-0000-0000-0000', '1111-1111-0000-0000-0000-0000-0000-0000'],
  // Refused: U (not an alias), other characters, any length but 32.
  ['S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPU', null],
  ['S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPP', null],
  ['S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPVV', null],
  ['S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPP*', null],
  ['S34W_NJYC_SQ7C_ZM6H_TB9X_9NEP_TZCD_KPPV', null],
  ['S34W.NJYC.SQ7C.ZM6H.TB9X.9NEP.TZCD.KPPV', null],
  ['', null],
  ['-'.repeat(40), null],
  ['S'.repeat(300), null],
  ['Ä34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPV', null],
];

test('typed invitation codes normalize to exactly the server canonical form', () => {
  for (const [input, expected] of NORMALIZATION) {
    const normalized = normalizeInvitationCode(input);
    assert.equal(normalized, expected, JSON.stringify(input));
    if (normalized !== null) assert.match(normalized, SERVER_CANONICAL);
  }
});

test('every random server code round-trips through normalization unchanged', () => {
  for (let index = 0; index < 500; index++) {
    const display = serverEncode(randomBytes(20));
    assert.match(display, SERVER_CANONICAL);
    assert.equal(normalizeInvitationCode(display), display);
    assert.equal(normalizeInvitationCode(display.toLowerCase().replaceAll('-', ' ')), display);
  }
});

test('the credential label follows the server rule (1-64 characters, no control character)', () => {
  assert.equal(credentialLabel(''), null);
  assert.equal(credentialLabel('   '), null);
  assert.equal(credentialLabel('  研究室の鍵 '), '研究室の鍵');
  assert.equal(credentialLabel('a'.repeat(64)), 'a'.repeat(64));
  assert.equal(credentialLabel('😀'.repeat(64)), '😀'.repeat(64));
  assert.equal(credentialLabel('a'.repeat(65)), undefined);
  assert.equal(credentialLabel('a\u0007b'), undefined);
  assert.equal(credentialLabel('a\u007fb'), undefined);
});

// --- base64url and the credential wire format ----------------------------

test('base64url round-trips every length and matches Node encoding', () => {
  for (let length = 0; length <= 70; length++) {
    const bytes = randomBytes(length);
    const encoded = wire.base64urlEncode(bytes);
    assert.equal(encoded, bytes.toString('base64url'));
    assert.equal(wire.base64urlEncode(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + length)), encoded);
    if (length > 0) assert.deepEqual(Buffer.from(wire.base64urlDecode(encoded)), bytes);
  }
});

test('base64url decoding is as strict as the server', () => {
  for (const value of ['', 'A', 'AB=', 'AA==', 'a+b/', 'ab c', 'AB', 'AAB', 'Zg=', 'Zh', 123, null, undefined, ['AA']]) {
    assert.throws(() => wire.base64urlDecode(value), wire.WireError, JSON.stringify(value));
  }
  assert.deepEqual(Array.from(wire.base64urlDecode('AA')), [0]);
  assert.deepEqual(Array.from(wire.base64urlDecode('_-8')), [255, 239]);
});

const creation = {
  rp: { id: 'example.invalid', name: 'example.invalid' },
  user: { id: 'AAECAw', name: 'person-a.invalid', displayName: 'person-a.invalid' },
  challenge: 'BAUGBw', pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
  timeout: 300000, excludeCredentials: [{ type: 'public-key', id: 'CQo' }],
  authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
  attestation: 'none',
};
const request = { challenge: 'BAUGBw', rpId: 'example.invalid', timeout: 300000, userVerification: 'required', allowCredentials: [] };

test('creation and request options decode to browser options', () => {
  const decoded = wire.decodeCreationOptions(creation);
  assert.deepEqual(Array.from(decoded.user.id), [0, 1, 2, 3]);
  assert.deepEqual(Array.from(decoded.challenge), [4, 5, 6, 7]);
  assert.deepEqual(Array.from(decoded.excludeCredentials[0].id), [9, 10]);
  assert.equal(decoded.authenticatorSelection.userVerification, 'required');
  assert.equal(decoded.attestation, 'none');
  assert.equal(decoded.timeout, 300000);
  const get = wire.decodeRequestOptions(request);
  assert.deepEqual(Array.from(get.challenge), [4, 5, 6, 7]);
  assert.equal(get.rpId, 'example.invalid');
  assert.deepEqual(get.allowCredentials, []);
});

test('options that weaken or garble the ceremony are refused', () => {
  const variants = [
    { ...creation, attestation: 'direct' },
    { ...creation, authenticatorSelection: { ...creation.authenticatorSelection, userVerification: 'preferred' } },
    { ...creation, authenticatorSelection: { ...creation.authenticatorSelection, residentKey: 'discouraged' } },
    { ...creation, challenge: 'BAUGBw==' }, { ...creation, user: { ...creation.user, id: '' } },
    { ...creation, pubKeyCredParams: [] }, { ...creation, pubKeyCredParams: [{ type: 'public-key', alg: '-7' }] },
    { ...creation, timeout: -1 }, { ...creation, rp: { id: '', name: 'x' } }, null, [], 'options',
  ];
  for (const value of variants) assert.throws(() => wire.decodeCreationOptions(value), wire.WireError);
  for (const value of [{ ...request, userVerification: 'discouraged' }, { ...request, challenge: 'A' },
    { ...request, allowCredentials: [{ type: 'other', id: 'AA' }] }, { ...request, rpId: 7 }, null]) {
    assert.throws(() => wire.decodeRequestOptions(value), wire.WireError);
  }
});

function withCredentialClasses(run) {
  class PublicKeyCredential {}
  class AuthenticatorAttestationResponse {}
  class AuthenticatorAssertionResponse {}
  Object.assign(globalThis, { PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse });
  const make = (Type, fields) => Object.assign(Object.create(Type.prototype), fields);
  try { run({ PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse, make }); } finally {
    for (const name of ['PublicKeyCredential', 'AuthenticatorAttestationResponse', 'AuthenticatorAssertionResponse']) delete globalThis[name];
  }
}

const bytes = values => new Uint8Array(values).buffer;

test('the registration serializer emits exactly the fields the server reads', () => {
  withCredentialClasses(({ PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse, make }) => {
    const created = make(PublicKeyCredential, {
      type: 'public-key', id: 'ignored', rawId: bytes([1, 2, 3]), authenticatorAttachment: 'platform',
      response: make(AuthenticatorAttestationResponse, {
        clientDataJSON: bytes([123, 125]), attestationObject: bytes([161, 0]), getTransports: () => ['internal'],
      }),
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    });
    assert.deepEqual(wire.serializeRegistration(created), {
      id: 'AQID', rawId: 'AQID', type: 'public-key', response: { clientDataJSON: 'e30', attestationObject: 'oQA' },
    });
    assert.throws(() => wire.serializeRegistration(null), wire.WireError);
    assert.throws(() => wire.serializeRegistration({ ...created }), wire.WireError);
    assert.throws(() => wire.serializeRegistration(make(PublicKeyCredential, {
      type: 'public-key', rawId: bytes([1]), response: make(AuthenticatorAssertionResponse, {}),
    })), wire.WireError);
  });
});

test('the assertion serializer emits exactly the fields the server reads', () => {
  withCredentialClasses(({ PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse, make }) => {
    const asserted = handle => make(PublicKeyCredential, {
      type: 'public-key', rawId: bytes([1, 2, 3]),
      response: make(AuthenticatorAssertionResponse, {
        clientDataJSON: bytes([123, 125]), authenticatorData: bytes([5]), signature: bytes([6, 7]), userHandle: handle,
      }),
    });
    assert.deepEqual(wire.serializeAssertion(asserted(bytes([8]))), {
      id: 'AQID', rawId: 'AQID', type: 'public-key',
      response: { clientDataJSON: 'e30', authenticatorData: 'BQ', signature: 'Bgc', userHandle: 'CA' },
    });
    assert.equal(wire.serializeAssertion(asserted(null)).response.userHandle, null);
    assert.equal(wire.serializeAssertion(asserted(bytes([]))).response.userHandle, null);
    assert.throws(() => wire.serializeAssertion(make(PublicKeyCredential, {
      type: 'public-key', rawId: bytes([1]), response: make(AuthenticatorAttestationResponse, {}),
    })), wire.WireError);
  });
});

// --- Build split, isolation, budget, determinism, manifest ---------------

const SHELL_FORBIDDEN = [
  /ServerSentinel/i, /Sentinel/i, /camera/i, /カメラ/, /録画/, /ライブ/, /live/i, /recording/i,
  /media-capture/i, /react/i, /version/i, /\bv?\d+\.\d+\.\d+\b/, /esbuild/i, /generator/i, /rel="?icon/i,
];

test('the shell is built only from src/signin and the shared WebAuthn module', async () => {
  const { shellInputs, appInputs } = await buildAll('build/inputs-check');
  assert.ok(shellInputs.includes('src/signin/main.ts'));
  assert.ok(shellInputs.includes('src/shared/webauthn.ts'));
  for (const input of shellInputs) assert.match(input, /^(src\/signin\/[^/]+\.(ts|css)|src\/shared\/webauthn\.ts)$/);
  assert.ok(appInputs.some(input => input.startsWith('node_modules/react')), 'the app bundle is the React one');
  for (const input of ['src/i18n.ts', 'src/App.tsx', 'src/shared/format.ts', 'node_modules/react/index.js', 'src/signin/sub/x.ts']) {
    assert.throws(() => checkShellInputs({ inputs: { 'src/signin/main.ts': {}, [input]: {} } }), /not allowed/);
  }
});

test('the shell stays within its size budget', async () => {
  const size = async path => (await readFile(path)).length;
  assert.ok(await size('dist/shell/index.html') <= SHELL_BUDGET.html, 'HTML <= 2 KB');
  assert.ok(await size('dist/shell/s.js') <= SHELL_BUDGET.js, 'JS <= 12 KB');
  assert.ok(await size('dist/shell/s.css') <= SHELL_BUDGET.css, 'CSS <= 3 KB');
  assert.deepEqual(await listFiles('dist/shell'), ['index.html', 's.css', 's.js']);
});

test('the shell carries no product, feature, dependency or version string', async () => {
  for (const name of await listFiles('dist/shell')) {
    const content = await readFile(`dist/shell/${name}`, 'utf8');
    for (const pattern of SHELL_FORBIDDEN) assert.doesNotMatch(content, pattern, `${name} ${pattern}`);
  }
  const html = await readFile('dist/shell/index.html', 'utf8');
  assert.match(html, /<html lang="ja">/);
  assert.match(html, /<title>サインイン<\/title>/);
  // Only its own two assets; no inline script or style, no external URL, no form.
  assert.deepEqual([...html.matchAll(/(?:src|href)="([^"]*)"/g)].map(match => match[1]).sort(), ['/s.css', '/s.js']);
  assert.doesNotMatch(html, /<script>|<style|\sstyle="|\son[a-z]+="|https?:|<form|<input[^>]*\sname=/i);
});

test('two builds are byte-identical', async () => {
  await buildAll('build/determinism-a');
  await buildAll('build/determinism-b');
  const first = await listFiles('build/determinism-a');
  assert.deepEqual(await listFiles('build/determinism-b'), first);
  assert.deepEqual(await listFiles('dist'), first);
  for (const name of first) {
    const a = await readFile(`build/determinism-a/${name}`);
    assert.ok(a.equals(await readFile(`build/determinism-b/${name}`)), name);
    assert.ok(a.equals(await readFile(`dist/${name}`)), `dist/${name}`);
  }
});

test('the manifest lists every served file with its digest, size and type', async () => {
  const manifest = JSON.parse(await readFile('dist/manifest.json', 'utf8'));
  assert.deepEqual(Object.keys(manifest), ['files']);
  const served = [...(await listFiles('dist/shell')).map(name => `shell/${name}`), ...(await listFiles('dist/app')).map(name => `app/${name}`)].sort();
  assert.deepEqual(Object.keys(manifest.files), served);
  assert.deepEqual(await listFiles('dist'), [...served, 'manifest.json'].sort());
  for (const [path, entry] of Object.entries(manifest.files)) {
    assert.deepEqual(Object.keys(entry), ['sha256', 'size', 'type']);
    const content = await readFile(`dist/${path}`);
    assert.equal(entry.sha256, createHash('sha256').update(content).digest('hex'), path);
    assert.equal(entry.size, content.length, path);
    assert.equal(entry.type, CONTENT_TYPES.get(path.slice(path.lastIndexOf('.'))), path);
  }
  for (const path of ['shell/index.html', 'shell/s.js', 'shell/s.css', 'app/index.html', 'app/app.js', 'app/app.css', 'app/icon.svg']) {
    assert.ok(manifest.files[path], path);
  }
});
