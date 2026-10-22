import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('tests/access_entry.ts', 'build/access.mjs');
const { messages } = await import('../build/i18n.mjs');
const {
  ApiError, createDashboardServices, parsePrincipals, parseIssuedInvitation, displayNameAcceptable, runOwnerChange,
  AccessScreen, PersonCard, InvitationCode, StepUpPrompt,
} = await import('../build/access.mjs');

// Synthetic only: generated identifiers and names, no deployment or person value.
const origin = 'https://server-sentinel.test';
const csrf = 'A'.repeat(42) + 'b';
const ownerId = '00000000-0000-4000-8000-00000000c000';
const personId = '00000000-0000-4000-8000-00000000c001';
const handle = '00000000-0000-4000-8000-00000000d001';
const CODE = '0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
const at = '2026-10-22T01:02:03.123456+00:00';
const ownerBody = { csrf, role: 'owner', permissions: ['live:view', 'recordings:view'] };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const STEP_UP = () => new Response('{"detail":"step_up_required"}', {
  status: 403, headers: { 'Content-Type': 'application/json', 'Content-Length': '29' } });
const signal = () => new AbortController().signal;

const credential = (overrides = {}) => ({
  handle, label: '生成ラベル', status: 'active', inconsistency_reason: null, backup_eligible: true,
  backup_state: true, created_at: at, last_used_at: null, revoked_at: null, ...overrides,
});
const person = (overrides = {}) => ({
  id: personId, display_name: '生成 閲覧者', role: 'invited_user', status: 'active', created_at: at, revoked_at: null,
  permissions: ['live:view'], invitation: { pending: false, expires_at: null }, credentials: [credential()], ...overrides,
});
const owner = person({ id: ownerId, display_name: '生成 管理者', role: 'owner', permissions: ['live:view', 'recordings:view'] });

function fake(routes) {
  const calls = [];
  const request = async (url, init) => {
    const parsed = new URL(url);
    const key = `${init.method} ${parsed.pathname}`;
    calls.push({ key, url: parsed, init });
    const answer = routes[key];
    if (!answer) return new Response('synthetic private detail', { status: 404 });
    const value = typeof answer === 'function' ? answer(parsed, init, calls) : answer;
    return value instanceof Response ? value.clone() : value;
  };
  return { calls, request };
}

async function signedIn(routes = {}, options = {}) {
  const transport = fake({ 'GET /api/session': json(ownerBody), ...routes });
  const services = createDashboardServices(origin, transport.request, options);
  await services.loadSession(signal());
  return { services, calls: transport.calls };
}

test('inventory decodes strictly and copies only the documented fields', async () => {
  const body = { principals: [
    { ...owner, last_external_identity: 'synthetic-login@example.invalid', tailscale_device: 'synthetic-node' },
    { ...person(), credentials: [{ ...credential(), credential_id: 'c3ludGhldGlj', public_key: 'cGs', sign_count: 7 }] },
  ] };
  const parsed = parsePrincipals(body);
  assert.deepEqual(parsed, [owner, person()]);
  // Nothing from an undocumented field reaches the parsed value (D14).
  assert.doesNotMatch(JSON.stringify(parsed), /example\.invalid|synthetic-node|c3ludGhldGlj|sign_count|public_key/);
  const { services, calls } = await signedIn({ 'GET /api/admin/principals': json(body) });
  assert.deepEqual(await services.loadPrincipals(signal()), [owner, person()]);
  const call = calls.at(-1);
  assert.equal(call.url.href, `${origin}/api/admin/principals`);
  assert.equal(call.init.method, 'GET');
  assert.deepEqual(call.init.headers, { Accept: 'application/json' });
  assert.equal(call.init.referrerPolicy, 'no-referrer');
  assert.equal(call.init.redirect, 'error');
});

test('one malformed person fails the whole inventory closed instead of hiding them', () => {
  const bad = [
    null, {}, { ...person(), id: 'x' }, { ...person(), id: personId.toUpperCase() }, { ...person(), display_name: '' },
    { ...person(), display_name: 'x'.repeat(129) }, { ...person(), role: 'admin' }, { ...person(), status: 'paused' },
    { ...person(), permissions: ['live:view', 'live:view'] }, { ...person(), permissions: ['admin'] },
    { ...person(), invitation: { pending: true, expires_at: null } }, { ...person(), invitation: { pending: false, expires_at: at } },
    { ...person(), created_at: '2026-10-22 01:02:03' }, { ...person(), created_at: '2026-10-22T01:02:03+09:00' },
    { ...person(), credentials: {} }, { ...person(), credentials: [credential(), credential()] },
    { ...person(), credentials: [credential({ handle: 'x' })] }, { ...person(), credentials: [credential({ status: 'lost' })] },
    { ...person(), credentials: [credential({ status: 'revoked' })] }, { ...person(), credentials: [credential({ revoked_at: at })] },
    { ...person(), credentials: [credential({ backup_state: 1 })] }, { ...person(), credentials: [credential({ label: '' })] },
    { ...person(), credentials: [credential({ label: '😀'.repeat(65) })] },
    { ...person(), credentials: [credential({ inconsistency_reason: 'other' })] },
  ];
  for (const entry of bad) {
    assert.throws(() => parsePrincipals({ principals: [owner, entry] }), { code: 'invalid_response' });
  }
  assert.throws(() => parsePrincipals({ principals: [person(), person()] }), { code: 'invalid_response' });
  for (const body of [null, [], {}, { principals: {} }]) assert.throws(() => parsePrincipals(body), { code: 'invalid_response' });
  // Readable older rows and code-point bounds.
  assert.equal(parsePrincipals({ principals: [person({ display_name: '😀'.repeat(128) })] }).length, 1);
  assert.equal(parsePrincipals({ principals: [person({ credentials: [credential({ label: '😀'.repeat(64) })] })] }).length, 1);
  assert.equal(parsePrincipals({ principals: [person({ created_at: '2026-10-22T01:02:03Z' })] }).length, 1);
});

test('an issued code must be the canonical grouped form', () => {
  assert.deepEqual(parseIssuedInvitation({ code: CODE, expires_at: at }), { code: CODE, expires_at: at });
  for (const code of [CODE.toLowerCase(), CODE.replaceAll('-', ''), CODE.replace('0123', 'O123'), CODE.replace('0123', 'U123'),
    `${CODE}-0000`, ` ${CODE}`, 7, null]) {
    assert.throws(() => parseIssuedInvitation({ code, expires_at: at }), { code: 'invalid_response' });
  }
  assert.throws(() => parseIssuedInvitation({ code: CODE, expires_at: 'tomorrow' }), { code: 'invalid_response' });
});

test('invite posts the name and grants with the CSRF token and returns the code', async () => {
  const { services, calls } = await signedIn({ 'POST /api/admin/principals': json({ principal_id: personId, code: CODE, expires_at: at }) });
  assert.deepEqual(await services.invitePrincipal('生成 閲覧者', ['recordings:view'], signal()),
    { principal_id: personId, code: CODE, expires_at: at });
  const call = calls.at(-1);
  assert.equal(call.init.body, JSON.stringify({ display_name: '生成 閲覧者', permissions: ['recordings:view'] }));
  assert.deepEqual(call.init.headers, { Accept: 'application/json', 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' });
  assert.equal(call.init.referrer, '');
  assert.equal(call.init.referrerPolicy, 'same-origin');
  assert.equal(call.init.redirect, 'error');
  // Refused locally, nothing sent.
  const before = calls.length;
  for (const [name, grants] of [['', []], ['x'.repeat(65), []], ['a\u0000b', []], ['a​b', []], ['a b', []],
    ['ok', ['admin']], ['ok', ['live:view', 'live:view']]]) {
    await assert.rejects(services.invitePrincipal(name, grants, signal()), { code: 'invalid_request' });
  }
  assert.equal(calls.length, before);
  assert.equal(displayNameAcceptable('😀'.repeat(64)), true);
  assert.equal(displayNameAcceptable('😀'.repeat(65)), false);
  for (const body of [{ code: CODE, expires_at: at }, { principal_id: 'x', code: CODE, expires_at: at }]) {
    const other = await signedIn({ 'POST /api/admin/principals': json(body) });
    await assert.rejects(other.services.invitePrincipal('x', [], signal()), { code: 'invalid_response' });
  }
});

test('re-issue, grant change and both revocations hit their own path with an exact body', async () => {
  const base = `/api/admin/principals/${personId}`;
  const { services, calls } = await signedIn({
    [`POST ${base}/invitation`]: json({ code: CODE, expires_at: at }),
    [`POST ${base}/permissions`]: new Response(null, { status: 204 }),
    [`POST ${base}/revoke`]: new Response(null, { status: 204 }),
    [`POST ${base}/credentials/${handle}/revoke`]: new Response(null, { status: 204 }),
  });
  assert.deepEqual(await services.reissueInvitation(personId, signal()), { code: CODE, expires_at: at });
  await services.changePermission(personId, 'live:view', false, signal());
  await services.revokeCredential(personId, handle, signal());
  await services.revokePrincipal(personId, signal());
  const posts = calls.filter(call => call.init.method === 'POST');
  assert.deepEqual(posts.map(call => [call.url.pathname, call.init.body]), [
    [`${base}/invitation`, '{}'],
    [`${base}/permissions`, JSON.stringify({ permission: 'live:view', granted: false })],
    [`${base}/credentials/${handle}/revoke`, '{}'],
    [`${base}/revoke`, '{}'],
  ]);
  for (const call of posts) assert.equal(call.init.headers['X-CSRF-Token'], csrf);
  const before = calls.length;
  await assert.rejects(services.revokePrincipal('../session', signal()), { code: 'invalid_request' });
  await assert.rejects(services.revokeCredential(personId, 'x/../..', signal()), { code: 'invalid_request' });
  await assert.rejects(services.changePermission(personId, 'admin', true, signal()), { code: 'invalid_request' });
  await assert.rejects(services.reissueInvitation(personId.toUpperCase(), signal()), { code: 'invalid_request' });
  assert.equal(calls.length, before);
  // A 200 where 204 is expected, or the reverse, is not a success.
  const wrong = await signedIn({ [`POST ${base}/revoke`]: json({}), [`POST ${base}/invitation`]: new Response(null, { status: 204 }) });
  await assert.rejects(wrong.services.revokePrincipal(personId, signal()), { code: 'unavailable' });
  await assert.rejects(wrong.services.reissueInvitation(personId, signal()), { code: 'unavailable' });
  // The generic refusal stays generic.
  const refused = await signedIn();
  await assert.rejects(refused.services.revokePrincipal(personId, signal()), { code: 'unauthorized' });
  await assert.rejects(refused.services.loadPrincipals(signal()), { code: 'unauthorized' });
});

test('only the exact step-up answer on an Owner change reads as step_up_required', async () => {
  const path = `POST /api/admin/principals/${personId}/revoke`;
  const stale = await signedIn({ [path]: STEP_UP });
  await assert.rejects(stale.services.revokePrincipal(personId, signal()), { code: 'step_up_required' });
  // Without a declared length the body is still read under the cap.
  const unsized = await signedIn({ [path]: () => new Response('{"detail":"step_up_required"}', {
    status: 403, headers: { 'Content-Type': 'application/json' } }) });
  await assert.rejects(unsized.services.revokePrincipal(personId, signal()), { code: 'step_up_required' });
  const others = [
    new Response('', { status: 403 }),
    new Response('{"detail":"step_up_required"}', { status: 403, headers: { 'Content-Type': 'text/plain' } }),
    new Response('{"detail":"Not Found"}', { status: 403, headers: { 'Content-Type': 'application/json' } }),
    new Response('{"detail":"step_up_required","x":1}', { status: 403, headers: { 'Content-Type': 'application/json' } }),
    new Response('{"detail":"step_up_required"}', { status: 404, headers: { 'Content-Type': 'application/json' } }),
    new Response('{"detail":"step_up_required"}', { status: 403, headers: { 'Content-Type': 'application/json', 'Content-Length': '99999' } }),
    new Response(`{"detail":"step_up_required","pad":"${'x'.repeat(400)}"}`, { status: 403, headers: { 'Content-Type': 'application/json' } }),
  ];
  for (const response of others) {
    const other = await signedIn({ [path]: response });
    await assert.rejects(other.services.revokePrincipal(personId, signal()), { code: 'unauthorized' });
  }
  // A read never reports a step-up: the inventory is OWNER_READ.
  const read = await signedIn({ 'GET /api/admin/principals': STEP_UP });
  await assert.rejects(read.services.loadPrincipals(signal()), { code: 'unauthorized' });
});

test('step-up: CSRF options, the session credential passed through unchanged, then the assertion', async () => {
  const challenge = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
  const own = 'AQID';
  const assertion = { id: 'BAU', rawId: 'BAU', type: 'public-key',
    response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AQ', userHandle: null } };
  let seen;
  const { services, calls } = await signedIn({
    'POST /api/auth/step-up/options': json({ challenge, rpId: 'server-sentinel.test', timeout: 60000,
      userVerification: 'required', allowCredentials: [{ type: 'public-key', id: own }] }),
    'POST /api/auth/step-up': new Response(null, { status: 204 }),
  }, { assertWith: async publicKey => { seen = publicKey; return assertion; } });
  await services.stepUp(signal());
  assert.equal(seen.rpId, 'server-sentinel.test');
  assert.equal(seen.userVerification, 'required');
  assert.equal(seen.allowCredentials.length, 1);
  assert.deepEqual([...seen.allowCredentials[0].id], [1, 2, 3]);
  const [options, finish] = calls.slice(-2);
  assert.equal(options.key, 'POST /api/auth/step-up/options');
  assert.equal(options.init.body, '{}');
  assert.equal(finish.key, 'POST /api/auth/step-up');
  assert.equal(finish.init.body, JSON.stringify(assertion));
  for (const call of [options, finish]) {
    assert.equal(call.init.headers['X-CSRF-Token'], csrf);
    assert.equal(call.init.referrerPolicy, 'same-origin');
  }
});

test('step-up failures stop before the next request and leak nothing', async () => {
  const goodOptions = json({ challenge: 'AAEC', rpId: 'server-sentinel.test', userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: 'AQID' }] });
  let asked = 0;
  const assertWith = async () => { asked += 1; throw new Error('synthetic private NotAllowedError'); };
  // Not exactly one allowed credential (none would open a picker): refused before the ceremony.
  for (const allowCredentials of [undefined, [], [{ type: 'public-key', id: 'AQID' }, { type: 'public-key', id: 'BAU' }]]) {
    const picker = await signedIn({ 'POST /api/auth/step-up/options': json({ challenge: 'AAEC', rpId: 'server-sentinel.test',
      userVerification: 'required', ...(allowCredentials ? { allowCredentials } : {}) }) }, { assertWith });
    await assert.rejects(picker.services.stepUp(signal()), { code: 'invalid_response' });
    assert.ok(!picker.calls.some(call => call.key === 'POST /api/auth/step-up'));
  }
  assert.equal(asked, 0);
  // Options refused: no ceremony.
  const refused = await signedIn({}, { assertWith });
  await assert.rejects(refused.services.stepUp(signal()), { code: 'unauthorized' });
  assert.equal(asked, 0);
  // Options without user verification "required": refused before the ceremony.
  const weak = await signedIn({ 'POST /api/auth/step-up/options': json({ challenge: 'AAEC', rpId: 'x', userVerification: 'preferred' }) }, { assertWith });
  await assert.rejects(weak.services.stepUp(signal()), { code: 'invalid_response' });
  assert.equal(asked, 0);
  // Cancelled or failed ceremony: no finish request.
  const cancelled = await signedIn({ 'POST /api/auth/step-up/options': goodOptions }, { assertWith });
  await assert.rejects(cancelled.services.stepUp(signal()), error => {
    assert.equal(error.code, 'unavailable');
    assert.doesNotMatch(error.message, /private/);
    return true;
  });
  assert.equal(asked, 1);
  assert.ok(!cancelled.calls.some(call => call.key === 'POST /api/auth/step-up'));
  // A refused finish is a failure.
  const denied = await signedIn({ 'POST /api/auth/step-up/options': goodOptions },
    { assertWith: async () => ({ id: 'AA', rawId: 'AA', type: 'public-key', response: {} }) });
  await assert.rejects(denied.services.stepUp(signal()), { code: 'unauthorized' });
  // No token yet: nothing is sent.
  const empty = fake({});
  await assert.rejects(createDashboardServices(origin, empty.request).stepUp(signal()), { code: 'unauthorized' });
  assert.equal(empty.calls.length, 0);
});

test('an Owner change runs once, asks before a step-up and retries exactly once', async () => {
  const stale = () => new ApiError('step_up_required');
  // done at once: no question asked.
  let runs = 0; let asked = 0; let ceremonies = 0;
  const hooks = (answer, ceremony = async () => { ceremonies += 1; }) => ({
    confirm: async () => { asked += 1; return answer; }, stepUp: ceremony });
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; return 'v'; }, hooks(true), signal()), { state: 'done', value: 'v' });
  assert.deepEqual([runs, asked, ceremonies], [1, 0, 0]);
  // Declined: not performed, no ceremony, no retry.
  runs = 0; asked = 0; ceremonies = 0;
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; throw stale(); }, hooks(false), signal()), { state: 'not_performed' });
  assert.deepEqual([runs, asked, ceremonies], [1, 1, 0]);
  // Confirmed: ceremony then one retry.
  runs = 0; asked = 0; ceremonies = 0;
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; if (runs === 1) throw stale(); return 'ok'; }, hooks(true), signal()),
    { state: 'done', value: 'ok' });
  assert.deepEqual([runs, asked, ceremonies], [2, 1, 1]);
  // onRetry fires once, after the ceremony and right before the retry is sent.
  const order = [];
  runs = 0;
  await runOwnerChange(async () => { runs += 1; order.push(`run${runs}`); if (runs === 1) throw stale(); return 'ok'; }, {
    confirm: async () => { order.push('confirm'); return true; }, stepUp: async () => { order.push('ceremony'); },
    onRetry: () => order.push('retry'),
  }, signal());
  assert.deepEqual(order, ['run1', 'confirm', 'ceremony', 'retry', 'run2']);
  // A failed ceremony never reaches the retry.
  const none = [];
  await runOwnerChange(async () => { throw stale(); }, { confirm: async () => true,
    stepUp: async () => { throw new Error('synthetic'); }, onRetry: () => none.push('retry') }, signal());
  assert.deepEqual(none, []);
  // Still stale after one step-up: no loop.
  runs = 0; asked = 0; ceremonies = 0;
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; throw stale(); }, hooks(true), signal()), { state: 'not_performed' });
  assert.deepEqual([runs, asked, ceremonies], [2, 1, 1]);
  // Failed ceremony: not performed, no retry.
  runs = 0; asked = 0; ceremonies = 0;
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; throw stale(); },
    hooks(true, async () => { ceremonies += 1; throw new Error('synthetic'); }), signal()), { state: 'not_performed' });
  assert.deepEqual([runs, asked, ceremonies], [1, 1, 1]);
  // No ceremony available: not performed.
  assert.deepEqual(await runOwnerChange(async () => { throw stale(); }, { confirm: async () => true }, signal()), { state: 'not_performed' });
  // Any other failure: unknown, no question.
  runs = 0; asked = 0; ceremonies = 0;
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; throw new Error('network'); }, hooks(true), signal()), { state: 'unknown' });
  assert.deepEqual([runs, asked, ceremonies], [1, 0, 0]);
  // A retry failing otherwise is unknown, not "not performed".
  runs = 0;
  assert.deepEqual(await runOwnerChange(async () => { runs += 1; if (runs === 1) throw stale(); throw new Error('network'); },
    hooks(true), signal()), { state: 'unknown' });
  // Leaving the screen: aborted, even with the question open.
  const controller = new AbortController();
  const pending = runOwnerChange(async () => { throw stale(); }, { confirm: () => { controller.abort(); return Promise.resolve(true); },
    stepUp: async () => assert.fail('no ceremony after abort') }, controller.signal);
  assert.deepEqual(await pending, { state: 'aborted' });
});

test('provider and helper together: stale, confirm, step-up, the same change once more', async () => {
  const path = `POST /api/admin/principals/${personId}/revoke`;
  let revokes = 0;
  const { services, calls } = await signedIn({
    [path]: () => (revokes += 1) === 1 ? STEP_UP() : new Response(null, { status: 204 }),
    'POST /api/auth/step-up/options': json({ challenge: 'AAEC', rpId: 'server-sentinel.test', userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: 'AQID' }] }),
    'POST /api/auth/step-up': new Response(null, { status: 204 }),
  }, { assertWith: async () => ({ id: 'AQID', rawId: 'AQID', type: 'public-key',
    response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AQ', userHandle: null } }) });
  const outcome = await runOwnerChange(inner => services.revokePrincipal(personId, inner),
    { confirm: async () => true, stepUp: inner => services.stepUp(inner) }, signal());
  assert.deepEqual(outcome, { state: 'done', value: undefined });
  assert.deepEqual(calls.filter(call => call.init.method === 'POST').map(call => call.key), [
    path, 'POST /api/auth/step-up/options', 'POST /api/auth/step-up', path,
  ]);
  // Declined: the step-up routes are never called and the change is not resent.
  revokes = 0;
  const declined = await signedIn({ [path]: () => STEP_UP() });
  assert.deepEqual(await runOwnerChange(inner => declined.services.revokePrincipal(personId, inner),
    { confirm: async () => false, stepUp: inner => declined.services.stepUp(inner) }, signal()), { state: 'not_performed' });
  assert.deepEqual(declined.calls.filter(call => call.init.method === 'POST').map(call => call.key), [path]);
});

const noop = () => undefined;
const actions = { grant: noop, reissue: noop, revokeCredential: noop, revokePerson: noop };
// Text checks compare against the catalog, so the two entities React writes for text are decoded.
const render = (element) => renderToStaticMarkup(element).replaceAll('&#x27;', "'").replaceAll('&quot;', '"');

test('the Owner row and revoked people carry no control; managed people carry each one', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const ownerRow = render(createElement(PersonCard, { t, person: owner, disabled: false, confirming: null, setConfirming: noop, actions }));
    assert.doesNotMatch(ownerRow, /<button/);
    assert.ok(ownerRow.includes(t.accessOwnerLocal));
    const revoked = render(createElement(PersonCard, { t, person: person({ status: 'revoked', revoked_at: at,
      credentials: [credential({ status: 'revoked', revoked_at: at })] }), disabled: false, confirming: null, setConfirming: noop, actions }));
    assert.doesNotMatch(revoked, /<button/);
    const managed = render(createElement(PersonCard, { t, person: person(), disabled: false, confirming: null, setConfirming: noop, actions }));
    for (const label of [t.accessWithdraw, t.accessGrant, t.accessReissue, t.credentialRevoke, t.accessRevokePerson]) {
      assert.ok(managed.includes(label), label);
    }
    // Independent grants: live:view held, recordings:view not.
    assert.match(managed, /data-permission="live:view" data-granted="true"/);
    assert.match(managed, /data-permission="recordings:view" data-granted="false"/);
    // No control is offered when the provider lacks it.
    const readOnly = render(createElement(PersonCard, { t, person: person(), disabled: false, confirming: null, setConfirming: noop, actions: {} }));
    assert.doesNotMatch(readOnly, /<button/);
  }
});

test('destructive changes ask first and describe credential-scoped revocation', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const card = confirming => render(createElement(PersonCard, { t, person: person(), disabled: false, confirming, setConfirming: noop, actions }));
    assert.ok(!card(null).includes(t.credentialRevokeConfirm));
    assert.ok(card(`credential:${handle}`).includes(t.credentialRevokeConfirm));
    assert.ok(card(`credential:${handle}`).includes(t.credentialRevokeConfirmText));
    assert.ok(card(`principal:${personId}`).includes(t.accessRevokePersonConfirmText));
    assert.ok(card(`reissue:${personId}`).includes(t.accessReissueConfirmText));
  }
  // Wording: never per-device revocation, always every device holding the passkey.
  const ja = messages.ja;
  for (const text of [ja.credentialRevoke, ja.credentialRevokeConfirm]) assert.doesNotMatch(text, /端末/);
  assert.match(ja.credentialRevokeConfirmText, /すべての端末/);
  assert.match(ja.accessCredentialScope, /複数の端末/);
  const en = messages.en;
  for (const text of [en.credentialRevoke, en.credentialRevokeConfirm]) assert.doesNotMatch(text, /device/i);
  assert.match(en.credentialRevokeConfirmText, /every device/);
  for (const locale of ['ja', 'en']) {
    for (const [key, value] of Object.entries(messages[locale])) {
      if (!/^(access|credential|invitation|stepUp)/.test(key)) continue;
      assert.doesNotMatch(value, /この端末を失効|revoke this device|device revoked/i, key);
    }
  }
});

test('credential facts are the recorded ones; no Tailscale identity or credential id is rendered', () => {
  const t = messages.ja;
  const inventory = parsePrincipals({ principals: [{ ...person({ credentials: [
    credential({ backup_eligible: false, backup_state: false, last_used_at: at }),
    { ...credential({ handle: '00000000-0000-4000-8000-00000000d002', label: null, status: 'inconsistent',
      inconsistency_reason: 'backup_eligibility_changed' }), credential_id: 'c3ludGhldGlj' },
  ] }), last_external_identity: 'synthetic-login@example.invalid' }] });
  const html = render(createElement(PersonCard, { t, person: inventory[0], disabled: false, confirming: null, setConfirming: noop, actions }));
  for (const value of [t.credentialDeviceBound, t.credentialNotBackedUp, t.credentialInconsistent, t.accessNoLabel,
    t.credentialStatus_inconsistent, '2026-10-22 01:02 UTC']) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /example\.invalid|c3ludGhldGlj|d00000000d00|00000000-0000-4000-8000-00000000d00/);
  assert.doesNotMatch(html, /tailscale/i);
});

test('an issued code is shown grouped with its expiry and hand-over guidance', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const html = render(createElement(InvitationCode, { t, issued: { name: '生成 閲覧者', principalId: personId, code: CODE, expires_at: at },
      copied: 'idle', onCopy: noop, onDismiss: noop }));
    assert.match(html, new RegExp(`<output class="code" data-invitation-code="true">${CODE}</output>`));
    for (const text of [t.invitationShownOnce, t.invitationHandOver, t.invitationCopy, t.invitationDismiss, '2026-10-22 01:02 UTC']) {
      assert.ok(html.includes(text), text);
    }
    assert.doesNotMatch(html, /<a |href=|download/);
  }
});

test('the step-up question is explicit and the screen is a placeholder without a provider', () => {
  const t = messages.ja;
  const prompt = render(createElement(StepUpPrompt, { t, onAnswer: noop }));
  assert.match(prompt, /role="alertdialog"/);
  assert.ok(prompt.includes(t.stepUpConfirm) && prompt.includes(t.cancel));
  const placeholder = render(createElement(AccessScreen, { services: { loadSession: async () => ({ state: 'denied' }) }, t }));
  assert.ok(placeholder.includes(t.foundation));
  const loading = render(createElement(AccessScreen, { services: { loadSession: async () => ({ state: 'denied' }),
    loadPrincipals: async () => [] }, t }));
  assert.ok(loading.includes(t.checking));
  assert.ok(loading.includes(t.accessTwoGates));
});
