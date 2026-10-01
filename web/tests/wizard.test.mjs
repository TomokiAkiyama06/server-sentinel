import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/domain.ts', 'build/domain.mjs');
await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('src/setup/wizard.tsx', 'build/wizard-view.mjs');
const {
  canVisit, currentWizardStep, deniedServices, optionalWizardSteps, parseWizard, wizardDeploymentReady, wizardSteps,
} = await import('../build/domain.mjs');
const { messages } = await import('../build/i18n.mjs');
const { WizardView } = await import('../build/wizard-view.mjs');

const serverOrder = ['welcome', 'deployment_owner', 'storage', 'hardware_and_recorder', 'locale_and_time',
  'camera_sources', 'detection_profiles', 'owner_verification', 'slack', 'human_remote_access'];
const snapshot = (statuses = {}) => ({
  states: serverOrder.map(step => ({ step, status: statuses[step] ?? 'pending', revision: statuses[step] ? 1 : 0 })),
});
const transition = () => assert.fail('render must not transition');
const markup = (value, extra = {}, locale = 'ja') =>
  renderToStaticMarkup(createElement(WizardView, { t: messages[locale], snapshot: value, ...extra }));
const actions = html => [...html.matchAll(/data-wizard-action="([a-z]+)"/g)].map(match => match[1]);

test('wizard steps follow the documented server order and only optional steps are skippable', () => {
  assert.deepEqual([...wizardSteps], serverOrder);
  assert.deepEqual([...optionalWizardSteps], ['owner_verification', 'slack', 'human_remote_access']);
  const html = markup(snapshot());
  const positions = serverOrder.map(step => html.indexOf(`data-wizard-step="${step}"`));
  assert.ok(positions.every(position => position >= 0));
  assert.deepEqual([...positions].sort((a, b) => a - b), positions);
  // Every step's localized title and explanation exists in both catalogs.
  for (const locale of ['ja', 'en']) {
    for (const step of serverOrder) {
      assert.equal(typeof messages[locale][`wizardStep_${step}`], 'string');
      assert.equal(typeof messages[locale][`wizardStepHint_${step}`], 'string');
    }
  }
});

test('only the current step offers forward actions, and the shell completes only Welcome', () => {
  let html = markup(snapshot(), { onTransition: transition });
  assert.deepEqual(actions(html), ['completed']);
  assert.match(html, /data-wizard-step="welcome"[^>]*aria-current="step"/);

  html = markup(snapshot({ welcome: 'completed' }), { onTransition: transition });
  assert.match(html, /data-wizard-step="deployment_owner"[^>]*aria-current="step"/);
  // A required integration step can be deferred, never completed or skipped here.
  assert.deepEqual(actions(html), ['unavailable']);

  const required = Object.fromEntries(serverOrder.slice(0, 7).map(step => [step, 'unavailable']));
  html = markup(snapshot({ ...required, welcome: 'completed' }), { onTransition: transition });
  assert.match(html, /data-wizard-step="owner_verification"[^>]*aria-current="step"/);
  // Optional current step: defer or skip; every deferred step offers a retry.
  assert.deepEqual(actions(html).filter(action => action !== 'pending'), ['unavailable', 'skipped']);
  assert.equal(actions(html).filter(action => action === 'pending').length, 6);
});

test('pending, unavailable and skipped are never shown as completed', () => {
  const value = snapshot({ welcome: 'completed', deployment_owner: 'unavailable', storage: 'unavailable',
    hardware_and_recorder: 'unavailable', locale_and_time: 'unavailable', camera_sources: 'unavailable',
    detection_profiles: 'unavailable', owner_verification: 'skipped', slack: 'skipped', human_remote_access: 'skipped' });
  assert.equal(currentWizardStep(value), null);
  assert.equal(wizardDeploymentReady(value), false);
  const html = markup(value);
  assert.match(html, /data-wizard-ready="false"/);
  assert.equal(html.includes(messages.ja.wizardReady), false);
  assert.ok(html.includes(messages.ja.wizardNotReady));
  assert.equal((html.match(/data-wizard-status="completed"/g) ?? []).length, 1);
  assert.equal((html.match(new RegExp(`>${messages.ja.wizardStatus_completed}<`, 'g')) ?? []).length, 1);
  for (const status of ['pending', 'unavailable', 'skipped']) {
    assert.notEqual(messages.ja[`wizardStatus_${status}`], messages.ja.wizardStatus_completed);
  }

  const fresh = markup(snapshot());
  assert.match(fresh, /data-wizard-ready="false"/);
  assert.equal((fresh.match(/data-wizard-status="completed"/g) ?? []).length, 0);

  // Readiness needs every required step completed; optional ones may be skipped.
  const done = Object.fromEntries(serverOrder.slice(0, 7).map(step => [step, 'completed']));
  assert.equal(wizardDeploymentReady(snapshot({ ...done, owner_verification: 'skipped', slack: 'skipped' })), true);
  assert.equal(wizardDeploymentReady(snapshot({ ...done, camera_sources: 'unavailable' })), false);
});

test('Owner controls are hidden without an authorized provider and from viewers', () => {
  for (const html of [markup(snapshot()), markup(snapshot({ welcome: 'completed', deployment_owner: 'unavailable' }))]) {
    assert.deepEqual(actions(html), []);
    assert.doesNotMatch(html, /<button/);
    assert.match(html, /data-wizard-readonly="true"/);
  }
  for (const permissions of [[], ['live:view'], ['recordings:view'], ['live:view', 'recordings:view']]) {
    assert.equal(canVisit({ state: 'allowed', role: 'viewer', permissions }, 'setup'), false);
  }
  assert.equal(canVisit({ state: 'denied' }, 'setup'), false);
  assert.equal(canVisit({ state: 'allowed', role: 'owner', permissions: [] }, 'setup'), true);
  for (const name of ['loadWizard', 'transitionWizard']) assert.equal(name in deniedServices, false);
});

test('private access keeps Tailnet approval and ServerSentinel invitation as separate conditions', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const html = markup(snapshot(), {}, locale);
    const network = html.indexOf('data-access-gate="network"');
    const application = html.indexOf('data-access-gate="application"');
    assert.ok(network > 0 && application > network);
    assert.ok(html.includes(t.accessGateNetwork) && html.includes(t.accessGateApplication));
    assert.ok(html.includes(t.accessGateIndependent));
    assert.ok(html.includes(t.accessGateNoTailscaleAdmin));
    // The application gate names both permissions independently.
    assert.match(t.accessGateApplication, /live:view/);
    assert.match(t.accessGateApplication, /recordings:view/);
    // Nothing says Tailnet membership grants access by itself.
    const all = Object.values(t).join('\n');
    assert.doesNotMatch(all, /Tailnet (membership )?(grants|allows|is enough)|Tailnet に参加すれば/);
  }
  assert.match(messages.ja.accessGateIndependent, /Tailnet に参加しているだけでは ServerSentinel にアクセスできません/);
  assert.match(messages.en.accessGateIndependent, /alone never grants access/);
});

test('Welcome explains self-hosted, video-only, source and viewer scope', () => {
  const html = markup(snapshot());
  for (const key of ['welcomeSelfHosted', 'welcomeVideoOnly', 'welcomeSources', 'welcomeViewers', 'welcomeNoNativeApp']) {
    assert.ok(html.includes(messages.ja[key]), key);
  }
});

test('no setting, secret, identifier or revision value from a provider is rendered', () => {
  const marker = 'SYNTHETIC_SECRET_SERIAL_BIOMETRIC';
  const raw = {
    secret: marker, webhook: marker,
    states: serverOrder.map(step => ({ step, status: 'pending', revision: 987654321, setting: marker, serial: marker })),
  };
  const parsed = parseWizard(raw);
  assert.equal(JSON.stringify(parsed).includes(marker), false);
  for (const state of parsed.states) assert.deepEqual(Object.keys(state).sort(), ['revision', 'status', 'step']);
  const html = markup(parsed, { onTransition: transition });
  assert.equal(html.includes(marker), false);
  assert.equal(html.includes('987654321'), false);
});

test('an out-of-order, incomplete or invalid snapshot fails closed', () => {
  const valid = snapshot();
  const cases = [
    null, {}, { states: valid.states.slice(1) },
    { states: [valid.states[1], valid.states[0], ...valid.states.slice(2)] },
    { states: valid.states.map((state, index) => index === 0 ? { ...state, status: 'done' } : state) },
    { states: valid.states.map((state, index) => index === 0 ? { ...state, revision: -1 } : state) },
    { states: valid.states.map((state, index) => index === 0 ? { ...state, revision: '0' } : state) },
    // A required step can never be reported as skipped.
    { states: valid.states.map((state, index) => index === 2 ? { ...state, status: 'skipped' } : state) },
  ];
  for (const value of cases) assert.throws(() => parseWizard(value));
  assert.deepEqual(parseWizard(valid), valid);
});

test('a failed transition is reported and controls are disabled while one is in flight', () => {
  const failed = markup(snapshot(), { onTransition: transition, failed: true });
  assert.match(failed, /data-wizard-failed="true"/);
  assert.ok(failed.includes(messages.ja.wizardActionFailed));
  const busy = markup(snapshot(), { onTransition: transition, busy: true });
  assert.match(busy, /<button[^>]*disabled=""[^>]*data-wizard-action="completed"/);
});
