import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/domain.ts', 'build/domain.mjs');
await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('src/views/timeline.tsx', 'build/timeline.mjs');
await compile('src/views/presence.tsx', 'build/presence.mjs');
const { canVisit, views } = await import('../build/domain.mjs');
const { messages } = await import('../build/i18n.mjs');
const { TimelineBody, detectorObservation, displayValue, filters, kindGroup, matches, spans } = await import('../build/timeline.mjs');
const { PresenceBody } = await import('../build/presence.mjs');

// Synthetic only: no real person, deployment, camera or identity value appears here.
const kinds = ['person', 'motion', 'owner_entry', 'owner_exit', 'anonymous_entry', 'anonymous_exit',
  'server_movement', 'camera_tamper', 'camera_health', 'node_health', 'recording', 'storage',
  'presence', 'configuration'];
let counter = 0;
const observation = (kind, overrides = {}) => ({
  id: `generated-observation-${counter += 1}`, kind, value: 'observed',
  occurred_at: '2026-09-21T09:00:00.000000+00:00', received_at: '2026-09-21T09:00:01.000000+00:00',
  source_id: '00000000-0000-4000-8000-00000000abcd', node_id: null, confidence: 0.8,
  quality: 'sufficient', clock_trusted: true, uncertainty_us: 0, confirmed: false,
  presence_state: null, sequence: counter, ...overrides,
});
const page = (items, overrides = {}) => ({
  items, ordering_basis: 'occurred_at', ordering_degraded: false,
  causality: 'not_inferred', next_sequence: items.length, ...overrides,
});
const snapshot = (overrides = {}) => ({
  state: 'UNKNOWN', basis: 'unknown', override_expires_at: null, clock_degraded: false,
  suppress_ordinary: false, critical_detection_armed: true, critical_evidence_armed: true,
  critical_notifications_armed: true, pending_critical_actions: 0, ...overrides,
});
const timeline = (value, locale = 'ja', filter = 'all') => renderToStaticMarkup(createElement(TimelineBody,
  { page: value, filter, t: messages[locale], onFilter: () => undefined }));
const presence = (report, locale = 'ja', extra = {}) => renderToStaticMarkup(createElement(PresenceBody,
  { report, t: messages[locale], ...extra }));

test('historical timeline follows recordings:view; presence stays owner-only', () => {
  assert.ok(views.includes('timeline') && views.includes('presence'));
  const owner = { state: 'allowed', role: 'owner', permissions: [] };
  assert.equal(canVisit(owner, 'timeline'), true);
  assert.equal(canVisit(owner, 'presence'), true);
  for (const permissions of [[], ['live:view'], ['recordings:view'], ['live:view', 'recordings:view']]) {
    const viewer = { state: 'allowed', role: 'viewer', permissions };
    assert.equal(canVisit(viewer, 'timeline'), permissions.includes('recordings:view'));
    assert.equal(canVisit(viewer, 'presence'), false);
  }
  for (const view of ['timeline', 'presence']) assert.equal(canVisit({ state: 'denied' }, view), false);
});

test('every observation kind reaches exactly one non-default filter', () => {
  assert.deepEqual(Object.keys(kindGroup).sort(), [...kinds].sort());
  for (const kind of kinds) {
    const selected = filters.filter(filter => filter !== 'all' && matches(filter, kind));
    assert.deepEqual(selected, [kindGroup[kind]]);
    assert.equal(matches('all', kind), true);
  }
});

test('kind filter renders only the selected group', () => {
  const items = kinds.map(kind => observation(kind));
  for (const filter of filters) {
    const markup = timeline(page(items), 'ja', filter);
    for (const kind of kinds) {
      assert.equal(markup.includes(`data-observation-kind="${kind}"`), matches(filter, kind));
    }
  }
  const critical = timeline(page(items), 'ja', 'critical');
  assert.equal((critical.match(/timeline-dot-critical/g) || []).length, 2);
  assert.match(critical, /観測数: 2/);
});

test('unreliable or unavailable results stay unknown instead of becoming a negative', () => {
  for (const quality of ['insufficient', 'unknown']) {
    const item = observation('person', { value: 'not_observed', quality, confidence: null });
    assert.equal(displayValue(item), 'unknown');
    const markup = timeline(page([item]));
    assert.match(markup, /判定できません/);
    assert.doesNotMatch(markup, /観測されず/);
    assert.match(markup, /確度: 不明/);
    assert.match(markup, /品質: (不十分|不明)/);
  }
  const reliable = observation('person', { value: 'not_observed', quality: 'sufficient' });
  assert.equal(displayValue(reliable), 'not_observed');
  assert.match(timeline(page([reliable])), /観測されず/);
  assert.equal(displayValue(observation('camera_health', { value: 'offline', quality: 'unknown' })), 'offline');
});

test('low-quality detector positives are not presented as factual results', () => {
  const detectors = kinds.filter(kind => detectorObservation(kind));
  assert.deepEqual(detectors, ['person', 'motion', 'owner_entry', 'owner_exit', 'anonymous_entry',
    'anonymous_exit', 'server_movement', 'camera_tamper']);
  for (const kind of detectors) {
    for (const quality of ['insufficient', 'unknown']) {
      const item = observation(kind, { value: 'observed', quality, confidence: 0.3 });
      assert.equal(displayValue(item), 'unknown');
      const markup = timeline(page([item]));
      assert.match(markup, /判定できません/);
      assert.doesNotMatch(markup, /: 検出/);
      // The observation itself stays visible with its kind, attribution and quality.
      assert.match(markup, new RegExp(`data-observation-kind="${kind}"`));
    }
    assert.equal(displayValue(observation(kind, { value: 'observed', quality: 'sufficient' })), 'observed');
  }
  // Status and configuration events are not image-quality gated; the value stands.
  for (const [kind, value] of [['camera_health', 'offline'], ['node_health', 'offline'],
    ['recording', 'failed'], ['storage', 'degraded'], ['presence', 'changed'], ['configuration', 'changed']]) {
    assert.equal(detectorObservation(kind), false);
    assert.equal(displayValue(observation(kind, { value, quality: 'unknown' })), value);
  }
});

test('ordering statement follows ordering_basis and the warning follows ordering_degraded', () => {
  const item = observation('motion', {
    occurred_at: '2026-09-21T09:00:00.000000+00:00', received_at: '2026-09-21T09:04:00.000000+00:00',
  });
  const received = timeline(page([item], { ordering_basis: 'received_at', ordering_degraded: false }));
  assert.match(received, /受信順で表示しています。/);
  assert.match(received, /<time[^>]*dateTime="2026-09-21T09:04:00.000000\+00:00"[^>]*>2026-09-21 09:04:00<\/time>/);
  assert.doesNotMatch(received, /<time[^>]*>2026-09-21 09:00:00<\/time>/);
  assert.doesNotMatch(received, /観測時刻順で表示しています。|時刻ずれまたは不連続が報告されています。/);
  const occurred = timeline(page([item], { ordering_basis: 'occurred_at', ordering_degraded: true }));
  assert.match(occurred, /観測時刻順で表示しています。/);
  assert.match(occurred, /<time[^>]*dateTime="2026-09-21T09:00:00.000000\+00:00"[^>]*>2026-09-21 09:00:00<\/time>/);
  assert.match(occurred, /時刻ずれまたは不連続が報告されています。/);
  assert.doesNotMatch(occurred, /受信順で表示しています。/);
  assert.doesNotMatch(timeline(page([item])), /時刻ずれまたは不連続が報告されています。/);
});

test('degraded timing is reported per span and never presented as ordering certainty', () => {
  const trusted = [observation('motion'), observation('motion')];
  const skewed = observation('motion', { clock_trusted: false, received_at: '2026-09-21T09:05:00.000000+00:00' });
  const uncertain = observation('motion', { uncertainty_us: 250000 });
  const items = [trusted[0], skewed, uncertain, trusted[1]];
  assert.deepEqual(spans(items).map(span => [span.degraded, span.items.length]),
    [[false, 1], [true, 2], [false, 1]]);
  const markup = timeline(page(items, { ordering_basis: 'received_at', ordering_degraded: true }));
  assert.equal((markup.match(/timeline-span-degraded/g) || []).length, 1);
  assert.equal((markup.match(/この区間は時刻の信頼性が低下しています/g) || []).length, 1);
  assert.match(markup, /受信順で表示しています/);
  assert.match(markup, /受信時刻: 2026-09-21 09:05:00/);
  assert.doesNotMatch(timeline(page(trusted)), /timeline-span-degraded|受信順で表示しています/);
});

test('timeline rows always carry source attribution plus confidence and quality', () => {
  const rows = [
    observation('person', { confidence: 0.42, quality: 'sufficient' }),
    observation('node_health', { value: 'offline', source_id: null, node_id: '00000000-0000-4000-8000-0000000012ef', confidence: null, quality: 'unknown' }),
    observation('configuration', { value: 'changed', source_id: null, confidence: null, quality: 'unknown' }),
  ];
  const markup = timeline(page(rows));
  assert.match(markup, /カメラ 00000000 · 検知器: 人物の観測/);
  assert.match(markup, /キャプチャノード 00000000 · 検知器: キャプチャノード状態の観測/);
  assert.match(markup, /メインサーバー · 検知器: 設定の更新/);
  assert.equal((markup.match(/確度:/g) || []).length, 3);
  assert.equal((markup.match(/品質:/g) || []).length, 3);
  assert.match(markup, /確度: 42%/);
  assert.match(markup, /確度は確実性ではありません。/);
  assert.match(timeline(page([]), 'en'), /Confidence is not certainty\./);
});

test('a quality-gated result is never labelled confirmed', () => {
  for (const kind of ['person', 'motion', 'owner_entry', 'server_movement', 'camera_tamper']) {
    for (const quality of ['insufficient', 'unknown']) {
      // The backend rejects this combination; the UI must not trust it either.
      const markup = timeline(page([observation(kind, { confirmed: true, quality, confidence: 0.9 })]));
      assert.match(markup, /判定できません/);
      assert.doesNotMatch(markup, /確認済み/);
    }
    assert.match(timeline(page([observation(kind, { confirmed: true, quality: 'sufficient' })])), /確認済み/);
  }
  const gatedNegative = observation('person', { confirmed: true, value: 'not_observed', quality: 'insufficient' });
  assert.doesNotMatch(timeline(page([gatedNegative])), /確認済み/);
  // Status events are not quality gated, so their confirmation still stands.
  assert.match(timeline(page([observation('recording', { value: 'failed', quality: 'unknown', confirmed: true })])), /確認済み/);
});

test('critical observations are visually distinguished without asserting a culprit', () => {
  const markup = timeline(page([observation('server_movement', { confirmed: true }),
    observation('camera_tamper', { confirmed: true })]));
  assert.equal((markup.match(/badge-critical/g) || []).length, 2);
  assert.equal((markup.match(/timeline-critical/g) || []).length, 2);
  assert.match(markup, /確認済み/);
});

test('neutral wording only: no culprit, attacker or cause claim in either locale', () => {
  const forbidden = [/犯人/, /加害者/, /容疑/, /不審/, /侵入者/, /のせい/, /culprit/i, /attacker/i, /suspect/i, /intruder/i, /blame/i];
  const everything = [timeline(page(kinds.map(kind => observation(kind))), 'ja'),
    timeline(page(kinds.map(kind => observation(kind))), 'en'),
    presence({ snapshot: snapshot(), transitions: [] }, 'ja'),
    presence({ snapshot: snapshot(), transitions: [] }, 'en'),
    JSON.stringify(messages)].join('\n');
  for (const pattern of forbidden) assert.doesNotMatch(everything, pattern);
});

test('presence shows state, basis and transitions; only PRESENT suppresses ordinary automation', () => {
  for (const state of ['PRESENT', 'PROBABLY_PRESENT', 'ABSENT', 'UNKNOWN']) {
    const markup = presence({
      snapshot: snapshot({ state, basis: 'owner_observation', suppress_ordinary: state === 'PRESENT' }),
      transitions: [{ at: '2026-09-21T08:00:00.000000+00:00', state, basis: 'owner_observation' }],
    });
    assert.match(markup, new RegExp(`presence-${state}`));
    assert.match(markup, /根拠: 管理者の入退室観測/);
    assert.match(markup, /2026-09-21 08:00:00/);
    // Critical work continues in every presence state.
    assert.match(markup, /サーバー移動・カメラ妨害の検知、証拠保護、critical 通知はすべての状態で継続します。/);
    assert.equal(/PRESENT のため通常の occupancy automation を抑制しています。/.test(markup), state === 'PRESENT');
    assert.equal(/PRESENT 以外のため通常の occupancy automation は抑制しません。/.test(markup), state !== 'PRESENT');
  }
  assert.match(presence({ snapshot: snapshot(), transitions: [] }), /本日の推移はありません。/);
});

test('manual override reports precedence, expiry and a cancel affordance', () => {
  const active = { snapshot: snapshot({ state: 'PRESENT', basis: 'manual_override', suppress_ordinary: true, override_expires_at: '2026-09-21T18:30:00.000000+00:00' }), transitions: [] };
  const wired = presence(active, 'ja', { onCancel: () => undefined });
  assert.match(wired, /手動上書きが有効です。/);
  assert.match(wired, /手動上書きは推定とスケジュールより優先します。/);
  assert.match(wired, /上書きの期限: 2026-09-21 18:30:00/);
  assert.match(wired, /<button[^>]*>手動上書きを取り消す<\/button>/);
  assert.doesNotMatch(wired, /<button[^>]*disabled/);
  const unwired = presence(active);
  assert.match(unwired, /<button[^>]*disabled/);
  const open = presence({ snapshot: snapshot({ basis: 'manual_override' }), transitions: [] }, 'ja', { onCancel: () => undefined });
  assert.match(open, /期限なし（取り消すまで有効）/);
  assert.match(presence({ snapshot: snapshot(), transitions: [] }), /手動上書きはありません。/);
});

test('an unarmed critical protection replaces the continuity statement with an alert', () => {
  for (const flag of ['critical_detection_armed', 'critical_evidence_armed', 'critical_notifications_armed']) {
    const markup = presence({ snapshot: snapshot({ [flag]: false }), transitions: [] });
    assert.doesNotMatch(markup, /すべての状態で継続します。/);
    assert.match(markup, /<p class="timeline-degraded" role="alert">critical 対応の一部が継続中であると確認できていません。/);
    assert.match(markup, /未確認/);
  }
});

test('degraded clock and pending critical work stay visible on presence', () => {
  const markup = presence({ snapshot: snapshot({ clock_degraded: true, pending_critical_actions: 2 }), transitions: [] });
  assert.match(markup, /時刻の信頼性が低下しています。状態の根拠と手動上書きを確認してください。/);
  assert.match(markup, /未完了の critical 対応: 2/);
  assert.doesNotMatch(presence({ snapshot: snapshot(), transitions: [] }), /未完了の critical 対応/);
});

test('degraded timing preserves a manual override state without claiming it became unknown', () => {
  const markup = presence({ snapshot: snapshot({
    state: 'PRESENT', basis: 'manual_override', suppress_ordinary: true, clock_degraded: true,
  }), transitions: [] });
  assert.match(markup, /presence-PRESENT/);
  assert.match(markup, /手動上書きが有効です。/);
  assert.match(markup, /時刻の信頼性が低下しています。状態の根拠と手動上書きを確認してください。/);
  assert.doesNotMatch(markup, /状態は不明側に倒して表示します。/);
});
