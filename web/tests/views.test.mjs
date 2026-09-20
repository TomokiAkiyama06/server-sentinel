import test, { mock } from 'node:test';
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
const { TimelineBody, cursorAdvanced, detectorObservation, displayValue, filters, kindGroup, matches, spans } = await import('../build/timeline.mjs');
const { PresenceBody, refreshDelay, scheduleExpiryRefresh } = await import('../build/presence.mjs');

// Synthetic only: no real person, deployment, camera or identity value appears here.
const kinds = ['person', 'motion', 'owner_entry', 'owner_exit', 'anonymous_entry', 'anonymous_exit',
  'server_movement', 'camera_tamper', 'camera_health', 'node_health', 'recording', 'storage',
  'presence', 'configuration'];
// Mirrors the backend enumerations the timeline projects.
const values = ['observed', 'not_observed', 'unknown', 'online', 'offline', 'degraded',
  'manual_intervention_required', 'revoked', 'ready', 'failed', 'created', 'deleted', 'changed'];
const qualities = ['sufficient', 'degraded', 'insufficient', 'unknown'];
const states = ['PRESENT', 'PROBABLY_PRESENT', 'ABSENT', 'UNKNOWN'];
const bases = ['manual_override', 'owner_observation', 'hint', 'unknown'];
const actions = ['override_set', 'override_cancelled', 'override_expired', 'hint_set',
  'critical_action_requeued', 'critical_degradation_cleared'];
let counter = 0;
const observation = (kind, overrides = {}) => ({
  id: `generated-observation-${counter += 1}`, kind, value: 'observed',
  occurred_at: '2026-09-21T09:00:00.000000+00:00', received_at: '2026-09-21T09:00:01.000000+00:00',
  source_id: '00000000-0000-4000-8000-00000000abcd', node_id: null, confidence: 0.8,
  quality: 'sufficient', clock_trusted: true, uncertainty_us: 0, confirmed: false,
  presence_state: null, sequence: counter, ...overrides,
});
const page = (items, overrides = {}) => ({
  items, ordering_basis: 'received_at', ordering_degraded: false, causality: 'not_inferred',
  next_cursor: items.length
    ? { received_at: items[items.length - 1].received_at, sequence: items[items.length - 1].sequence }
    : null,
  ...overrides,
});
const paths = ['critical_detection', 'critical_persistence', 'critical_evidence', 'critical_notifications'];
const snapshot = (overrides = {}) => ({
  state: 'UNKNOWN', basis: 'unknown', override_expires_at: null, clock_degraded: false,
  observation_clock_degraded: false, suppress_ordinary: false, critical_detection: 'armed', critical_persistence: 'armed',
  critical_evidence: 'armed', critical_notifications: 'armed', critical_paths_degraded: false,
  override_expiry_pending: false, pending_critical_actions: 0, ...overrides,
});
// The backend suppresses ordinary automation only for a trusted PRESENT.
const reported = (state, clockDegraded = false) => snapshot({
  state, clock_degraded: clockDegraded, suppress_ordinary: state === 'PRESENT' && !clockDegraded,
});
const timeline = (value, locale = 'ja', filter = 'all', extra = {}) => renderToStaticMarkup(createElement(TimelineBody,
  { page: value, filter, t: messages[locale], onFilter: () => undefined, ...extra }));
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

test('rows are ordered by receipt and still carry their own observation time', () => {
  const item = observation('motion', {
    occurred_at: '2026-09-21T09:00:00.000000+00:00', received_at: '2026-09-21T09:04:00.000000+00:00',
  });
  const markup = timeline(page([item]));
  assert.match(markup, /メインサーバーの受信順で表示しています。/);
  assert.match(markup, /<time[^>]*dateTime="2026-09-21T09:04:00.000000\+00:00"[^>]*>2026-09-21 09:04:00<\/time>/);
  assert.match(markup, /観測時刻: 2026-09-21 09:00:00/);
  assert.doesNotMatch(markup, /時刻ずれまたは不連続が報告されています。/);
  const degraded = timeline(page([item], { ordering_degraded: true }));
  assert.match(degraded, /メインサーバーの受信順で表示しています。/);
  assert.match(degraded, /時刻ずれまたは不連続が報告されています。/);
  assert.equal(page([item]).next_cursor.sequence, item.sequence);
  assert.equal(page([]).next_cursor, null);
});

test('older history stays reachable while a cursor is offered', () => {
  const items = [observation('motion'), observation('person')];
  const offered = timeline(page(items), 'ja', 'all', { onMore: () => undefined, complete: false });
  assert.match(offered, /<button[^>]*>古い観測をさらに読み込む<\/button>/);
  assert.doesNotMatch(offered, /この期間の観測をすべて読み込みました。/);
  const loading = timeline(page(items), 'ja', 'all', { onMore: () => undefined, loadingMore: true });
  assert.match(loading, /<button[^>]*disabled[^>]*>読み込んでいます<\/button>/);
  // A failed page keeps the loaded history and the retry path.
  const failedMore = timeline(page(items), 'ja', 'all', { onMore: () => undefined, moreFailed: true });
  assert.match(failedMore, /<p role="alert">古い観測を読み込めませんでした。/);
  assert.match(failedMore, /<button[^>]*>古い観測をさらに読み込む<\/button>/);
  assert.equal((failedMore.match(/data-observation-kind=/g) || []).length, items.length);
  const exhausted = timeline(page(items, { next_cursor: null }), 'ja', 'all', { complete: true });
  assert.doesNotMatch(exhausted, /古い観測をさらに読み込む/);
  assert.match(exhausted, /この期間の観測をすべて読み込みました。/);
  // Without a provider there is no load-more affordance at all.
  assert.doesNotMatch(timeline(page(items)), /古い観測をさらに読み込む/);
});

test('paging continues while the cursor advances, including over an empty page', () => {
  const sent = { received_at: '2026-09-21T09:00:01.000000+00:00', sequence: 4 };
  // An empty intermediate page that still moves the cursor keeps older history reachable.
  assert.equal(cursorAdvanced(sent, { received_at: '2026-09-21T09:30:00.000000+00:00', sequence: 9 }), true);
  assert.equal(cursorAdvanced(sent, { received_at: sent.received_at, sequence: 9 }), true);
  // The core echoes the cursor it was given when it has no rows: that ends paging.
  assert.equal(cursorAdvanced(sent, { ...sent }), false);
  assert.equal(cursorAdvanced(sent, null), false);
  assert.equal(cursorAdvanced(null, null), false);
  assert.equal(cursorAdvanced(null, sent), true);
});

test('degraded timing is reported per span and never presented as ordering certainty', () => {
  const trusted = [observation('motion'), observation('motion')];
  const skewed = observation('motion', { clock_trusted: false, received_at: '2026-09-21T09:05:00.000000+00:00' });
  const uncertain = observation('motion', { uncertainty_us: 250000 });
  const items = [trusted[0], skewed, uncertain, trusted[1]];
  assert.deepEqual(spans(items).map(span => [span.degraded, span.items.length]),
    [[false, 1], [true, 2], [false, 1]]);
  const markup = timeline(page(items, { ordering_degraded: true }));
  assert.equal((markup.match(/timeline-span-degraded/g) || []).length, 1);
  assert.equal((markup.match(/この区間は時刻の信頼性が低下しています/g) || []).length, 1);
  assert.match(markup, /時刻ずれまたは不連続が報告されています/);
  assert.match(markup, />2026-09-21 09:05:00</);
  assert.doesNotMatch(timeline(page(trusted)), /timeline-span-degraded|時刻ずれまたは不連続が報告されています/);
});

test('timeline rows always carry source attribution plus confidence and quality', () => {
  const rows = [
    observation('person', { confidence: 0.42, quality: 'sufficient' }),
    observation('node_health', { value: 'offline', source_id: null, node_id: '00000000-0000-4000-8000-0000000012ef', confidence: null, quality: 'unknown' }),
    observation('configuration', { value: 'changed', source_id: null, confidence: null, quality: 'unknown' }),
  ];
  const markup = timeline(page(rows));
  assert.match(markup, /カメラ 00000000 · 検知器: 人物の観測/);
  // A status or control event is not attributed to a detector.
  assert.match(markup, /キャプチャノード 00000000 · 種別: キャプチャノード状態の観測/);
  assert.match(markup, /メインサーバー · 種別: 設定の更新/);
  for (const kind of kinds) {
    const row = timeline(page([observation(kind)]));
    assert.equal(/· 検知器: /.test(row), detectorObservation(kind), kind);
    assert.equal(/· 種別: /.test(row), !detectorObservation(kind), kind);
  }
  assert.equal((markup.match(/確度:/g) || []).length, 3);
  assert.equal((markup.match(/品質:/g) || []).length, 3);
  assert.match(markup, /確度: 42%/);
  assert.match(markup, /確度は確実性ではありません。/);
  assert.match(timeline(page([]), 'en'), /Confidence is not certainty\./);
});

test('every projected kind, value, quality, state and basis has a label in both locales', () => {
  const required = [...kinds.map(kind => `kind_${kind}`), ...values.map(value => `value_${value}`),
    ...qualities.map(quality => `quality_${quality}`), ...states.map(state => `state_${state}`),
    ...bases.map(basis => `basis_${basis}`),
    ...['armed', 'unavailable', 'unknown'].map(path => `path_${path}`),
    ...actions.map(action => `action_${action}`)];
  for (const locale of ['ja', 'en']) {
    for (const key of required) {
      assert.equal(typeof messages[locale][key], 'string', `${locale} is missing ${key}`);
      assert.ok(messages[locale][key].length > 0, `${locale} has an empty ${key}`);
    }
  }
});

test('health transitions and degraded detector quality render without a blank value', () => {
  const rows = [
    observation('camera_health', { value: 'manual_intervention_required', quality: 'unknown', confidence: null }),
    observation('node_health', { value: 'revoked', quality: 'unknown', confidence: null, source_id: null, node_id: '00000000-0000-4000-8000-0000000012ef' }),
  ];
  const markup = timeline(page(rows));
  assert.match(markup, /カメラ状態の観測: 管理者の確認が必要な状態を観測/);
  assert.match(markup, /キャプチャノード状態の観測: 失効を観測/);
  assert.doesNotMatch(markup, /観測: <\/p>|観測: <span/);
  assert.match(timeline(page(rows), 'en'), /Owner intervention required observed/);
  assert.match(timeline(page(rows), 'en'), /Revocation observed/);
  // Degraded detector quality is a real contract value and still fails to unknown.
  for (const kind of kinds.filter(name => detectorObservation(name))) {
    assert.equal(displayValue(observation(kind, { value: 'observed', quality: 'degraded' })), 'unknown');
  }
  const degraded = timeline(page([observation('person', { value: 'observed', quality: 'degraded' })]));
  assert.match(degraded, /判定できません/);
  assert.match(degraded, /品質: 低下/);
  assert.doesNotMatch(degraded, /確認済み/);
  assert.equal(displayValue(observation('storage', { value: 'degraded', quality: 'degraded' })), 'degraded');
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
  // The core confirms only a quality-sufficient positive carrying a confidence.
  for (const overrides of [{ value: 'unknown' }, { value: 'not_observed' }, { quality: 'unknown' }, { confidence: null }]) {
    const item = observation('camera_tamper', { confirmed: true, ...overrides });
    assert.doesNotMatch(timeline(page([item])), /確認済み/, JSON.stringify(overrides));
  }
  assert.match(timeline(page([observation('camera_tamper', { confirmed: true })])), /確認済み/);
  // A status event is not quality gated, but confirmation still needs its prerequisites.
  assert.match(timeline(page([observation('recording', { confirmed: true })])), /確認済み/);
  assert.doesNotMatch(timeline(page([observation('recording', { value: 'failed', quality: 'unknown', confirmed: true })])), /確認済み/);
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
    presence({ snapshot: snapshot(), audit: [] }, 'ja'),
    presence({ snapshot: snapshot(), audit: [] }, 'en'),
    JSON.stringify(messages)].join('\n');
  for (const pattern of forbidden) assert.doesNotMatch(everything, pattern);
});

test('presence shows state, basis and the owner control history', () => {
  for (const state of states) {
    const markup = presence({
      snapshot: { ...reported(state), basis: 'owner_observation' },
      audit: [{ sequence: 1, action: 'override_cancelled', at: '2026-09-21T08:00:00.000000+00:00', state }],
    });
    assert.match(markup, new RegExp(`presence-${state}`));
    assert.match(markup, /根拠: 管理者の入退室観測/);
    assert.match(markup, /2026-09-21 08:00:00/);
    assert.match(markup, /手動上書きを取り消し/);
    assert.match(markup, /data-control-action="override_cancelled"/);
    // Critical work continues in every presence state.
    assert.match(markup, /サーバー移動・カメラ妨害の検知、記録、証拠保護、critical 通知はすべての presence state で継続します。/);
    assert.equal(/PRESENT かつ時刻が信頼できるため、通常の occupancy automation を抑制しています。/.test(markup), state === 'PRESENT');
    assert.equal(/PRESENT 以外のため通常の occupancy automation は抑制しません。/.test(markup), state !== 'PRESENT');
  }
  for (const action of actions) {
    const markup = presence({ snapshot: snapshot(), audit: [{ sequence: 2, action, at: '2026-09-21T08:00:00.000000+00:00', state: null }] });
    assert.match(markup, new RegExp(`data-control-action="${action}"`));
  }
  assert.match(presence({ snapshot: snapshot(), audit: [] }), /記録された管理者の操作はありません。/);
});

test('owner critical recovery actions explain what happened in the control history', () => {
  const entry = (action, locale) => presence({
    snapshot: snapshot(),
    audit: [{ sequence: 3, action, at: '2026-09-21T08:15:00.000000+00:00', state: null }],
  }, locale);
  const requeued = entry('critical_action_requeued', 'ja');
  assert.match(requeued, /未完了の critical 対応を再投入（管理者承認）/);
  assert.match(requeued, /重複する可能性を管理者が承知のうえで再投入しました。/);
  assert.doesNotMatch(requeued, /ServerSentinel 外で対応済み/);
  const cleared = entry('critical_degradation_cleared', 'ja');
  assert.match(cleared, /期限切れの critical 未完了マーカーを解除（管理者確認）/);
  assert.match(cleared, /ServerSentinel 外で対応済みと管理者が確認し、劣化表示を解除しました。/);
  assert.match(entry('critical_action_requeued', 'en'), /may be duplicated/);
  assert.match(entry('critical_degradation_cleared', 'en'), /handled outside ServerSentinel/);
  // Ordinary override actions carry no critical-recovery note.
  assert.doesNotMatch(entry('override_set', 'ja'), /再投入しました。|劣化表示を解除しました。/);
});

test('manual override reports precedence, expiry and a cancel affordance', () => {
  const active = { snapshot: snapshot({ state: 'PRESENT', basis: 'manual_override', suppress_ordinary: true, override_expires_at: '2026-09-21T18:30:00.000000+00:00' }), audit: [] };
  const wired = presence(active, 'ja', { onCancel: () => undefined });
  assert.match(wired, /手動上書きが有効です。/);
  assert.match(wired, /手動上書きは推定とスケジュールより優先します。/);
  assert.match(wired, /上書きの期限: 2026-09-21 18:30:00/);
  assert.match(wired, /<button[^>]*>手動上書きを取り消す<\/button>/);
  assert.doesNotMatch(wired, /<button[^>]*disabled/);
  const unwired = presence(active);
  assert.match(unwired, /<button[^>]*disabled/);
  const open = presence({ snapshot: snapshot({ basis: 'manual_override' }), audit: [] }, 'ja', { onCancel: () => undefined });
  assert.match(open, /期限なし（取り消すまで有効）/);
  assert.match(presence({ snapshot: snapshot(), audit: [] }), /手動上書きはありません。/);
});

test('suppression is judged against the state and clock trust, not the state alone', () => {
  for (const state of states) {
    for (const clockDegraded of [false, true]) {
      // Combinations the core can actually report never raise the alert.
      const agreed = presence({ snapshot: reported(state, clockDegraded), audit: [] });
      assert.doesNotMatch(agreed, /一致していません/);
      assert.equal(/PRESENT かつ時刻が信頼できるため、通常の occupancy automation を抑制しています。/.test(agreed),
        state === 'PRESENT' && !clockDegraded);
      assert.equal(/PRESENT ですが時刻の信頼性が低下しているため、通常の occupancy automation は抑制しません。/.test(agreed),
        state === 'PRESENT' && clockDegraded);
      // An inconsistent report is surfaced instead of a contradictory sentence.
      const inconsistent = reported(state, clockDegraded);
      const mismatch = presence({ snapshot: { ...inconsistent, suppress_ordinary: !inconsistent.suppress_ordinary }, audit: [] });
      assert.match(mismatch, /<p class="timeline-degraded" role="alert">報告された抑制状態が、presence state と時刻の信頼性から導かれる状態と一致していません。/);
      assert.doesNotMatch(mismatch, /通常の occupancy automation を抑制しています。/);
      assert.doesNotMatch(mismatch, /通常の occupancy automation は抑制しません。/);
      assert.match(mismatch, inconsistent.suppress_ordinary ? /報告された抑制状態: 抑制なし/ : /報告された抑制状態: 抑制あり/);
    }
  }
});

test('a critical path that is not armed replaces the continuity statement with an alert', () => {
  for (const path of paths) {
    for (const state of ['unavailable', 'unknown']) {
      const markup = presence({ snapshot: snapshot({ [path]: state, critical_paths_degraded: true }), audit: [] });
      assert.doesNotMatch(markup, /すべての presence state で継続します。/);
      assert.match(markup, /<p class="timeline-degraded" role="alert">critical 対応の経路に armed でないものがあります。/);
      // A known failure and an unreported path are never merged into one label.
      assert.match(markup, state === 'unavailable' ? /unavailable（既知の異常）/ : /unknown（未報告）/);
      assert.doesNotMatch(markup, state === 'unavailable' ? /unknown（未報告）/ : /unavailable（既知の異常）/);
    }
  }
  // The aggregate degraded flag alone also withdraws the continuity claim.
  const degraded = presence({ snapshot: snapshot({ critical_paths_degraded: true }), audit: [] });
  assert.doesNotMatch(degraded, /すべての presence state で継続します。/);
  // Aggregate degradation with every path armed gets its own wording.
  const aggregate = presence({ snapshot: snapshot({ critical_paths_degraded: true }), audit: [] });
  assert.match(aggregate, /<p class="timeline-degraded" role="alert">各経路は armed と報告されていますが、critical 対応全体として劣化が報告されています。/);
  assert.doesNotMatch(aggregate, /critical 対応の経路に armed でないものがあります。/);
  const armed = presence({ snapshot: snapshot(), audit: [] });
  assert.match(armed, /すべての presence state で継続します。/);
  assert.equal((armed.match(/armed（継続中）/g) || []).length, 4);
});

test('an incomplete override expiry is reported instead of a silently active override', () => {
  const markup = presence({ snapshot: snapshot({ basis: 'manual_override', override_expiry_pending: true,
    override_expires_at: '2026-09-21T07:00:00.000000+00:00' }), audit: [] });
  assert.match(markup, /<p class="timeline-degraded" role="alert">手動上書きの期限切れ処理が完了していません。/);
  assert.doesNotMatch(presence({ snapshot: snapshot({ basis: 'manual_override' }), audit: [] }), /期限切れ処理が完了していません/);
});

test('presence offers a refresh path and serializes override cancellation', () => {
  const active = { snapshot: snapshot({ basis: 'manual_override' }), audit: [] };
  const idle = presence(active, 'ja', { onCancel: () => undefined, onRefresh: () => undefined, fetchedAt: '2026-09-21T09:30:00.000000+00:00' });
  assert.match(idle, /<button[^>]*>最新の状態を取得<\/button>/);
  assert.match(idle, /取得時刻: 2026-09-21 09:30:00/);
  assert.match(idle, /<button[^>]*>手動上書きを取り消す<\/button>/);
  // While a cancellation is in flight neither control can be triggered again.
  const pending = presence(active, 'ja', { onCancel: () => undefined, onRefresh: () => undefined, cancelling: true });
  assert.match(pending, /<button[^>]*disabled[^>]*>取り消しています<\/button>/);
  assert.match(pending, /<button[^>]*disabled[^>]*>最新の状態を取得<\/button>/);
  assert.doesNotMatch(pending, />手動上書きを取り消す</);
  // A failed refresh keeps the last known status and the retry control.
  const stale = presence(active, 'ja', { onRefresh: () => undefined, refreshFailed: true,
    fetchedAt: '2026-09-21T09:30:00.000000+00:00' });
  assert.match(stale, /<p role="alert">最新の状態を取得できませんでした。/);
  assert.match(stale, /<button[^>]*>最新の状態を取得<\/button>/);
  assert.match(stale, /取得時刻: 2026-09-21 09:30:00/);
  assert.match(stale, /手動上書きが有効です。/);
  // Without providers neither affordance appears as usable.
  const plain = presence(active, 'ja');
  assert.doesNotMatch(plain, /最新の状態を取得/);
  assert.doesNotMatch(plain, /取得時刻/);
  assert.match(plain, /<button[^>]*disabled/);
});

test('only a future override expiry schedules a refresh', () => {
  const now = Date.parse('2026-09-21T09:00:00.000Z');
  assert.equal(refreshDelay(null, now), null);
  // An expiry the core still reports after it passed must not loop refreshes.
  assert.equal(refreshDelay('2026-09-21T08:59:59.000000+00:00', now), null);
  assert.equal(refreshDelay('2026-09-21T09:00:00.000000+00:00', now), null);
  assert.equal(refreshDelay('not a timestamp', now), null);
  assert.equal(refreshDelay('2026-09-21T09:00:30.000000+00:00', now), 31000);
  // Long-lived overrides re-read at most hourly.
  assert.equal(refreshDelay('2026-09-22T09:00:00.000000+00:00', now), 3600000);
});

test('basis timing and observation timing are reported as separate facts', () => {
  const basisOnly = presence({ snapshot: snapshot({ clock_degraded: true }), audit: [] });
  assert.match(basisOnly, /現在の状態の根拠となる記録の時刻信頼性が低下しています。/);
  assert.doesNotMatch(basisOnly, /観測の受信時刻に skew/);
  const observationOnly = presence({ snapshot: snapshot({ observation_clock_degraded: true }), audit: [] });
  assert.match(observationOnly, /観測の受信時刻に skew または不連続が報告されています。/);
  assert.doesNotMatch(observationOnly, /現在の状態の根拠となる記録の時刻信頼性/);
  const both = presence({ snapshot: snapshot({ clock_degraded: true, observation_clock_degraded: true }), audit: [] });
  assert.match(both, /現在の状態の根拠となる記録の時刻信頼性/);
  assert.match(both, /観測の受信時刻に skew/);
  const neither = presence({ snapshot: snapshot(), audit: [] });
  assert.doesNotMatch(neither, /時刻信頼性が低下|観測の受信時刻に skew/);
  // A skewed observation clock never blocks an accepted Owner override.
  const override = presence({ snapshot: snapshot({ state: 'PRESENT', basis: 'manual_override',
    suppress_ordinary: true, observation_clock_degraded: true }), audit: [] });
  assert.doesNotMatch(override, /一致していません/);
  assert.match(override, /PRESENT かつ時刻が信頼できるため、通常の occupancy automation を抑制しています。/);
});

test('a clamped expiry re-arms until the override actually expires', () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    let refreshes = 0;
    let current = Date.parse('2026-09-21T09:00:00.000Z');
    const tick = milliseconds => { current += milliseconds; mock.timers.tick(milliseconds); };
    // An override three hours out is checked hourly, then once at its expiry.
    const stop = scheduleExpiryRefresh('2026-09-21T12:00:30.000000+00:00',
      () => { refreshes += 1; }, () => false, () => current);
    for (const expected of [1, 2, 3]) {
      tick(3600000);
      assert.equal(refreshes, expected);
    }
    tick(31000);
    assert.equal(refreshes, 4);
    // Once the expiry has passed nothing is scheduled again.
    tick(3600000 * 5);
    assert.equal(refreshes, 4);
    stop();
  } finally { mock.timers.reset(); }
});

test('an expiry check defers while an audited control operation is in flight', () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    let refreshes = 0;
    let busy = true;
    let current = Date.parse('2026-09-21T09:00:00.000Z');
    const tick = milliseconds => { current += milliseconds; mock.timers.tick(milliseconds); };
    const stop = scheduleExpiryRefresh('2026-09-21T09:00:30.000000+00:00',
      () => { refreshes += 1; }, () => busy, () => current);
    tick(31000);
    assert.equal(refreshes, 0);
    tick(5000);
    assert.equal(refreshes, 0);
    busy = false;
    tick(1000);
    assert.equal(refreshes, 1);
    stop();
  } finally { mock.timers.reset(); }
});

test('degraded clock and pending critical work stay visible on presence', () => {
  const markup = presence({ snapshot: snapshot({ clock_degraded: true, pending_critical_actions: 2 }), audit: [] });
  assert.match(markup, /現在の状態の根拠となる記録の時刻信頼性が低下しています。/);
  assert.match(markup, /未完了の critical 対応: 2/);
  assert.doesNotMatch(presence({ snapshot: snapshot(), audit: [] }), /未完了の critical 対応/);
});

test('degraded timing preserves a manual override state without claiming it became unknown', () => {
  // Manual override applies even with untrusted timing, and the core then
  // reports suppress_ordinary false for that PRESENT state.
  const markup = presence({ snapshot: snapshot({
    state: 'PRESENT', basis: 'manual_override', suppress_ordinary: false, clock_degraded: true,
  }), audit: [] });
  assert.match(markup, /presence-PRESENT/);
  assert.match(markup, /手動上書きが有効です。/);
  assert.match(markup, /現在の状態の根拠となる記録の時刻信頼性が低下しています。/);
  assert.match(markup, /PRESENT ですが時刻の信頼性が低下しているため、通常の occupancy automation は抑制しません。/);
  assert.doesNotMatch(markup, /一致していません/);
  assert.doesNotMatch(markup, /状態は不明側に倒して表示します。/);
});
