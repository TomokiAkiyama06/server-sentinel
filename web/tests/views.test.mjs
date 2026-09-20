import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/domain.ts', 'build/domain.mjs');
await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('src/recordings/view.tsx', 'build/recordings-view.mjs');
await compile('src/setup/storage.tsx', 'build/storage-view.mjs');
const { canVisit, deniedServices, storageStates } = await import('../build/domain.mjs');
const { messages } = await import('../build/i18n.mjs');
const { RecordingsView } = await import('../build/recordings-view.mjs');
const { StorageView } = await import('../build/storage-view.mjs');

const recordings = [
  { id: 'synthetic-recording-1', source_id: 'synthetic-source-1', source_name: '生成カメラ 1',
    kind: 'event', status: 'complete', start_ms: 1_700_000_000_000, duration_ms: 150_000,
    size_bytes: 536_870_912, starred: false, retention_days_left: 12 },
  { id: 'synthetic-recording-2', source_id: 'synthetic-source-2', source_name: '生成カメラ 2',
    kind: 'critical', status: 'gapped', start_ms: 1_700_003_600_000, duration_ms: 900_000,
    size_bytes: 3_221_225_472, starred: true, retention_days_left: null },
  { id: 'synthetic-recording-3', source_id: 'synthetic-source-1', source_name: '生成カメラ 1',
    kind: 'manual', status: 'active', start_ms: 1_700_007_200_000, duration_ms: 1_200_000,
    size_bytes: 104_857_600, starred: false, retention_days_left: 3 },
];
const storage = {
  state: 'STORAGE_PRESSURE', recording_bytes: 64_424_509_440, starred_bytes: 10_737_418_240,
  available_bytes: 21_474_836_480, reserved_bytes: 0, hard_reserve_bytes: 5_368_709_120,
  recording_limit_bytes: 85_899_345_920, critical_allowance_bytes: 2_147_483_648,
  recording_retention_days: 20, audit_retention_days: 90, agent_incident_retention_days: 60,
  slack_configured: false, daily_summary_local_time: '23:00',
  audit_delivery_failed: false, cleanup_failed: false,
  notification_delivery_failed: false, notification_log_failed: false,
};
const actions = { star() { assert.fail('render must not mutate'); }, remove() { assert.fail('render must not mutate'); } };
const recordingsMarkup = (owner, { recordings: items = recordings, ...extra } = {}) =>
  renderToStaticMarkup(createElement(RecordingsView, { t: messages.ja, recordings: items, owner, ...extra }));
const storageMarkup = (locale = 'ja', value = storage) =>
  renderToStaticMarkup(createElement(StorageView, { t: messages[locale], storage: value }));

test('storage stays owner-only and recording metadata needs recordings:view', () => {
  for (const permissions of [[], ['live:view'], ['recordings:view'], ['live:view', 'recordings:view']]) {
    const viewer = { state: 'allowed', role: 'viewer', permissions };
    assert.equal(canVisit(viewer, 'storage'), false);
    assert.equal(canVisit(viewer, 'recordings'), permissions.includes('recordings:view'));
  }
  assert.equal(canVisit({ state: 'allowed', role: 'owner', permissions: [] }, 'storage'), true);
  for (const view of ['recordings', 'storage']) assert.equal(canVisit({ state: 'denied' }, view), false);
  for (const name of ['loadRecordings', 'loadStorage', 'starRecording', 'deleteRecording']) {
    assert.equal(name in deniedServices, false);
  }
});

test('recording rows expose no download, export or direct media route', () => {
  for (const markup of [recordingsMarkup(false, { actions }), recordingsMarkup(true, { actions })]) {
    assert.doesNotMatch(markup, /<a\b|href=|\bdownload\b|<video|<source|<iframe|<object|<embed/);
    assert.doesNotMatch(markup, /\.mp4|\.m3u8|\.mpd|blob:|data:video/);
  }
  const markup = recordingsMarkup(false, { actions });
  assert.match(markup, /data-recording-id="synthetic-recording-1"/);
  assert.match(markup, /生成カメラ 2/);
  assert.ok(markup.includes(messages.ja.recordingsCaption));
  assert.equal(markup.includes(messages.ja.columnActions), false);
});

test('star and delete controls are owner-only', () => {
  const controls = [messages.ja.starOn, messages.ja.starOff, messages.ja.deleteRecording, messages.ja.ownerOnlyActions];
  for (const markup of [recordingsMarkup(false, { actions }), recordingsMarkup(true)]) {
    // An owner without an authorized mutation provider also gets no control.
    for (const label of controls) assert.doesNotMatch(markup, new RegExp(`>${label}<`));
    assert.doesNotMatch(markup, /row-actions/);
    assert.equal(markup.includes(messages.ja.columnActions), false);
  }
  const owner = recordingsMarkup(true, { actions });
  for (const label of controls) assert.match(owner, new RegExp(`>${label}<`));
  assert.match(owner, /row-actions/);
  assert.ok(owner.includes(messages.ja.columnActions));
});

test('an in-flight mutation disables that row\'s owner controls only', () => {
  const markup = recordingsMarkup(true, { actions, busy: ['synthetic-recording-1'] });
  const rows = markup.split('<tr').filter(row => row.includes('data-recording-id='));
  assert.equal(rows.length, recordings.length);
  for (const row of rows) {
    const inflight = row.includes('data-recording-id="synthetic-recording-1"');
    assert.equal(/aria-busy="true"/.test(row), inflight);
    assert.equal(/<button[^>]*disabled[^>]*>/.test(row), inflight);
  }
  // Without an in-flight mutation nothing is disabled.
  assert.doesNotMatch(recordingsMarkup(true, { actions }), /<button[^>]*disabled/);
});

test('a failed write is reported without discarding the loaded list', () => {
  const markup = recordingsMarkup(true, { actions, failedWrites: ['synthetic-recording-1'] });
  // Only the recording whose write failed is flagged.
  assert.equal(markup.split('data-write-failed="true"').length - 1, 1);
  const rows = markup.split('<tr').filter(row => row.includes('data-recording-id='));
  for (const row of rows) {
    assert.equal(row.includes('data-write-failed="true"'),
      row.includes('data-recording-id="synthetic-recording-1"'));
  }
  assert.match(markup, /class="write-alert" role="alert"/);
  assert.ok(markup.includes(messages.ja.actionFailed));
  // The list itself is intact: a failed write is not a failed read.
  assert.equal(markup.split('data-recording-id=').length - 1, recordings.length);
  assert.equal(markup.includes(messages.ja.recordingsUnavailable), false);
  assert.doesNotMatch(recordingsMarkup(true, { actions }), /write-alert|data-write-failed/);
});

test('starred recordings are shown as never auto-deleted and keep their day counts separate', () => {
  const markup = recordingsMarkup(true, { actions });
  assert.match(markup, new RegExp(`★ ${messages.ja.neverAutoDeleted}`));
  assert.match(markup, /12 日/);
  assert.match(markup, /3 日/);
});

test('recording filters keep every store-backed kind selectable', () => {
  const markup = recordingsMarkup(false);
  // Every kind in the catalog must be isolatable, manual included.
  const kinds = Object.keys(messages.ja).filter(key => key.startsWith('kind_')).map(key => messages.ja[key]);
  assert.equal(kinds.length, new Set(recordings.map(recording => recording.kind)).size);
  for (const label of [messages.ja.filterAll, ...kinds, messages.ja.filterStarred]) {
    assert.match(markup, new RegExp(`aria-pressed="(true|false)"[^>]*>${label}<`));
  }
  assert.match(markup, /role="group"/);
});

test('recording coverage state is projected and active rows never offer deletion', () => {
  const markup = recordingsMarkup(true, { actions, recordings: [
    ...recordings,
    { ...recordings[1], id: 'synthetic-recording-4', status: 'interrupted' },
  ] });
  for (const status of ['active', 'complete', 'gapped', 'interrupted']) {
    assert.ok(markup.includes(messages.ja[`status_${status}`]));
  }
  assert.ok(markup.includes(messages.ja.coverageIncomplete));
  const active = markup.split('<tr').find(row => row.includes('data-recording-id="synthetic-recording-3"'));
  assert.ok(active);
  assert.doesNotMatch(active, new RegExp(`>${messages.ja.deleteRecording}<`));
  const gapped = markup.split('<tr').find(row => row.includes('data-recording-id="synthetic-recording-2"'));
  assert.ok(gapped);
  assert.match(gapped, new RegExp(`>${messages.ja.coverageIncomplete}<`));
});

test('storage shows all three states with the current one marked', () => {
  assert.deepEqual([...storageStates], ['NORMAL', 'STORAGE_PRESSURE', 'STORAGE_HARD_STOP']);
  const markup = storageMarkup();
  for (const state of storageStates) assert.match(markup, new RegExp(`data-storage-state="${state}"`));
  assert.match(markup, /aria-current="true"[^>]*state-STORAGE_PRESSURE|state-STORAGE_PRESSURE[^>]*aria-current="true"/);
  assert.ok(markup.includes(messages.ja.state_STORAGE_PRESSURE));
  assert.ok(markup.includes(messages.ja.hysteresis));
});

test('disk breakdown separates recordings, starred, free space and the hard reserve', () => {
  const markup = storageMarkup();
  for (const name of ['recordings', 'starred', 'free', 'reserve']) {
    assert.match(markup, new RegExp(`id="disk-${name}"`));
    assert.match(markup, new RegExp(`aria-labelledby="disk-${name}"`));
  }
  // Starred bytes are a subset of recording bytes and must not be counted twice.
  assert.match(markup, /50\.0 GiB/);
  assert.match(markup, /10\.0 GiB/);
  assert.match(markup, /15\.0 GiB/);
  assert.match(markup, /5\.0 GiB/);
  assert.ok(markup.includes(messages.ja.reserveNote));
  assert.match(markup, /class="numeric"/);
});

test('the three retention periods are displayed as separate lifecycles', () => {
  for (const locale of ['ja', 'en']) {
    const markup = storageMarkup(locale);
    for (const [name, days] of [['main', 20], ['audit', 90], ['agent', 60]]) {
      assert.match(markup, new RegExp(`data-retention="${name}"`));
      assert.match(markup, new RegExp(`${days} ${messages[locale].daysUnit}`));
    }
    assert.ok(markup.includes(messages[locale].retentionAgentNote));
  }
});

test('Slack is disabled until configured and no credential is rendered', () => {
  const markup = storageMarkup();
  assert.ok(markup.includes(messages.ja.slackDisabled));
  assert.ok(markup.includes(messages.ja.slackUnconfiguredNote));
  assert.ok(markup.includes(messages.ja.slackCredential));
  assert.match(markup, /23:00/);
  assert.doesNotMatch(markup, /hooks\.slack\.com|xox[baprs]-|webhook/i);
  const configured = storageMarkup('ja', { ...storage, slack_configured: true });
  assert.ok(configured.includes(messages.ja.slackEnabled));
  assert.doesNotMatch(configured, /hooks\.slack\.com|xox[baprs]-|webhook/i);
});

const meters = markup => Object.fromEntries([...markup.matchAll(/aria-labelledby="disk-(\w+)"[^>]*value="(\d+)"/g)]
  .map(([, name, value]) => [name, Number(value)]));

test('an intact hard reserve is metered without inventing capacity', () => {
  const rows = meters(storageMarkup());
  assert.equal(rows.reserve, storage.hard_reserve_bytes);
  assert.equal(rows.free + rows.reserve, storage.available_bytes);
  assert.equal(rows.recordings + rows.starred, storage.recording_bytes);
  assert.doesNotMatch(storageMarkup(), /data-reserve-shortfall/);
});

test('a consumed hard reserve is never drawn as intact space', () => {
  // 1 GiB available under a 5 GiB configured reserve: no free space, only the
  // 1 GiB still on disk counts as reserve, and the 4 GiB gap is reported.
  const markup = storageMarkup('ja', { ...storage, state: 'STORAGE_HARD_STOP', available_bytes: 1_073_741_824 });
  const rows = meters(markup);
  assert.doesNotMatch(markup, /-\d/);
  assert.equal(rows.free, 0);
  assert.equal(rows.reserve, 1_073_741_824);
  assert.equal(rows.free + rows.reserve, 1_073_741_824);
  assert.match(markup, /data-reserve-shortfall="true"/);
  assert.ok(markup.includes(messages.ja.reserveShortfall));
  assert.match(markup, />4\.0 GiB</);
  // The configured target stays visible as a separate figure, not as space.
  assert.ok(markup.includes(messages.ja.reserveTarget));
  assert.match(markup, /aria-current="true"/);
});

test('an active write reservation is removed before rendering free capacity', () => {
  const markup = storageMarkup('en', {
    ...storage,
    state: 'STORAGE_HARD_STOP',
    available_bytes: 210,
    reserved_bytes: 120,
    hard_reserve_bytes: 100,
  });
  const rows = meters(markup);
  assert.equal(rows.free, 0);
  assert.equal(rows.reserve, 90);
  assert.equal(rows.free + rows.reserve, 90);
  assert.match(markup, /data-reserve-shortfall="true"/);
});

test('a healthy backend shows no fault alert', () => {
  const markup = storageMarkup();
  assert.doesNotMatch(markup, /data-fault=/);
  assert.doesNotMatch(markup, /fault-alert/);
});

test('sticky backend faults stay visible after the state recovers', () => {
  // NORMAL capacity must not hide a lost transition audit or a stalled cleanup.
  const markup = storageMarkup('ja', { ...storage, state: 'NORMAL', audit_delivery_failed: true, cleanup_failed: true });
  assert.match(markup, /class="fault-alert" role="alert"/);
  for (const name of ['audit_delivery_failed', 'cleanup_failed']) {
    assert.match(markup, new RegExp(`data-fault="${name}"`));
    assert.ok(markup.includes(messages.ja[`fault_${name}`]));
  }
  assert.ok(markup.includes(messages.ja.state_NORMAL));
});

test('a configured Slack that lost a notification is not reported as healthy', () => {
  const markup = storageMarkup('ja', {
    ...storage, slack_configured: true,
    notification_delivery_failed: true, notification_log_failed: true,
  });
  assert.ok(markup.includes(messages.ja.slackEnabled));
  for (const name of ['notification_delivery_failed', 'notification_log_failed']) {
    assert.match(markup, new RegExp(`data-fault="${name}"`));
    assert.ok(markup.includes(messages.ja[`fault_${name}`]));
  }
  // Still no credential, in either locale.
  for (const locale of ['ja', 'en']) {
    assert.doesNotMatch(storageMarkup(locale, { ...storage, notification_delivery_failed: true }),
      /hooks\.slack\.com|xox[baprs]-|webhook/i);
  }
});
