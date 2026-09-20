import { storageStates, type StorageSummary } from '../domain';
import { type Catalog } from '../i18n';
import { bytes } from '../shared/format';

/** Owner-only capacity, retention and notification status; no credential is displayed. */
export function StorageView({ t, storage }: { t: Catalog; storage: StorageSummary }) {
  const starred = Math.min(Math.max(0, storage.starred_bytes), Math.max(0, storage.recording_bytes));
  const segments = [
    ['recordings', Math.max(0, storage.recording_bytes) - starred],
    ['starred', starred],
    ['free', Math.max(0, storage.available_bytes - storage.hard_reserve_bytes)],
    ['reserve', Math.max(0, storage.hard_reserve_bytes)],
  ] as const;
  const total = segments.reduce((sum, [, value]) => sum + value, 0);
  const retention = [
    ['main', t.retentionMainRecordings, storage.recording_retention_days, t.retentionMainNote],
    ['audit', t.retentionAudit, storage.audit_retention_days, t.retentionAuditNote],
    ['agent', t.retentionAgentIncident, storage.agent_incident_retention_days, t.retentionAgentNote],
  ] as const;

  return <section className="storage">
    <div className="states" role="group" aria-label={t.storageStateLabel}>
      {storageStates.map(state => <span key={state} data-storage-state={state}
        aria-current={state === storage.state ? 'true' : undefined}
        className={`state state-${state}${state === storage.state ? ' state-current' : ''}`}>{state}</span>)}
    </div>
    <p>{t.currentState}: <strong>{t[`state_${storage.state}`]}</strong></p>
    <p className="muted">{t.hysteresis}</p>

    <h2>{t.diskBreakdown}</h2>
    <dl className="breakdown">
      {segments.map(([name, value]) => <div key={name} className="breakdown-row">
        <dt id={`disk-${name}`}>{t[`disk_${name}`]}</dt>
        <dd><meter className={`meter meter-${name}`} aria-labelledby={`disk-${name}`} value={value} max={total || 1} />
          <span className="numeric">{bytes(value)}</span></dd>
      </div>)}
      <div className="breakdown-row"><dt>{t.recordingLimit}</dt>
        <dd><span className="numeric">{bytes(storage.recording_limit_bytes)}</span></dd></div>
      <div className="breakdown-row"><dt>{t.criticalAllowance}</dt>
        <dd><span className="numeric">{bytes(storage.critical_allowance_bytes)}</span></dd></div>
    </dl>
    <p className="muted">{t.reserveNote}</p>
    <p className="muted">{t.externalUsage}</p>

    <h2>{t.retentionTitle}</h2>
    <div className="retention-grid">{retention.map(([name, title, days, note]) =>
      <article className="retention-card" key={name} data-retention={name}>
        <h3>{title}</h3>
        <p className="retention-days numeric">{days} {t.daysUnit}</p>
        <p className="muted">{note}</p>
      </article>)}</div>

    <h2>{t.slackTitle}</h2>
    <p><span className="badge">{storage.slack_configured ? t.slackEnabled : t.slackDisabled}</span></p>
    <p>{storage.slack_configured ? t.slackConfiguredNote : t.slackUnconfiguredNote}</p>
    <ul className="notification-rules">
      <li>{t.slackDailyTime}: <span className="numeric">{storage.daily_summary_local_time}</span></li>
      <li>{t.slackImmediate}</li>
      <li>{t.slackAggregated}</li>
    </ul>
    <p className="muted">{t.slackCredential}</p>
  </section>;
}
