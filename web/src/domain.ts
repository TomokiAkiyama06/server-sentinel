/** UI projections only: authoritative identity/permissions remain server-side. */
export type Permission = 'live:view' | 'recordings:view';
export type Session =
  | { state: 'denied' }
  | { state: 'allowed'; role: 'owner' | 'viewer'; permissions: readonly Permission[] };

export type CameraHealth = 'online' | 'degraded' | 'offline' | 'manual_intervention_required';
export interface CameraSourceSummary {
  id: string;
  name: string;
  source_type: 'local_uvc' | 'remote_agent';
  role: string | null;
  enabled: boolean;
  health: CameraHealth;
}

/** `manual` has no event_id in RecordingStore; ordinary/critical event rows do. */
// These are UI projections, not a mirror of a backend payload: no route serves
// them yet (#10). Fields marked "derived" have no column or attribute of that
// name; an adapter must compute or join them. See web/README.md for the audit.
export type RecordingKind = 'event' | 'manual' | 'critical';
export type RecordingStatus = 'active' | 'complete' | 'gapped' | 'interrupted';
export interface RecordingSummary {
  id: string;
  source_id: string;
  /** Derived: joined from the camera registry, not a `recordings` column. */
  source_name: string;
  /** Derived: no `event_id` is manual, the `critical` flag is critical evidence. */
  kind: RecordingKind;
  /** Store coverage state; `gapped` and `interrupted` are never presented as complete. */
  status: RecordingStatus;
  start_ms: number;
  /** Derived from `start_ms` and `ended_ms`; the store keeps no duration. */
  duration_ms: number;
  /** Derived: summed from the linked `recording_segments.byte_length`. */
  size_bytes: number;
  starred: boolean;
  /** Derived from `ended_ms` and `RetentionPeriods.recording_days`. `null`
   *  means the owner starred it and it never auto-deletes. */
  retention_days_left: number | null;
}

export const storageStates = ['NORMAL', 'STORAGE_PRESSURE', 'STORAGE_HARD_STOP'] as const;
export type StorageState = typeof storageStates[number];

export interface StorageSummary {
  state: StorageState;
  recording_bytes: number;
  starred_bytes: number;
  /** Bytes reserved by in-flight recording writes; unavailable until released. */
  reserved_bytes: number;
  available_bytes: number;
  hard_reserve_bytes: number;
  recording_limit_bytes: number;
  critical_allowance_bytes: number;
  /** `RetentionPeriods.recording_days` (renamed). */
  recording_retention_days: number;
  /** `RetentionPeriods.audit_days` (renamed). */
  audit_retention_days: number;
  /** Agent-owned protected incidents; a separate lifecycle Main retention never
   *  shortens. No Main-server field supplies this today: the 60-day default is
   *  documented policy (agent/storage/README.md) and Plan 9A owns it. */
  agent_incident_retention_days: number;
  /** `SlackDelivery.configured` (renamed). */
  slack_configured: boolean;
  /** Derived: formatted from the daily scheduler's hour, minute and zone. */
  daily_summary_local_time: string;
  // Sticky backend faults. A recovered state never hides a lost audit record,
  // an unfinished cleanup, or a notification that was never delivered.
  /** `StorageStatus.audit_delivery_failed`. */
  audit_delivery_failed: boolean;
  /** `StorageStatus.cleanup_failed`. */
  cleanup_failed: boolean;
  /** `NotificationService.delivery_failed` (renamed for this payload). */
  notification_delivery_failed: boolean;
  /** `NotificationService.local_delivery_failed` (renamed for this payload). */
  notification_log_failed: boolean;
}

export interface DashboardServices {
  loadSession(signal: AbortSignal): Promise<Session>;
  loadSources?(signal: AbortSignal): Promise<readonly CameraSourceSummary[]>;
  loadTimeline?(signal: AbortSignal, after?: TimelineCursor | null): Promise<TimelinePage>;
  loadPresence?(signal: AbortSignal): Promise<PresenceReport>;
  cancelPresenceOverride?(signal: AbortSignal): Promise<PresenceReport>;
  loadRecordings?(signal: AbortSignal): Promise<readonly RecordingSummary[]>;
  loadStorage?(signal: AbortSignal): Promise<StorageSummary>;
  starRecording?(id: string, starred: boolean, signal: AbortSignal): Promise<void>;
  deleteRecording?(id: string, signal: AbortSignal): Promise<void>;
}

// No URL/query/localStorage switch can grant a production session. #10 must
// supply a server-validated provider before human data is integrated.
export const deniedServices: DashboardServices = {
  async loadSession() { return { state: 'denied' }; },
};

export const views = ['overview', 'sources', 'nodes', 'live', 'recordings', 'timeline', 'presence', 'access', 'storage'] as const;
export type View = typeof views[number];

export function canVisit(session: Session, view: View): boolean {
  if (session.state !== 'allowed') return false;
  if (session.role === 'owner') return true;
  if (view === 'overview') return true;
  if (view === 'live') return session.permissions.includes('live:view');
  // Historical timeline/events stay with recordings:view; presence stays owner-only.
  if (view === 'recordings' || view === 'timeline') return session.permissions.includes('recordings:view');
  // Storage, retention and notification settings stay owner-only; no viewer
  // permission grants them, and the server repeats this check.
  return false;
}

export type ObservationKind = 'person' | 'motion' | 'owner_entry' | 'owner_exit' | 'anonymous_entry'
  | 'anonymous_exit' | 'server_movement' | 'camera_tamper' | 'camera_health' | 'node_health'
  | 'recording' | 'storage' | 'presence' | 'configuration';
// Superset of the presence Value/Quality enums: it also covers the source and
// node health transitions and the detector quality states that reach the
// timeline as those producers are wired, so no reported state renders blank.
export type ObservationValue = 'observed' | 'not_observed' | 'unknown' | 'online' | 'offline'
  | 'degraded' | 'manual_intervention_required' | 'revoked' | 'ready' | 'failed' | 'created'
  | 'deleted' | 'changed';
export type Quality = 'sufficient' | 'degraded' | 'insufficient' | 'unknown';
export type PresenceState = 'PRESENT' | 'PROBABLY_PRESENT' | 'ABSENT' | 'UNKNOWN';
export type PresenceBasis = 'manual_override' | 'owner_observation' | 'hint' | 'unknown';
/** `unknown` is unreported availability; `unavailable` is a known failure. */
export type CriticalPath = 'armed' | 'unavailable' | 'unknown';
export type PresenceAuditAction = 'override_set' | 'override_cancelled' | 'override_expired'
  | 'hint_set' | 'critical_action_requeued' | 'critical_degradation_cleared'
  | 'critical_event_cleared';

/** Neutral observation projection: never a culprit, cause or identity claim. */
export interface Observation {
  id: string;
  kind: ObservationKind;
  value: ObservationValue;
  occurred_at: string;
  received_at: string;
  source_id: string | null;
  node_id: string | null;
  confidence: number | null;
  quality: Quality;
  clock_trusted: boolean;
  uncertainty_us: number;
  confirmed: boolean;
  presence_state: PresenceState | null;
  sequence: number;
}

/** Main-host receipt order with the durable sequence only as a tie-break. */
export interface TimelineCursor {
  received_at: string;
  sequence: number;
}

export interface TimelinePage {
  items: readonly Observation[];
  ordering_basis: 'received_at';
  ordering_degraded: boolean;
  causality: 'not_inferred';
  next_cursor: TimelineCursor | null;
}

export interface PresenceSnapshot {
  state: PresenceState;
  basis: PresenceBasis;
  override_expires_at: string | null;
  /** Timing trust of the marker behind `basis`: Owner control or observation. */
  clock_degraded: boolean;
  /** Timing trust of observation receipt, independent of `clock_degraded`. */
  observation_clock_degraded: boolean;
  suppress_ordinary: boolean;
  critical_detection: CriticalPath;
  critical_persistence: CriticalPath;
  critical_evidence: CriticalPath;
  critical_notifications: CriticalPath;
  critical_paths_degraded: boolean;
  override_expiry_pending: boolean;
  pending_critical_actions: number;
}

/** Audited Owner control history; it carries no biometric or viewer identity.
 *
 * The core also records the acting Owner identity. It is deliberately left out
 * of this projection: the screen is Owner-only and the actor adds no fact the
 * Owner needs here, so the identifier is not carried into the browser.
 */
export interface PresenceAuditEntry {
  sequence: number;
  action: PresenceAuditAction;
  at: string;
  state: PresenceState | null;
  /** Recovery target: `<action>:<observation>`, `<action>`, or an event observation id. */
  target: string | null;
}

export interface PresenceReport {
  snapshot: PresenceSnapshot;
  audit: readonly PresenceAuditEntry[];
}
