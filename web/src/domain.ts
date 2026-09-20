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

export const views = ['overview', 'sources', 'nodes', 'live', 'recordings', 'access', 'storage'] as const;
export type View = typeof views[number];

export function canVisit(session: Session, view: View): boolean {
  if (session.state !== 'allowed') return false;
  if (session.role === 'owner') return true;
  if (view === 'overview') return true;
  if (view === 'live') return session.permissions.includes('live:view');
  if (view === 'recordings') return session.permissions.includes('recordings:view');
  // Storage, retention and notification settings stay owner-only; no viewer
  // permission grants them, and the server repeats this check.
  return false;
}
