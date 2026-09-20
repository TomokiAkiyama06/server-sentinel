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

export type RecordingKind = 'event' | 'continuous' | 'critical';
export interface RecordingSummary {
  id: string;
  source_id: string;
  source_name: string;
  kind: RecordingKind;
  start_ms: number;
  duration_ms: number;
  size_bytes: number;
  starred: boolean;
  /** Remaining Main retention; `null` means the owner starred it and it never auto-deletes. */
  retention_days_left: number | null;
}

export const storageStates = ['NORMAL', 'STORAGE_PRESSURE', 'STORAGE_HARD_STOP'] as const;
export type StorageState = typeof storageStates[number];

export interface StorageSummary {
  state: StorageState;
  recording_bytes: number;
  starred_bytes: number;
  available_bytes: number;
  hard_reserve_bytes: number;
  recording_limit_bytes: number;
  critical_allowance_bytes: number;
  recording_retention_days: number;
  audit_retention_days: number;
  /** Agent-owned protected incidents; a separate lifecycle Main retention never shortens. */
  agent_incident_retention_days: number;
  slack_configured: boolean;
  daily_summary_local_time: string;
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
