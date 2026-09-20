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

export interface DashboardServices {
  loadSession(signal: AbortSignal): Promise<Session>;
  loadSources?(signal: AbortSignal): Promise<readonly CameraSourceSummary[]>;
  loadTimeline?(signal: AbortSignal, after?: TimelineCursor | null): Promise<TimelinePage>;
  loadPresence?(signal: AbortSignal): Promise<PresenceReport>;
  cancelPresenceOverride?(signal: AbortSignal): Promise<PresenceReport>;
}

// No URL/query/localStorage switch can grant a production session. #10 must
// supply a server-validated provider before human data is integrated.
export const deniedServices: DashboardServices = {
  async loadSession() { return { state: 'denied' }; },
};

export const views = ['overview', 'sources', 'nodes', 'live', 'recordings', 'timeline', 'presence', 'access'] as const;
export type View = typeof views[number];

export function canVisit(session: Session, view: View): boolean {
  if (session.state !== 'allowed') return false;
  if (session.role === 'owner') return true;
  if (view === 'overview') return true;
  if (view === 'live') return session.permissions.includes('live:view');
  // Historical timeline/events stay with recordings:view; presence stays owner-only.
  if (view === 'recordings' || view === 'timeline') return session.permissions.includes('recordings:view');
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
  | 'hint_set' | 'critical_action_requeued' | 'critical_degradation_cleared';

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

/** Audited Owner control history; it carries no biometric or viewer identity. */
export interface PresenceAuditEntry {
  sequence: number;
  action: PresenceAuditAction;
  at: string;
  state: PresenceState | null;
}

export interface PresenceReport {
  snapshot: PresenceSnapshot;
  audit: readonly PresenceAuditEntry[];
}
