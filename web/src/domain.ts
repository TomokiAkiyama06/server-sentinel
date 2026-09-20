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
  loadTimeline?(signal: AbortSignal): Promise<TimelinePage>;
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
export type ObservationValue = 'observed' | 'not_observed' | 'unknown' | 'online' | 'offline'
  | 'degraded' | 'ready' | 'failed' | 'created' | 'deleted' | 'changed';
export type Quality = 'sufficient' | 'insufficient' | 'unknown';
export type PresenceState = 'PRESENT' | 'PROBABLY_PRESENT' | 'ABSENT' | 'UNKNOWN';
export type PresenceBasis = 'manual_override' | 'owner_observation' | 'hint' | 'unknown';

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

export interface TimelinePage {
  items: readonly Observation[];
  ordering_basis: 'occurred_at' | 'received_at';
  ordering_degraded: boolean;
  causality: 'not_inferred';
  next_sequence: number;
}

export interface PresenceSnapshot {
  state: PresenceState;
  basis: PresenceBasis;
  override_expires_at: string | null;
  clock_degraded: boolean;
  suppress_ordinary: boolean;
  critical_detection_armed: boolean;
  critical_evidence_armed: boolean;
  critical_notifications_armed: boolean;
  pending_critical_actions: number;
}

export interface PresenceTransition {
  at: string;
  state: PresenceState;
  basis: PresenceBasis;
}

export interface PresenceReport {
  snapshot: PresenceSnapshot;
  transitions: readonly PresenceTransition[];
}
