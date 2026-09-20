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
}

// No URL/query/localStorage switch can grant a production session. #10 must
// supply a server-validated provider before human data is integrated.
export const deniedServices: DashboardServices = {
  async loadSession() { return { state: 'denied' }; },
};

export const views = ['overview', 'sources', 'nodes', 'live', 'recordings', 'access'] as const;
export type View = typeof views[number];

export function canVisit(session: Session, view: View): boolean {
  if (session.state !== 'allowed') return false;
  if (session.role === 'owner') return true;
  if (view === 'overview') return true;
  if (view === 'live') return session.permissions.includes('live:view');
  if (view === 'recordings') return session.permissions.includes('recordings:view');
  return false;
}
