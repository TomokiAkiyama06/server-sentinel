/** Test-only entry point. Never copied into dist or used for deployment. */
import { createRoot } from 'react-dom/client';
import { App } from '../src/App';
import { createApiClient } from '../src/api';
import { type CameraSourceSummary, type PresenceReport, type Session, type TimelineCursor, type TimelinePage } from '../src/domain';
import '../src/style.css';

const api = createApiClient(window.location.origin);
function session(value: unknown): Session {
  if (typeof value !== 'object' || value === null || !('state' in value)) throw new Error();
  if (value.state === 'denied') return { state: 'denied' };
  if (value.state === 'allowed' && 'role' in value && 'permissions' in value &&
      (value.role === 'owner' || value.role === 'viewer') && Array.isArray(value.permissions) &&
      value.permissions.every(permission => permission === 'live:view' || permission === 'recordings:view')) {
    return { state: 'allowed', role: value.role, permissions: value.permissions };
  }
  throw new Error();
}
function presence(value: unknown): PresenceReport {
  if (typeof value !== 'object' || value === null || !('snapshot' in value)) throw new Error();
  return value as PresenceReport;
}

/** Class-based on purpose: providers must keep their receiver when invoked. */
class SyntheticServices {
  constructor(private readonly client: typeof api) {}
  loadSession(signal: AbortSignal) { return this.client.read('/api/mock/session', session, signal); }
  loadSources(signal: AbortSignal) {
    return this.client.read('/api/mock/sources', value => {
      if (!Array.isArray(value)) throw new Error();
      return value as CameraSourceSummary[];
    }, signal);
  }
  loadTimeline(signal: AbortSignal, after?: TimelineCursor | null) {
    const path = after ? `/api/mock/timeline?after=${encodeURIComponent(String(after.sequence))}` : '/api/mock/timeline';
    return this.client.read(path, value => {
      if (typeof value !== 'object' || value === null || !Array.isArray((value as TimelinePage).items)) throw new Error();
      return value as TimelinePage;
    }, signal);
  }
  loadPresence(signal: AbortSignal) { return this.client.read('/api/mock/presence', presence, signal); }
  cancelPresenceOverride(signal: AbortSignal) { return this.client.read('/api/mock/presence-cancelled', presence, signal); }
}
const services = new SyntheticServices(api);
const root = document.getElementById('root');
if (root) createRoot(root).render(<App services={services} />);
