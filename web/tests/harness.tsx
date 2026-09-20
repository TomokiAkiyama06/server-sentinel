/** Test-only entry point. Never copied into dist or used for deployment. */
import { createRoot } from 'react-dom/client';
import { App } from '../src/App';
import { createApiClient } from '../src/api';
import { type CameraSourceSummary, type RecordingSummary, type Session, type StorageSummary } from '../src/domain';
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
let recordings: RecordingSummary[] = [];
let loaded = false;
// Synthetic latency so tests can observe in-flight mutation handling.
let syntheticMutations = 0;
const settle = () => new Promise<void>(resolve => setTimeout(resolve, 150));
// The synthetic write still asks the server, so failures and aborts are real.
let syntheticMutationPath = '/api/mock/mutation';
Object.defineProperty(window, 'failNextMutations', {
  value: (path: string) => { syntheticMutationPath = path; },
});
const accepted = (signal: AbortSignal) => api.read(syntheticMutationPath, value => {
  if (typeof value !== 'object' || value === null || !('accepted' in value) || value.accepted !== true) throw new Error();
  return true;
}, signal);
Object.defineProperty(window, 'syntheticMutations', { get: () => syntheticMutations });
const services = {
  loadSession: (signal: AbortSignal) => api.read('/api/mock/session', session, signal),
  loadSources: (signal: AbortSignal) => api.read('/api/mock/sources', value => {
    if (!Array.isArray(value)) throw new Error();
    return value as CameraSourceSummary[];
  }, signal),
  loadRecordings: async (signal: AbortSignal) => {
    if (!loaded) {
      recordings = await api.read('/api/mock/recordings', value => {
        if (!Array.isArray(value)) throw new Error();
        return value as RecordingSummary[];
      }, signal);
      loaded = true;
    }
    return recordings;
  },
  loadStorage: (signal: AbortSignal) => api.read('/api/mock/storage', value => {
    if (typeof value !== 'object' || value === null) throw new Error();
    return value as StorageSummary;
  }, signal),
  // Synthetic local mutations: this harness has no write route and never gets one.
  starRecording: async (id: string, starred: boolean, signal: AbortSignal) => {
    syntheticMutations += 1;
    await settle();
    await accepted(signal);
    recordings = recordings.map(recording => recording.id === id
      ? { ...recording, starred, retention_days_left: starred ? null : 7 } : recording);
  },
  deleteRecording: async (id: string, signal: AbortSignal) => {
    syntheticMutations += 1;
    await settle();
    await accepted(signal);
    recordings = recordings.filter(recording => recording.id !== id);
  },
};
const root = document.getElementById('root');
if (root) {
  const tree = createRoot(root);
  tree.render(<App services={services} />);
  // Test-only provider switch. The replacement never resolves a session, so any
  // data still on screen afterwards came from the previous provider.
  Object.defineProperty(window, 'switchProvider', {
    value: () => tree.render(<App services={{ loadSession: () => new Promise<Session>(() => {}) }} />),
  });
}
