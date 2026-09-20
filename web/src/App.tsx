import { Component, useEffect, useState, type ReactNode } from 'react';
import { canVisit, deniedServices, views, type CameraSourceSummary, type DashboardServices, type RecordingSummary, type Session, type StorageSummary, type View } from './domain';
import { messages, type Locale } from './i18n';
import { RecordingsView } from './recordings/view';
import { StorageView } from './setup/storage';
import { MutationQueue } from './shared/mutations';

type Access = { state: 'loading' | 'failed' } | Session;
type Sources = { state: 'loading' | 'failed' | 'pending' } | { state: 'ready'; items: readonly CameraSourceSummary[] };
type Recordings = { state: 'loading' | 'failed' | 'pending' } | { state: 'ready'; items: readonly RecordingSummary[] };
type Storage = { state: 'loading' | 'failed' | 'pending' } | { state: 'ready'; item: StorageSummary };

/** Deliberately no external reporter, error details, or automatic retry loop. */
class LocalBoundary extends Component<{ children: ReactNode; message: string }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <p role="alert">{this.props.message}</p> : this.props.children;
  }
}

export function App({ services = deniedServices }: { services?: DashboardServices }) {
  const [locale, setLocale] = useState<Locale>('ja');
  const [access, setAccess] = useState<Access>({ state: 'loading' });
  const [sources, setSources] = useState<Sources>({ state: 'pending' });
  const [recordings, setRecordings] = useState<Recordings>({ state: 'pending' });
  const [storage, setStorage] = useState<Storage>({ state: 'pending' });
  const [view, setView] = useState<View>('overview');
  const [attempt, setAttempt] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState<readonly string[]>([]);
  const [mutations] = useState(() => new MutationQueue());
  const t = messages[locale];

  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => {
    const controller = new AbortController();
    setAccess({ state: 'loading' });
    setSources({ state: 'pending' });
    setRecordings({ state: 'pending' });
    setStorage({ state: 'pending' });
    setView('overview');
    void (async () => {
      try {
        const session = await services.loadSession(controller.signal);
        if (controller.signal.aborted) return;
        setAccess(session);
        // Owner-only metadata until the separate human authorization contract
        // defines which projections are available to invited viewers.
        if (session.state === 'allowed' && session.role === 'owner' && services.loadSources) {
          setSources({ state: 'loading' });
          try {
            const items = await services.loadSources(controller.signal);
            if (!controller.signal.aborted) setSources({ state: 'ready', items });
          } catch {
            if (!controller.signal.aborted) setSources({ state: 'failed' });
          }
        }
      } catch {
        if (!controller.signal.aborted) setAccess({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [services, attempt]);

  // Historical recording metadata follows `recordings:view`; the server repeats
  // the check and no client state can widen it.
  useEffect(() => {
    const loader = services.loadRecordings;
    if (!loader || access.state !== 'allowed' || !canVisit(access, 'recordings')) return;
    const controller = new AbortController();
    setRecordings({ state: 'loading' });
    void (async () => {
      try {
        const items = await loader(controller.signal);
        if (!controller.signal.aborted) setRecordings({ state: 'ready', items });
      } catch {
        if (!controller.signal.aborted) setRecordings({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [services, access, refresh]);

  useEffect(() => {
    const loader = services.loadStorage;
    if (!loader || access.state !== 'allowed' || access.role !== 'owner') return;
    const controller = new AbortController();
    setStorage({ state: 'loading' });
    void (async () => {
      try {
        const item = await loader(controller.signal);
        if (!controller.signal.aborted) setStorage({ state: 'ready', item });
      } catch {
        if (!controller.signal.aborted) setStorage({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [services, access, refresh]);

  useEffect(() => {
    setBusy(current => current.length ? [] : current);
    return () => mutations.abortAll();
  }, [services, access, mutations]);

  const session: Session = access.state === 'allowed' ? access : { state: 'denied' };
  const selected = canVisit(session, view) ? view : 'overview';
  const hint = `${selected}Hint` as const;
  const star = services.starRecording;
  const remove = services.deleteRecording;
  const mutate = (id: string, run: (signal: AbortSignal) => Promise<void>) => {
    if (!mutations.start(id, run, outcome => {
      setBusy(mutations.pending);
      // An aborted mutation belongs to a replaced session: no result, no error.
      if (outcome === 'done') setRefresh(value => value + 1);
      else if (outcome === 'failed') setRecordings({ state: 'failed' });
    })) return;
    setBusy(mutations.pending);
  };
  // Owner-only star/delete; rendered only when the authorized provider exists.
  const actions = session.state === 'allowed' && session.role === 'owner' && star && remove ? {
    star: (recording: RecordingSummary) =>
      mutate(recording.id, signal => star(recording.id, !recording.starred, signal)),
    remove: (recording: RecordingSummary) => mutate(recording.id, signal => remove(recording.id, signal)),
  } : undefined;

  return <div className="shell">
    <a className="skip-link" href="#main">{t.skip}</a>
    <header className="header">
      <div className="brand"><span className="brand-symbol" aria-hidden="true">S</span><div><strong>ServerSentinel</strong><p>{t.tagline}</p></div></div>
      <label className="language">{t.language}<select value={locale} onChange={event => setLocale(event.target.value as Locale)}>
        <option value="ja">日本語</option><option value="en">English</option>
      </select></label>
    </header>
    <div className="workspace">
      <nav aria-label={t.navigation} className="navigation">
        {views.map(item => <button key={item} type="button" disabled={!canVisit(session, item)}
          aria-current={selected === item && session.state === 'allowed' ? 'page' : undefined}
          onClick={() => setView(item)}>{t[item]}</button>)}
      </nav>
      <main id="main" tabIndex={-1}>
        <LocalBoundary message={t.failed}>
          {access.state === 'loading' && <section className="notice" role="status"><h1>{t.checking}</h1></section>}
          {access.state === 'denied' && <section className="notice"><span className="eyebrow">ServerSentinel</span><h1>{t.deniedTitle}</h1><p>{t.denied}</p><p className="muted">{t.privateGate}</p></section>}
          {access.state === 'failed' && <section className="notice" role="alert"><h1>{t.failedTitle}</h1><p>{t.failed}</p><button className="primary" onClick={() => setAttempt(value => value + 1)}>{t.retry}</button></section>}
          {access.state === 'allowed' && <>
            <div className="page-heading"><div><span className="eyebrow">{t[access.role]}</span><h1>{t[selected]}</h1><p>{t[hint]}</p></div><span className="badge">{t.pending}</span></div>
            {selected === 'sources' && access.role === 'owner' && sources.state === 'ready' ? <>
              <p className="source-count">{t.sourceCount}: {sources.items.length}</p>
              <div className="source-grid">{sources.items.map(source => <article className="source-card" key={source.id} data-source-id={source.id}>
                <div className="source-icon" aria-hidden="true">▣</div><h2>{source.name}</h2><p>{t[source.source_type]}</p>
                <dl><dt>{t.role}</dt><dd>{source.role || t.unassigned}</dd></dl>
                <span className={`health health-${source.health}`}>{t[source.health]}</span>
                {!source.enabled && <span className="badge">{t.disabled}</span>}
              </article>)}</div>
              {sources.items.length === 0 && <p>{t.noSources}</p>}
            </> : selected === 'sources' && sources.state === 'failed' ? <p role="alert">{t.sourcesUnavailable}</p>
              : selected === 'sources' && sources.state === 'loading' ? <p role="status">{t.checking}</p>
              : selected === 'recordings' && recordings.state === 'ready'
                ? <RecordingsView t={t} recordings={recordings.items} owner={access.role === 'owner'} actions={actions} busy={busy} />
                : selected === 'recordings' && recordings.state === 'failed'
                  ? <section className="notice" role="alert"><p>{t.recordingsUnavailable}</p><button className="primary" onClick={() => setRefresh(value => value + 1)}>{t.retry}</button></section>
                  : selected === 'recordings' && recordings.state === 'loading' ? <p role="status">{t.checking}</p>
                    : selected === 'storage' && access.role === 'owner' && storage.state === 'ready'
                      ? <StorageView t={t} storage={storage.item} />
                      : selected === 'storage' && storage.state === 'failed'
                        ? <section className="notice" role="alert"><p>{t.storageUnavailable}</p><button className="primary" onClick={() => setRefresh(value => value + 1)}>{t.retry}</button></section>
                        : selected === 'storage' && storage.state === 'loading' ? <p role="status">{t.checking}</p>
                          : <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span><h2>{t[selected]}</h2><p>{t.foundation}</p></section>}
          </>}
        </LocalBoundary>
      </main>
    </div>
  </div>;
}
