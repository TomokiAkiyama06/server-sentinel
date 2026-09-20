import { Component, useEffect, useState, type ReactNode } from 'react';
import { canVisit, deniedServices, views, type CameraSourceSummary, type DashboardServices, type Session, type View } from './domain';
import { messages, type Locale } from './i18n';
import { PresenceScreen } from './views/presence';
import { TimelineScreen } from './views/timeline';

type Access = { state: 'loading' | 'failed' } | Session;
type Sources = { state: 'loading' | 'failed' | 'pending' } | { state: 'ready'; items: readonly CameraSourceSummary[] };

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
  const [view, setView] = useState<View>('overview');
  const [attempt, setAttempt] = useState(0);
  const t = messages[locale];

  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => {
    const controller = new AbortController();
    setAccess({ state: 'loading' });
    setSources({ state: 'pending' });
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

  const session: Session = access.state === 'allowed' ? access : { state: 'denied' };
  const selected = canVisit(session, view) ? view : 'overview';
  const hint = `${selected}Hint` as const;

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
            {selected === 'timeline' && canVisit(session, 'timeline') ? <TimelineScreen services={services} t={t} />
              : selected === 'presence' && access.role === 'owner' ? <PresenceScreen services={services} t={t} />
                : selected === 'sources' && access.role === 'owner' && sources.state === 'ready' ? <>
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
                : <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span><h2>{t[selected]}</h2><p>{t.foundation}</p></section>}
          </>}
        </LocalBoundary>
      </main>
    </div>
  </div>;
}
