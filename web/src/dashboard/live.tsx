/**
 * Live screen (#205 CP-5): the Camera Sources this principal may watch and
 * one player at a time, fed by the interim frame-pull loop (`live_loop.ts`).
 *
 * Shown only for `canVisit(session, 'live')`; the server checks `live:view`
 * on every request and this screen widens nothing. It shows current frames
 * only: no history, timeline, recording, download or export control. A frame
 * is decoded with `createImageBitmap` and drawn into a `<canvas>`, so the
 * dashboard policy (`img-src 'self'`, `connect-src 'self'`) stays unchanged;
 * no object URL or data URL is created. A refused, paused or stopped session
 * clears the canvas. None of this prevents screen recording or a photo of the
 * screen, and the screen says so.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type { DashboardServices, LiveSource } from '../domain';
import type { Catalog } from '../i18n';
import { documentVisibility, startLiveLoop, type LiveStatus, type LiveTransport } from './live_loop';

type Sources = { state: 'loading' | 'failed' } | { state: 'ready'; items: readonly LiveSource[] };

export function liveTransport(services: DashboardServices): LiveTransport | null {
  const { openLiveSession: open, readLiveFrame: read, closeLiveSession: close } = services;
  if (!open || !read || !close) return null;
  return { open, read, close };
}

export function LiveScreen({ services, t }: { services: DashboardServices; t: Catalog }) {
  const [sources, setSources] = useState<Sources>({ state: 'loading' });
  const [selected, setSelected] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  // One transport per provider: a new object would restart the player.
  const transport = useMemo(() => liveTransport(services), [services]);
  const load = services.loadLiveSources;

  useEffect(() => {
    if (!load) return;
    const controller = new AbortController();
    setSources({ state: 'loading' });
    void (async () => {
      try {
        const items = await load(controller.signal);
        if (controller.signal.aborted) return;
        setSources({ state: 'ready', items });
        setSelected(current => items.some(item => item.id === current) ? current : items[0]?.id ?? null);
      } catch {
        if (!controller.signal.aborted) setSources({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [load, reload]);

  if (!load || !transport) {
    return <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span><h2>{t.live}</h2><p>{t.foundation}</p></section>;
  }
  if (sources.state === 'loading') return <p role="status">{t.checking}</p>;
  if (sources.state !== 'ready') {
    return <section className="notice" role="alert"><p>{t.liveSourcesUnavailable}</p>
      <button className="primary" type="button" onClick={() => setReload(value => value + 1)}>{t.retry}</button></section>;
  }
  const source = sources.items.find(item => item.id === selected) ?? null;
  return <div className="live-screen">
    <p className="muted">{t.liveViewOnly}</p>
    {sources.items.length === 0 ? <p>{t.liveNoSources}</p> : <>
      <div className="live-sources" role="group" aria-label={t.liveSourceChoice}>
        {sources.items.map(item => <button key={item.id} type="button" data-live-source={item.id}
          aria-pressed={item.id === selected} onClick={() => setSelected(item.id)}>
          <span>{item.name}</span>
          {item.health && <span className={`health health-${item.health}`}>{t[item.health]}</span>}
        </button>)}
      </div>
      {source && <LivePlayer key={source.id} transport={transport} source={source} t={t} />}
    </>}
  </div>;
}

function LivePlayer({ transport, source, t }: { transport: LiveTransport; source: LiveSource; t: Catalog }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [status, setStatus] = useState<LiveStatus>('connecting');
  const [shown, setShown] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    const clear = () => {
      const element = canvas.current;
      // Resetting the size drops the bitmap the canvas holds.
      if (element) { element.width = 0; element.height = 0; }
      setShown(false);
    };
    const stop = startLiveLoop({
      transport, sourceId: source.id, visibility: documentVisibility(),
      async onFrame(frame, current) {
        const bitmap = await createImageBitmap(frame.data);
        try {
          const element = canvas.current;
          const context = element?.getContext('2d');
          // A decode that finishes after a pause, refusal or unmount is dropped.
          if (!active || !current() || !element || !context) return;
          if (element.width !== bitmap.width || element.height !== bitmap.height) {
            element.width = bitmap.width;
            element.height = bitmap.height;
          }
          context.drawImage(bitmap, 0, 0);
          setShown(true);
        } finally { bitmap.close(); }
      },
      onStatus(next) {
        if (!active) return;
        if (next === 'paused' || next === 'ended') clear();
        setStatus(next);
      },
    });
    return () => { active = false; stop(); clear(); };
  }, [transport, source.id, attempt]);

  const message = {
    connecting: t.liveConnecting, live: t.liveReceiving, stale: t.liveStale, retrying: t.liveRetrying,
    paused: t.livePaused, ended: t.liveEnded,
  }[status];
  return <section className="live-player" aria-label={source.name} data-live-status={status}>
    <div className={`live-frame${status === 'live' ? '' : ' live-frame-inactive'}`}>
      {/* No save/export entry point is offered; suppressing the context menu
          is not a protection against capture. */}
      <canvas ref={canvas} width={0} height={0} aria-label={source.name} role="img" hidden={!shown}
        onContextMenu={event => event.preventDefault()} />
      {!shown && <span className="live-empty" aria-hidden="true">▣</span>}
    </div>
    <p role={status === 'ended' ? 'alert' : 'status'} className="live-status">{message}</p>
    {status === 'ended' && <button className="primary" type="button" onClick={() => {
      setStatus('connecting');
      setAttempt(value => value + 1);
    }}>{t.liveReconnect}</button>}
  </section>;
}
