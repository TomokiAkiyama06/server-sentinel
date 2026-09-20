import { useEffect, useState } from 'react';
import type { DashboardServices, Observation, ObservationKind, ObservationValue, TimelinePage } from '../domain';
import type { Messages } from '../i18n';

export const kindGroup: Record<ObservationKind, TimelineGroup> = {
  person: 'activity', motion: 'activity', owner_entry: 'activity', owner_exit: 'activity',
  anonymous_entry: 'activity', anonymous_exit: 'activity',
  server_movement: 'critical', camera_tamper: 'critical',
  camera_health: 'equipment', node_health: 'equipment', recording: 'equipment', storage: 'equipment',
  presence: 'configuration', configuration: 'configuration',
};
export const filters = ['all', 'activity', 'critical', 'equipment', 'configuration'] as const;
export type TimelineFilter = typeof filters[number];
export type TimelineGroup = Exclude<TimelineFilter, 'all'>;
export interface Span { degraded: boolean; items: readonly Observation[] }

export function matches(filter: TimelineFilter, kind: ObservationKind): boolean {
  return filter === 'all' || kindGroup[kind] === filter;
}

/** Detector results are image-quality gated; status and configuration events are not. */
export function detectorObservation(kind: ObservationKind): boolean {
  return kindGroup[kind] === 'activity' || kindGroup[kind] === 'critical';
}

/** Unreliable results stay unknown: never a negative, never a factual detection. */
export function displayValue(item: Observation): ObservationValue {
  if (item.quality === 'sufficient') return item.value;
  return item.value === 'not_observed' || detectorObservation(item.kind) ? 'unknown' : item.value;
}

export function untrusted(item: Observation): boolean {
  return !item.clock_trusted || item.uncertainty_us > 0;
}

/** Consecutive observations sharing one timing-trust state form a labelled span. */
export function spans(items: readonly Observation[]): readonly Span[] {
  const result: { degraded: boolean; items: Observation[] }[] = [];
  for (const item of items) {
    const last = result[result.length - 1];
    if (last && last.degraded === untrusted(item)) last.items.push(item);
    else result.push({ degraded: untrusted(item), items: [item] });
  }
  return result;
}

function stamp(value: string): string {
  return value.slice(0, 19).replace('T', ' ');
}

function attribution(item: Observation, t: Messages): string {
  const where = item.source_id ? `${t.attributionCamera} ${item.source_id.slice(0, 8)}`
    : item.node_id ? `${t.attributionNode} ${item.node_id.slice(0, 8)}`
      : t.attributionServer;
  return `${where} · ${t.detector}: ${t[`kind_${item.kind}`]}`;
}

function Row({ item, t, orderingBasis }: {
  item: Observation; t: Messages; orderingBasis: TimelinePage['ordering_basis'];
}) {
  const group = kindGroup[item.kind];
  const value = displayValue(item);
  const displayedAt = orderingBasis === 'received_at' ? item.received_at : item.occurred_at;
  return <li className={`timeline-row timeline-${group}`} data-observation-kind={item.kind}>
    <time className="timeline-time" dateTime={displayedAt}>{stamp(displayedAt)}</time>
    <span className={`timeline-dot timeline-dot-${group}`} aria-hidden="true" />
    <div className="timeline-detail">
      <p className="timeline-body">
        {t[`kind_${item.kind}`]}: {t[`value_${value}`]}
        {item.presence_state ? ` (${t[`state_${item.presence_state}`]})` : ''}
        {group === 'critical' && <span className="badge badge-critical">{t.criticalBadge}</span>}
        {/* A quality-gated result is never labelled confirmed. */}
        {item.confirmed && value === item.value && <span className="badge">{t.confirmedLabel}</span>}
      </p>
      <p className="timeline-meta">
        <span>{attribution(item, t)}</span>
        <span>{t.confidenceLabel}: {item.confidence === null ? t.confidenceUnknown : `${Math.round(item.confidence * 100)}%`}</span>
        <span>{t.qualityLabel}: {t[`quality_${item.quality}`]}</span>
        {untrusted(item) && <span>{t.receivedLabel}: {stamp(item.received_at)}</span>}
      </p>
    </div>
  </li>;
}

export function TimelineBody({ page, filter, t, onFilter }: {
  page: TimelinePage; filter: TimelineFilter; t: Messages; onFilter: (value: TimelineFilter) => void;
}) {
  const items = page.items.filter(item => matches(filter, item.kind));
  return <section className="timeline-screen">
    <p className="muted">{t.timelineNeutral}</p>
    <p className="muted">{t.utcNote} {t.confidenceCaveat}</p>
    <p className={page.ordering_degraded ? 'timeline-notice timeline-notice-degraded' : 'timeline-notice'}
      role={page.ordering_degraded ? 'status' : undefined}>
      {page.ordering_basis === 'received_at' ? t.orderingReceived : t.orderingOccurred}
      {page.ordering_degraded ? ` ${t.orderingDegraded}` : ''}
    </p>
    <div className="timeline-filter" role="group" aria-label={t.filter}>
      {filters.map(name => <button key={name} type="button" aria-pressed={filter === name}
        onClick={() => onFilter(name)}>{t[`filter_${name}`]}</button>)}
    </div>
    <p className="source-count">{t.observationCount}: {items.length}</p>
    {items.length === 0 && <p>{t.timelineEmpty}</p>}
    {spans(items).map(span => <section key={span.items[0].id}
      className={span.degraded ? 'timeline-span timeline-span-degraded' : 'timeline-span'}>
      {span.degraded && <p className="timeline-degraded" role="status">{t.timelineDegraded}</p>}
      <ol className="timeline-list">{span.items.map(item => <Row key={item.id} item={item} t={t}
        orderingBasis={page.ordering_basis} />)}</ol>
    </section>)}
  </section>;
}

type State = { state: 'pending' } | { state: 'loading' } | { state: 'failed' } | { state: 'ready'; page: TimelinePage };

export function TimelineScreen({ services, t }: { services: DashboardServices; t: Messages }) {
  const [data, setData] = useState<State>({ state: 'pending' });
  const [filter, setFilter] = useState<TimelineFilter>('all');

  useEffect(() => {
    // Bound to the service so class-based providers keep their receiver.
    const load = services.loadTimeline?.bind(services);
    if (!load) return;
    const controller = new AbortController();
    setData({ state: 'loading' });
    void (async () => {
      try {
        const page = await load(controller.signal);
        if (!controller.signal.aborted) setData({ state: 'ready', page });
      } catch {
        if (!controller.signal.aborted) setData({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [services]);

  if (data.state === 'failed') return <p role="alert">{t.timelineUnavailable}</p>;
  if (data.state === 'loading') return <p role="status">{t.checking}</p>;
  if (data.state === 'pending') {
    return <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span>
      <h2>{t.timeline}</h2><p>{t.foundation}</p></section>;
  }
  return <TimelineBody page={data.page} filter={filter} t={t} onFilter={setFilter} />;
}
