import { useState } from 'react';
import { type RecordingSummary } from '../domain';
import { type Catalog } from '../i18n';
import { bytes, duration, timestamp } from '../shared/format';

/** Browser playback only: no download, export or copied-media route exists here. */
export interface RecordingActions {
  star(recording: RecordingSummary): void;
  remove(recording: RecordingSummary): void;
}

const filters = ['all', 'event', 'critical', 'starred'] as const;
type Filter = typeof filters[number];

function matches(recording: RecordingSummary, filter: Filter): boolean {
  if (filter === 'all') return true;
  if (filter === 'starred') return recording.starred;
  return recording.kind === filter;
}

function filterLabel(t: Catalog, filter: Filter): string {
  if (filter === 'all') return t.filterAll;
  if (filter === 'starred') return t.filterStarred;
  return t[`kind_${filter}`];
}

export function RecordingsView({ t, recordings, owner = false, actions }: {
  t: Catalog;
  recordings: readonly RecordingSummary[];
  owner?: boolean;
  actions?: RecordingActions | undefined;
}) {
  const [filter, setFilter] = useState<Filter>('all');
  const [playing, setPlaying] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const visible = recordings.filter(recording => matches(recording, filter));
  const selected = visible.find(recording => recording.id === playing);
  const manageable = owner && actions ? actions : undefined;

  return <section className="recordings">
    <div className="filters" role="group" aria-label={t.filterLabel}>
      {filters.map(item => <button key={item} type="button" aria-pressed={filter === item}
        className={filter === item ? 'filter filter-active' : 'filter'}
        onClick={() => setFilter(item)}>{filterLabel(t, item)}</button>)}
    </div>
    <p className="source-count">{t.recordingsCount}: <span className="numeric">{visible.length}</span></p>
    {visible.length === 0 ? <p>{t.noRecordings}</p> : <div className="table-scroll"><table className="records">
      <caption className="muted">{t.recordingsCaption}</caption>
      <thead><tr>
        <th scope="col">{t.columnTime}</th>
        <th scope="col">{t.columnCamera}</th>
        <th scope="col">{t.columnKind}</th>
        <th scope="col">{t.columnDuration}</th>
        <th scope="col">{t.columnSize}</th>
        <th scope="col">{t.columnRetention}</th>
        <th scope="col">{t.columnPlayback}</th>
        {manageable && <th scope="col">{t.columnActions}</th>}
      </tr></thead>
      <tbody>{visible.map(recording => <tr key={recording.id} data-recording-id={recording.id}>
        <td className="numeric">{timestamp(recording.start_ms)}</td>
        <td>{recording.source_name}</td>
        <td><span className={`kind kind-${recording.kind}`}>{t[`kind_${recording.kind}`]}</span></td>
        <td className="numeric">{duration(recording.duration_ms)}</td>
        <td className="numeric">{bytes(recording.size_bytes)}</td>
        <td>{recording.starred || recording.retention_days_left === null
          ? <span className="badge">★ {t.neverAutoDeleted}</span>
          : <span className="numeric">{recording.retention_days_left} {t.daysUnit}</span>}</td>
        <td><button type="button" aria-expanded={selected?.id === recording.id} aria-controls="playback"
          onClick={() => setPlaying(current => current === recording.id ? null : recording.id)}>{t.play}</button></td>
        {manageable && <td className="row-actions">
          <button type="button" onClick={() => manageable.star(recording)}>
            {recording.starred ? t.starOff : t.starOn}</button>
          {confirming === recording.id ? <>
            <button type="button" className="danger" onClick={() => { setConfirming(null); manageable.remove(recording); }}>
              {t.confirmDelete}</button>
            <button type="button" onClick={() => setConfirming(null)}>{t.cancel}</button>
          </> : <button type="button" onClick={() => setConfirming(recording.id)}>{t.deleteRecording}</button>}
        </td>}
      </tr>)}</tbody>
    </table></div>}
    {selected && <aside className="playback" id="playback">
      <h2>{t.play}: {selected.source_name}</h2>
      <p className="numeric">{timestamp(selected.start_ms)} · {duration(selected.duration_ms)}</p>
      <p role="status">{t.playbackPending}</p>
      <p className="muted">{t.playbackBrowserOnly}</p>
    </aside>}
    {manageable && <p className="muted">{t.ownerOnlyActions}</p>}
  </section>;
}
