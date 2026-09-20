# Agent disk ring core (Issue #16)

`media_capture_agent.ring.DiskRing` stores immutable compressed segment bytes on
the Agent's approved media filesystem and a private SQLite ledger under the
configured runtime root. It supports one to four source UUIDs, duration/capacity
limits, shared incident references, autonomous loss transitions, critical
preserve requests and 60-day media expiry. No third-party runtime dependency,
decoded-frame history, HTTP route or credential type is introduced.

This is an independently testable core. The production CLI remains unpaired and
capture-unconfigured. Real segmenter/camera integration, authenticated transport
callbacks, Owner authorization and dashboard rendering remain the acceptance
dependencies in #11/#13/#15/#17 and #8/#10. Issue #16 stays open until those and
the physical Capture Node/Main/UVC tests pass. Calling this core directly from
the synthetic harness is not a claim that production capture is operational.

## Inputs and control boundary

`SegmentProfile` takes a source UUID, bounded/expected bitrate in bits per second,
fixed segment duration in integer microseconds, and an explicit per-segment
container/segment overhead bound. There is no guessed bitrate, reserve or
overhead default. `DiskRing` also requires an explicit `ledger_maximum_bytes`
limit for the SQLite main database; it has no deployment default. Each complete input segment must match that duration and stay
within its compressed byte bound. Different sources may have different profiles.
Overlapping/out-of-order segments, unconfigured sources and violations of the
profile bound are refused. Real segmenters must provide this bounded cadence
contract; a maximum duration alone does not bound segment count/overhead.

`append(source_id, start_us, end_us, bytes, now_us=..., clock_trusted=...)` receives
already encoded video-only data. The capture adapter is responsible for codec,
container, audio exclusion and decodability validation; the ring does not pretend
that inspecting arbitrary bytes establishes those facts. Tests generate compressed
patterns and do not claim video playback/codec acceptance.

The default `ControlAuthority` denies configuration and early incident deletion.
An integration must supply `require_owner(operation)` using approved application
authorization. Critical preservation separately calls `require_preserve()` from
the authenticated, narrowly scoped Agent control path. These injectable contracts
are not identity/session implementations, and no human API is enabled.

`observe_connection` receives observations from an authenticated transport
adapter. Only a previously authenticated connected state followed by an
unexpected loss of either authentication or connectivity creates a loss incident; repeated offline observations do not
create new incidents. Initial unpaired/offline startup creates none. A reconnect
does not remove or shorten existing protection. Future transport integration
must distinguish deliberate revocation/shutdown from unexpected loss and enforce
its command resource/rate bounds; the core does not establish remote trust itself.

Loss at T0 protects the requested interval `[T0-600s, T0+600s]`. Existing segment
references are pinned in one durable transaction, and subsequent local appends
whose intervals overlap the incident are protected without a Main connection.
An untrusted wall-clock observation cannot apply an expiry cutoff to a late
overlapping append; retained incidents keep their protection until trusted time
can establish expiry.
Loss observations with an untrusted or rolled-back clock use the last accepted
trusted timestamp and any fixed-cadence capture that continuously extends trusted
capture as their window anchor, never the jumped wall time or disconnected legacy
future segments. Timing
uncertainty remains visible while the incident is active and after completion.
If no trusted timestamp has ever been accepted, a durable pending-loss marker
holds the current ring against FIFO and reconfiguration. The first trusted
capture/maintenance observation creates an uncertain incident covering the held
ring and POST after that observation before releasing the hold. Status-only
reads do not release it; without enough ledger/disk budget, the hold remains and
the refusal is explicit. The hold is released in the same durable transition
that creates its incident, so an interrupted release cannot leave a durable
incident beside a marker that would admit a duplicate loss on recovery. Such protection never claims exact loss-time coverage.
Critical `server_movement`/`camera_tamper` preservation uses an explicit interval.
Profile changes are refused while post-loss protection is active so a new profile
cannot invalidate an in-progress capacity estimate.

## Disk admission and accounting

All media operations use #12's descriptor-pinned `MediaStore`, its current mount
identity checks, dedicated account and explicit hard reserve. Available bytes
already exclude every protected, ordinary and unrelated file on that filesystem.
Physical allocation uses `st_blocks * 512`, not a sparse file's logical length.
Estimated segments round up to the filesystem allocation unit. Window estimates
include two possible boundary segments per source as well as container overhead.

For a candidate configuration:

- `P` is the unique allocated size of usable segments intersecting the required
  pre-loss interval. A segment shared by multiple incidents is counted once.
- `R` contains only closed ordinary segments wholly outside that interval.
  Runtime credit additionally requires current selected-FIFO eligibility and
  trusted time. Future aging during POST provides no advance credit, avoiding
  assumptions about when released bytes become available. Protected, writing,
  unknown/orphan and required pre-loss files provide no reclaim credit.
- `B20` and `Bpost` are bounded aggregate estimates for 20 and 10 minutes.
- `L` is the conservative ledger completion headroom when runtime/media share a filesystem; otherwise it is zero on the media filesystem.
- Admission requires `free + R - reserve >= max(Bpost, B20 - P) + L`.

The shared-filesystem decision compares the verified pinned directory devices,
so a transient pathname substitution cannot cache a zero ledger reservation.
The runtime headroom estimate is conservative: later FIFO expiry becomes credit
at a subsequent trusted status check, and can clear an earlier pressure warning.

The pre-loss setting must itself hold at least ten minutes: duration is at least
600 seconds, and capacity is at least the bounded ten-minute estimate. The
selected whole duration/capacity target must also fit `free + existing ordinary
allocations - reserve - L`. This separate conservative setting check prevents choosing
a known impossible buffer size; existing ordinary allocations are part of that
target, not a claim that required pre-loss media can immediately be deleted.

When admission needs `R`, eligible files are deleted first and actual free space
is rechecked before configuration is committed. An unlinked file whose blocks
are still held by another process cannot provide fictional free space. Existing
protected incidents and other processes' disk usage can therefore cause a new
configuration to be rejected even when the ordinary limit alone appears valid.
During reconfiguration, pre-commit reclaim credit includes only files already
eligible for FIFO under the current setting as well as the proposed setting.
Current duration coverage and the current capacity allocation remain owned until
the new setting commits. A failed shrink therefore preserves the active ring;
it may require free space to be restored before the shorter setting can apply.
Capacity transitions must also fit the new pre-window envelope plus incompatible
legacy carryover (changed source/cadence/allocation bound or uncertain data),
and room for the next full source batch. A one-batch-only check is insufficient:
larger old segments may remain until several smaller new batches have arrived.
Unknown time credits no timestamp reclamation. Rejection leaves configuration,
profiles and currently owned media unchanged; existing over-limit capacity is
reported as pressure, including on restart.
Duration transitions likewise reserve the new full-duration envelope while
incompatible legacy rows remain allocated. Only trusted, retained, same-source
and same-cadence segments within the new allocation bound count toward that
envelope. Removed sources, uncertain data and larger old segments stay additional
carryover. This prevents a longer, lower-bitrate setting from fitting its final
target but exhausting space while the older high-bitrate media still belongs to
the new duration. The check runs before mutation and again after any permitted
reclamation; expired blocks are not credited before actual deletion.

Every media write retains `L` in addition to the hard reserve, and uses the store's exclusive
allocation/write/fsync path. Runtime status recomputes full protection headroom;
later external disk consumption yields explicit `STORAGE_PRESSURE` or
`STORAGE_HARD_STOP`, coverage/gaps and refused unsafe writes. Capacity limits use
physical ordinary allocations and exclude shared protected bytes. A provisional
write exceeding its actual allocation budget is rejected/cleaned before it is
admitted to the ring. The core never overwrites an unexpired protected segment to
make its status look healthy. Unrelated external filesystem writers remain a
deployment concurrency limitation; the storage layer verifies admission and
allocation outcomes, rather than claiming to control those writers.

## Ledger filesystem budget

Before creating the database, SQLite startup/hot-journal recovery, or any
transaction, the ledger checks available runtime-filesystem blocks against the
same explicitly configured safety reserve plus bounded metadata headroom. An
independent runtime filesystem gets its own check; a shared filesystem also
retains this headroom in every media admission and write. Pressure refuses new
mutations and reports `ledger_reserve_unavailable`; it does not delete protected
media. Recovery can require the operator to restore free space first.

The main database uses 4096-byte pages and an enforced `max_page_count` derived
from `ledger_maximum_bytes`. Oversized/unsupported existing databases and unsafe
journal/WAL sidecars are rejected before SQLite may perform recovery. The bound
allows the full maximum database plus every possible original journal page,
eight record bytes per page, one worst-case sector header and alignment per
page, a final sector and two filesystem allocation units for directory updates.
It conservatively retains the full bound even when current metadata already
occupies blocks; it never credits those occupied blocks as free.

The derivation follows SQLite's [rollback-journal format](https://www.sqlite.org/fileformat2.html#the_rollback_journal)
(each original page appears at most once, with an eight-byte record overhead)
and its [pager sector limit](https://github.com/sqlite/sqlite/blob/master/src/pager.c)
of 65536 bytes. The page-size/cap and DELETE-journal assumptions are enforced;
SQLite temporary stores stay in memory. The bound does not purport to reserve
exclusive disk capacity against unrelated processes or a filesystem failure.
DB-cap exhaustion is an explicit failure; schema history and incidents are never
reset to make capacity available. Interrupted transactions roll back even for
`KeyboardInterrupt` / `SystemExit`.

Configuration also checks that this page cap can hold the selected ordinary
ring and a complete new T-10/T+10 incident at every configured segment cadence.
Duration-mode row counts include boundary segments per source. Capacity-mode
counts use the [512-byte `st_blocks` unit](https://man7.org/linux/man-pages/man3/stat.3type.html)
as the minimum positive allocation, independently of the filesystem fragment
size. New zero-allocation media is refused before admission; such existing media
is uncertain at inventory/recovery. Maximum bitrate is never treated as a
minimum payload. Existing protected segments, incident tombstones and every
protection reference consume metadata capacity, including separate references
when incidents share one media file. Missing, untrusted or incompatible ordinary
rows consume additional capacity; they cannot replace future selected-ring rows.
New preservation requests must fit before any incident is created; active
incidents keep room for their remaining segment and reference rows across append
and restart. Overlapping requested windows share future segment-row reservations
per source, including distinct trusted coverage and boundary allowance for each
connected interval. Each incident still reserves its own protection references.
Untrusted timestamps never spend the reserved slots for corrected
trusted capture; admitting such segments requires additional row/reference room
before writing. Status exposes insufficient room
for the next incident as `STORAGE_PRESSURE / insufficient_ledger_capacity`.
Late media that reactivates a completed/partial incident must also fit that
incident's segment/reference reservation before reactivation or media writes.
A request that recovers trusted time also materializes any held pending loss
before its own incident is inserted, so admission is rechecked against the
combined incident set instead of the requested interval alone.

The admission bound deliberately does not assume average SQLite page packing.
Schema-v1 bounded UUID/numeric records and indexes need no overflow pages. The
[SQLite B-tree format](https://www.sqlite.org/fileformat2.html#b_tree_pages)
allows a conservative two pages per entry per tree, covering leaf and interior
pages: six pages per segment (table and two indexes), four per incident and four
per protection edge (table and primary-key index). Ten root pages and 64 pages
of transient split headroom are added; 4096-byte pages, no reserved page bytes
and no auto-vacuum pointer maps are required. This intentionally generous bound
can reject a cap that happens to fit one insertion order. The Owner must size
the explicit ledger cap and its filesystem reserve together. Continued incident
growth can still exhaust a finite cap; expiry does not silently erase tombstones
or promise unlimited incident storage.

## Durable recovery, time and deletion

The runtime directory must already exist, be private to the service account and
remain the same directory. A lifetime directory lock permits only one ledger
owner. SQLite uses foreign keys, FULL synchronization, explicit transactions and
a checked schema version; it is not recreated when an incompatible/corrupt
ledger is found. New ledger files use mode 0600 and symlinks/special files are
refused. The instance serializes operations and verifies directory/file identity.

A segment's interval, SHA-256 and `writing` state are committed before its media
write. Only after the store fsyncs it does the ledger mark it `stored`. On restart,
owned segment size/hash verification distinguishes a complete interrupted write
from a full-size but zeroed/partial allocation. Missing or uncertain files remain
gaps; uncertain protected files are retained for explicit expiry/deletion.
Unknown UUID files are reported as orphan allocation and are not automatically
deleted or treated as coverage/reclaimable space. Presence/size loss is also
reconciled when reporting status. The startup hash check is not a continuous
full-content integrity scan of every historical segment on every tick.

Per-source interval unions expose actual coverage and exact gaps. A completed
incident whose media later disappears reports `partial`. Multiple sources
finalizing their last segment separately cannot leave a stale partial/complete
result; late finalization re-evaluates coverage without extending the protected
interval's completion or expiry. Clock-uncertain segments never count as
trustworthy coverage.
An unexpired partial incident keeps overall status degraded even when every
existing file is intact and current pre-roll has recovered. Historical absent
intervals and clock uncertainty cannot disappear from health merely because
they have no missing-file row; expiry or authorized deletion ends that warning.

The integration supplies trustworthy **local capture time**, independently of
whether Main is reachable; Main loss alone does not mean the local monotonic
capture interval is unknown. Integer UTC microseconds describe intervals, and
the persisted highest trusted clock observation also detects backward movement across
restart. Explicit clock uncertainty or rollback degrades protection and suspends
automatic expiry until time is trusted. The future timing adapter must compare
wall/monotonic changes and assess forward jumps under the approved clock policy.
Rejected forward jumps never advance that persisted watermark. Corrected trusted
time can resume completion and expiry, including after restart, while affected
incidents retain their explicit clock-uncertainty flag.
An untrusted segment may only continue an existing contiguous per-source
chronology. It cannot establish an initial timeline or jump over a gap; those
appends are refused as `clock_uncertain` and active incidents stay visibly
uncertain. Trusted capture ordering uses only trusted segment endpoints, so a
legacy untrusted future endpoint cannot block corrected capture after restart.

Completion uses the protected interval's end, establishing
`completed_at = ended_at` and `expires_at = ended_at + 60 days`. A delayed trusted
tick immediately expires an incident whose deadline has already passed; restart,
clock recovery and late finalization do not start another 60-day period.
Owner-authorized early deletion does not need the clock to become
trusted. Deletion intent is durable before unlink, shared references keep media
needed by other incidents, and an interrupted delete resumes at restart/tick.
Media-root loss never creates a fallback directory. Deleted-incident tombstones
contain deletion state for the future UI; there is no deleted media export or
playback endpoint. Audit/tombstone presentation/retention integration is separate
from this media-expiry core and must follow the application's retention contract.

## Status DTOs and validation

`status()` provides selected mode/value/unit, projected maximum/expected bytes,
estimated capacity-mode duration, physical ordinary/protected/orphan usage,
filesystem free, reserve, required future bytes, pressure state and per-source
pre-loss intervals/gaps. Duration estimates use each profile's allocated segment
size and cadence; capacity bytes are never treated as elapsed seconds. Search
probes above capacity do not overflow the persisted numeric range.
`incident()` includes trigger, target interval,
completion, expiry, logical/allocated bytes, integrity/time gaps and deletion
state. Known damaged protected evidence keeps overall status degraded even after
its interval leaves the current pre-loss window. On unavailable storage, free space is `None` and the state is a hard stop;
the UI must not turn unknown capacity into a healthy zero/default.

Tests use temporary Linux filesystems, generated compressed patterns, a fake
quota that accounts for actual allocated files and controlled clock samples.
They cover one/four-source protection, both modes, pre-only quota rejection,
existing protected/other usage, actual reclaimed-block verification, shared
references, missing/corrupt recovery, clock rollback, partial post-loss capture,
60-day expiry and interrupted deletion. CI normal/error smoke executes actual
ring/SQLite writes under an accelerated synthetic timeline with no socket or
subprocess attempts, in a non-root/read-only/network-isolated container.

Run from `agent/`: `python -m unittest discover -s tests -p 'test_*.py' -v`.
Physical throughput, camera codecs, real 20-minute outage continuity, systemd,
mount behavior under deployment privileges, authenticated commands, UI permissions
and real browser rendering remain unchecked in `MANUAL_TEST.md`.


Incident deletion removes that incident's protection references. A segment is
physically unlinked only after every other incident and the current ordinary
ring have released it. In particular, deleting a recent incident never erases
the independent T-10 pre-roll. Duration/capacity FIFO then applies normally, so
unreferenced media outside the selected ring does not accumulate indefinitely.
`delete_incident` requires the current timestamp and explicit clock trust;
uncertain time/recovery conservatively retains ordinary ownership until a trusted
tick can apply the cutoff. No API promises secure erasure of other references.

Missing ordinary segments still within the selected duration/capacity window
keep status degraded even when the most recent ten minutes are complete.
Untrusted forward clock jumps do not authorize ordinary FIFO deletion.
