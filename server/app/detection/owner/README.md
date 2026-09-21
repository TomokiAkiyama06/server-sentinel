# Optional local Owner verification

Issue #25 provides an internal 1:1 verification boundary, private singleton
template persistence and synthetic adapters only. No human route, face detector,
production face model/weights or comparison threshold is enabled. Model/weights,
their separate licenses, final thresholds and hardware feasibility remain Owner
decisions. The existing person-detector evaluation is not a face-model decision.

`OwnerTemplateStore` requires a pre-created private runtime directory outside
checkout (`0700`, current UID), an explicit template-byte limit and a metadata
reservation context factory. The fixed `owner-template.sqlite3` is a separate
private regular file (`0600`, one hard link), with a private contiguous migration
history. It is never part of a main-database/diagnostic archive. A directory lock
and creating-worker checks enforce a single owner; symlink/FIFO/shared-file,
root/file substitution and missing-root errors fail closed without mkdir fallback.
The connection is opened through the already verified directory descriptor
(`/proc/self/fd/<dirfd>`) and re-verified before any schema write, so a symlink
or directory substituted after those checks cannot redirect it; an unavailable
descriptor fails closed instead of reopening by re-resolved path. SQLite canonicalizes that
filename and derives auxiliary names such as the rollback journal, which holds
pre-update template pages, from the ordinary path, so every ancestor of the
private root must also be unsubstitutable: owned by the service or root and not
writable by others unless sticky. Deployments therefore cannot place the root
under a world-writable non-sticky directory.
Deployment wiring must reserve worst-case database, rollback journal and audit
growth before construction/mutation, and pass this store to the Main Server's
audit-retention runtime. Its bounded maintenance connection repeats the private
root/file identity and permission checks, uses the storage reservation, and
deletes only `owner_template_audit` rows older than the 90-day default. It never
reads or changes `owner_template`. No production storage policy is silently
installed by this module.

Enrollment/replacement/delete require `OwnerAuthorizer.require_owner(operation)`;
the default denies, and the implementation must validate an actual current
application principal. Enrollment authorizes `ENROLL` before reading any
private state, so an unauthorized caller cannot probe whether a template exists;
overwriting an existing template additionally requires `REPLACE` from the same
principal. Mutations atomically check expected generation, advance
it and audit the actor UUID, operation and UTC time. Raw template/provenance is
private to the verifier, never an audit payload. Replacement/delete invalidate
old and in-flight results. `secure_delete=ON`, DELETE journals and FULL sync are
used, but logical deletion is not a claim of forensic erasure on SSDs, snapshots
or backups. File permissions are not encryption; encryption/key custody is not
invented here. Local administrators remain within the documented trust boundary.

An audited `LocalVerifier` implements `enroll`, `compare` and `forget_candidate`,
and supplies exact local `ModelProvenance` (model/version, code and weight
licenses, upstream, artifact and comparison-policy SHA-256, explicit review ID).
Metadata validates format/identity, not license approval. There is no downloader,
external service, opt-in upload path or production adapter. Missing adapter,
unenrolled template, stale generation/provenance, invalid quality or failed
comparison yields `unknown`; storage failures propagate fixed unavailable errors.
Adapter cleanup failure cannot return a trusted match or complete enrollment.
A null template is reserved for Owner deletion: an adapter that returns no
template fails enrollment/replacement instead of clearing the enrolled template,
advancing the generation or auditing a non-enrollment as `ENROLL`/`REPLACE`.
This boundary is not a sandbox for untrusted Python plugins.

Call `service.assess(candidate, gate, context=target_context)` on an
`owner_verification` QualityGate. The service assesses the candidate's actual
immutable crop and returns an opaque `OwnerAssessment`. A bounded weak reference
binds that ticket to the exact candidate object; another crop from the same
source/stream/sequence cannot reuse its quality decision. This retains no extra
crop bytes or derived face fingerprint. Supply target-size/occlusion context for
that crop, not another person in the image. Then pass the candidate, gate and
assessment to `enroll` or `verify`. Use an independently calibrated gate per
target stream when several crops from one camera frame are assessed; detector
and crop extraction integration remains pending. Call `close_session` on reset.

Match results carry service-issued, bounded receipts. `is_current` accepts only
the original issued object while its template generation and exact quality
assessment remain current. They cannot authorize a human session. There is no
non-Owner enrollment parameter/API, persisted candidate table, profile library
or cross-camera matching interface. Verifier candidate/intermediate state is
released on success/failure; anonymous tracking uses only geometric positions.

`diagnostic_snapshot()` always returns only enrollment state and generation,
including explicit Owner exports. Do not collect this private directory in any
diagnostic archive, introspect private fields, install SQL trace logging, or log
frames/adapter inputs. Normal authorized recording exports are a separate feature
and never authorize exporting this database or invoking a biometric service.

Tests and isolated normal/error smoke use repository-generated shapes and an
explicit synthetic verifier. They validate persistence, boundaries, failure and
no-egress behavior, not face recognition accuracy or a production threshold.
Real Owner/model/room checks remain in `MANUAL_TEST.md` N/O.
