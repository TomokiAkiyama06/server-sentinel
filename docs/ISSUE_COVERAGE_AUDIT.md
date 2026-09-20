# Requirement-to-Issue Coverage Audit

監査日: 2026-09-21

対象: `REQUIREMENTS.md` を最上位のProduct Requirementsとして、`SPECIFICATION.md`、`ROADMAP.md`、`docs/SETUP.md`、`SECURITY.md`、`PRIVACY.md`、`MANUAL_TEST.md`、`docs/INITIAL_ISSUES.md`、`AGENTS.md` と全Open/Closed GitHub Issueを照合した。

分類は、要件を完了へ導く実装または検証Owner Issueが存在するかで判定する。Issueに関連語があるだけではCoveredとしない。`Covered` は実装完了ではなく、追跡可能なOwnerが登録済みであることを表す。

| Requirement | Classification | Owner Issue(s) | Notes |
|---|---|---|---|
| PRIV-001〜003 | Covered | #5, #7, #27, #47 | developer cloud/data/telemetryを禁止する実装・検証境界 |
| PRIV-004 | Covered | #49 | 本監査でOwner-initiated diagnostic exportを新規登録 |
| PRIV-005 | Covered | #12〜#19, #47 | self-hosted media pathとprivate listener |
| PRIV-006 | Covered | #25, #49 | local biometricとexportからの恒久除外 |
| PRIV-007 | Covered | #25 | non-owner identity libraryを禁止 |
| PRIV-008 | Deferred / Non-goal | — | 適用法令・noticeはdeployment ownerの外部責任で、MVPの実装要件ではない |
| PRIV-009 | Covered | #11, #12, #14, #27, #28 | Main/Agent/browserのvideo-only検証 |
| DIST-001 | Covered | #12, #47 | Capture AgentとMain Serverのstable distribution |
| DIST-002〜003 | Covered | #1 | public repository / Apache-2.0 bootstrap |
| DIST-004 | Covered | #51 | 本監査で横断license gateを新規登録 |
| CAM-001〜007 | Covered | #9, #17, #20, #24, #25 | source abstraction、profiles、roles |
| CAM-008〜010 | Covered | #11, #12, #27, #28 | stable identity、health、reconnect |
| CAM-011 | Covered | #12〜#15, #28 | remote-agent room-overview path |
| AGENT-001〜004 | Covered | #12 | service identity、non-root、video-only、outbound model |
| AGENT-005〜010 | Covered | #13〜#15 | trusted pairing、ingest、health、clock |
| AGENT-011 | Covered | #12 | versioned artifact / installer |
| AGENT-012〜015 | Covered | #16, #17, #27, #28 | disk ring buffer、incident evidence、retention |
| AGENT-016 | Covered | #12, #16, #28 | configurable media root / mount fail-safe |
| MEDIA-001〜003 | Covered | #17, #20 | profiles、benchmark、codec path |
| MEDIA-004〜006 | Covered | #19, #27, #28 | private multi-source live view / transport decision |
| MEDIA-007〜010 | Covered | #18, #21, #27, #28 | durable/manual/event evidence |
| DET-001〜003 | Covered | #20, #51 | detector baseline、pluggability、license gate |
| DET-004〜007 | Covered | #22, #24 | ROI/tamper/quality gate |
| DET-008〜011 | Covered | #25 | owner verification、anonymous tracking、zone crossing |
| EVENT-001〜003 | Covered | #26 | factual timeline、no culprit inference、attribution |
| PRES-001〜003 | Covered | #26 | states、override、suppression safety |
| STORE-001〜003 | Covered | #21, #50 | Main storageとrecording/audit retention |
| STORE-004〜006 | Covered | #21, #23, #27, #28 | allocation、starred recording、filesystem safety |
| INTEGRITY-001〜006 | Covered | #23, #28 | baseline、self-test、fail-safe、immediate alert |
| INTEGRITY-007 | Covered | #23, #49 | local-only identifiersとdiagnostic redaction |
| NOTIFY-001〜004 | Covered | #21, #23, #28 | optional direct Slack、alerts、daily summary |
| AUTH-001〜010 | Covered | #6, #7, #10, #19, #21, #28 | private reachability、app authorization、revocation |
| UI-001〜004 | Covered | #8, #10, #16, #19, #21, #48 | dashboard、access、buffer settings、setup flow |
| PERF-001〜003 | Covered | #15, #17, #19, #27, #28 | four-source target、adaptive inference、truthful degradation |
| TEST-001〜003 | Covered | #5, #11〜#28 | synthetic fixtures、manual hardware plan、required test families |
| DEV-001〜003 | Covered | #4, #5, #51 | PR/review gate、repository safety、license gate |

## Gaps registered by this audit

| Plan | Issue | Gap before registration |
|---|---|---|
| Plan 22 | #47 | Main Server deployment / install / release lifecycle |
| Plan 23 | #48 | First-run setup wizard と初期設定フロー |
| Plan 24 | #49 | Privacy-safe diagnostic export / support bundle |
| Plan 25 | #50 | Security / admin audit log と90日 retention |
| Plan 26 | #51 | Dependency / model license compliance gate |

Plan 19 (#21) remains the Owner for recording storage, capacity and Slack. Its audit-retention reference alone did not own security/admin audit events, sensitive-data exclusions, or the retention subsystem, so Plan 25 was registered as a separate cross-cutting owner. Plan 12 (#12) is a Capture Node installer and Plan 5 (#5) validates Compose where relevant; neither owns the Main Server lifecycle. Plans 12, 20 and 25 contain focused license/privacy checks, but none owned a repository-wide release gate (including material transitive and redistribution obligations) or generic diagnostic export.

The direct dependency graph in `docs/INITIAL_ISSUES.md` was updated with all five Issues. It has no self-dependency or cycle.
