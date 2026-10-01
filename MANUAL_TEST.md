# ServerSentinel Manual / Real-Hardware Test Plan

This document contains checks that cannot be truthfully completed using software mocks alone.

Do not mark an item PASS without performing it on the stated hardware/network/browser environment. Do not commit or attach real monitoring footage, real-person images/video/audio, owner biometric templates, or private deployment values to GitHub.

Issue #7's backend foundation uses temporary SQLite and in-process ASGI tests;
it does not mark any check here PASS. Before opening human routes under #10,
verify the documented launcher binds only to the intended loopback boundary,
the proxy cannot be bypassed, and generic denial also covers schema/version,
static assets and errors. No unauthenticated HTTP health exception is provided.

## Test metadata

Issue #16's disk-ring core has only synthetic filesystem/quota/clock acceptance.
Before closing #16, run the existing Agent buffer/outage checks with the real
segmenter/profile and authenticated transport: verify each source retains the
full T−10/T+10 interval, confirm real segment/container/block overhead fits the
admission bound, and inspect partial/gap reporting during actual disk pressure
and mount loss. Verify Owner-only mode/value/deletion controls and DTO rendering
through #10-authorized routes. Do not record those physical/UI checks as passed
because the temporary-filesystem tests succeeded.

```text
Date:
ServerSentinel version / Git commit:
Main Ubuntu version / hardware:
Capture-node Ubuntu version / hardware:
Camera source(s) / model(s):
USB topology:
LAN topology/speed:
Tailscale/private-access path:
Phone/Mac/desktop browser used for viewing:
Recording volume:
Tester:
```

## A. Local UVC / USB camera

Issue #11 implementation status (2026-09-20): synthetic discovery, driver-ioctl,
identity, restart-persistence and registry integration tests passed. No physical
camera was opened and no actual preview, audio-device trace or arm64 execution
was verified. All hardware checkboxes below remain unverified.

After the Owner-authorized management and worker/preview wiring are available,
run the following on the intended Main Ubuntu host under its dedicated account:

1. Record model, supported profile, device permission and stable evidence in a
   private local test record; publish only pass/fail and non-sensitive counts.
2. Enable one source with an explicit profile and select its current physical
   candidate. Verify negotiated dimensions/FPS/FourCC and first-frame transition
   from degraded to online. Repeat with up to four sources.
3. Observe the service's opened descriptors locally while the camera's integrated
   microphone is present; only the selected video device may be opened, never
   ALSA/OSS microphone devices. Do not publish trace paths or captured media.
4. Unplug one camera. Verify its offline audit event, continuing service process,
   and uninterrupted second source. Reconnect a unique serial camera with changed
   video-node numbering and verify the same source UUID returns online only after
   a new frame. Disable it and verify its video descriptor is closed.
5. Reorder identical non-serial devices, including the case where only one is
   reattached. Verify manual intervention; restart the backend and verify the
   latch still holds. Explicitly reapprove the current candidate and confirm video
   resumes. Duplicate-serial evidence must also require manual intervention.
6. Check unsupported profile/permission, driver timeout and corrupted-frame paths
   are visibly unavailable, never healthy; restore the supported configuration.
7. Using a disposable database, inject a failed ambiguity-latch write and stop the
   worker without clean shutdown. Restart with one formerly duplicated serial
   device remaining: it must require Owner reapproval. Repeat with no capture
   profile; the manual-intervention state must remain visible. A normal clean
   shutdown/restart of an unambiguous serial device may reconnect automatically.

Backend runtime wiring status (2026-09-29): the lifespan now starts/stops
`LocalUvcRuntime` for the deployment `local_uvc` source list, and frames reach
the authorization-bound preview session layer. This was verified only with
synthetic discovery/capture adapters and synthetic frame bytes; no physical
camera, V4L2 node, udev rule or real frame was used.

#### Real-hardware runtime procedure (serial-bearing UVC cameras)

Use one or more USB UVC cameras that report a USB serial number (for example
conference-style or speakerphone-integrated webcams from vendors such as EMEET
or Yamaha; any serial-bearing UVC model is suitable). Record the exact models,
serials, by-id names and ports only in the private local test record.

1. Create the `local_uvc` registry sources with explicit capture profiles, list
   their UUIDs in the private deployment `local_uvc` object, and run
   `--check`. Confirm that an unknown key, a device path in place of a UUID, a
   duplicate UUID and a fifth UUID each fail validation without echoing values.
2. Start the service without the `local_uvc` object once and confirm the
   `local_uvc_unconfigured` log event and that no video node is opened.
3. Start with the object. Before Owner approval, confirm each source stays
   `offline` and the service holds no `/dev/video*` descriptor.
4. Approve one camera through the audited Owner path (stop-worker reapproval).
   Confirm `degraded` until the first frame, then `online`, the negotiated
   profile, and an `approve_camera` audit record. Repeat for up to four sources.
5. Unplug one camera: confirm that source becomes `offline`, the service stays
   running (process and other sources unaffected, their frames continue), and a
   `local_uvc_source_health_changed` log line contains no path, serial or UUID.
6. Replug it into a different port so its video node number changes: it must
   return `online` automatically as the same source UUID after a new frame.
7. Connect a second camera of the same model with the same (or no usable)
   serial, or reproduce that with a controlled mock: the source must become
   `manual_intervention_required`, deliver no frames, and stay so across a
   service restart until explicitly reapproved.
8. Stop the service (`systemctl stop`) while capturing: confirm all video
   descriptors close within the join bound, the sources are `offline`, and a
   clean restart reconnects a unique-serial camera automatically. Simulate a
   hung driver if practical and confirm `local_uvc_stop_failed`; if the process
   is terminated before that worker exits, the next start must require Owner
   reapproval.
9. While capturing, confirm no ALSA/OSS/microphone device of the integrated
   speakerphone/microphone is opened (inspect `/proc/<pid>/fd` locally; do not
   publish paths).
10. With an invited `live:view` principal (once the authorized viewer route
    exists), confirm preview frames are delivered; with a `recordings:view`-only
    principal and after revoking `live:view`, confirm refusal and that no frame
    is retained without viewers.

Results: **PARTIAL — 2026-09-30 に実機確認を一部実施（本節の 2026-09-30
実機記録を参照。各記録の未実施・不合格項目はそれぞれの記録に記載）。
非serial同型機・3–4 source・低照度・browser viewer（手順 10）・deployment
launcher/systemd（手順 1, 2, 8）は未実施。Issue #11 はこれらの記録では close しない。**

For each tested camera:

- [ ] exact manufacturer/model and advertised UVC resolution/FPS/pixel-format/codec capabilities are recorded locally;
- [x] device is discovered;（2026-09-30 Issue #101 記録、serial 付き同型 2 台）
- [x] stable identity evidence is shown where available;（同記録: serial 照合で復帰）
- [ ] owner can enable/disable source;
- [ ] preview works;
- [ ] negotiated resolution/FPS/format is reported;
- [x] unplug creates `offline` event/state;（同記録 手順 1。ただし触れていない
      source の健全性表示は不合格。同記録を参照）
- [x] reconnect works when identity is unambiguous;（同記録 手順 2・3）
- [x] reboot/re-enumeration does not silently bind a different device through `/dev/videoN` reuse;
      （同記録 手順 4: 逆順再列挙 + runtime 再起動。host 再起動は未実施）
- [ ] no unnecessary privileged container is required.

#### 実機記録 2026-09-30（Main Server 候補、serial 付き同型 UVC × 2）

```text
Date: 2026-09-30
ServerSentinel version / Git commit: 83d387f (main)
Main Ubuntu version / hardware: Ubuntu LTS の x86_64 desktop 機（multi-core CPU、
  discrete GPU 搭載。desktop session 常駐の開発機で、専用 service account ではない）。
  正確な OS/kernel・CPU・RAM・GPU は INTEGRITY-007 によりローカル記録のみ
Capture-node: 未使用（remote_agent は対象外）
Camera source(s) / model(s): serial 付き同型 USB UVC camera × 2（同一
  vendor/product、各個体が一意の USB serial を報告。UVC 内蔵マイク付き）。
  正確な model と advertised mode 一覧はローカル記録のみ。概略: MJPG は最大
  1920x1080@30、YUYV は 640x480 以下 @30、4K 非対応
USB topology: 2 台とも USB 2.0 high-speed 接続（controller・port はローカル記録のみ）
Tester: Claude Code（Owner 指示による自動実行。実行ユーザーは video group の
  非 root ユーザー、sudo/root 不使用）
```

実行方法: `create_app()` の lifespan を一時 SQLite（repository 外の一時
directory、実行後削除）で起動し、既定の `LocalUvcDependencies`（実
`LinuxDiscovery` + `MmapCapture`）で 2 source の `local_uvc` を構成した。
Owner 承認は `LocalUvcRuntime.reapprove()` → `OwnerAdministration.approve_uvc()`
の監査付き経路だが、**authorizer は stand-in**（Owner WebAuthn 経路が未接続の
ため）。frame は件数・byte 数・JPEG SOI/EOI marker・V4L2 sequence だけを
メモリ上で数えて破棄し、画像は保存・閲覧していない。serial・by-id 名・
device path・USB port・source UUID は本記録に含めない（INTEGRITY-007 / PRIVACY）。
以下「カメラA/B」は serial の hash 順で付けた一時ラベル。

| # | 確認内容 | 結果 | 区分 |
|---|---|---|---|
| A-1 | discovery: sysfs の video node 4 個（各カメラ capture + metadata）のうち capture 対応 2 個だけを検出、失敗 0。両方 `MJPG`/`YUYV`、serial あり、by-id alias 1、topology あり | PASS | 実機確認済み |
| A-2 | 同型判定: 2 台の `model_key` は同一、serial-backed `strong_key` は 2 個で相異なる | PASS | 実機確認済み |
| A-3 | `/dev/videoN` 非依存: A の承認 evidence の node path/番号/by-id/topology を B のものに置換しても `identity_matched` で**実 A** を選び B を選ばない | PASS | 実機 evidence + 論理置換（物理抜線なし） |
| A-4 | A 不在で同型 B のみ存在（A 抜線相当をメモリ上で再現）: `offline` / `approved_device_absent`、B を bind しない | PASS | 実機 evidence のサブセット（物理抜線なし） |
| A-5 | 非 serial 同型（serial を除去した evidence）: 2 台でも 1 台でも `manual_intervention_required` / `identity_not_unique`。重複 serial: `duplicate_identity` | PASS | 実機 evidence 由来の mock（使用機は serial 付きのため物理再現不可） |
| A-6 | `local_uvc` 未構成で起動: `unconfigured`、`local_uvc_unconfigured` log、video/audio descriptor 0 | PASS | 実機確認済み |
| A-7 | 構成済み・未承認: 2 秒間 両 source `offline`、discovery scan 0 回、video descriptor 0。未承認 idle の process CPU 0.25%（1 core 比） | PASS | 実機確認済み |
| A-8 | Owner 承認（stand-in authorizer）後 0.60–0.72 秒で `online`、negotiated `1920x1080 30fps MJPG`、`approve_camera` 監査 1 件。非 Owner actor の承認は拒否され source は `offline` のまま | PASS（authorizer は stand-in） | 実機確認済み（部分） |
| A-9 | 承認経路の遷移は `offline → online`（`degraded` を経由しない）。clean restart 経路は `degraded(identity_matched) → online` | 手順 4 の期待（degraded until first frame）と差異 | 実機確認済み（下記 提案-3） |
| A-10 | 2 source 同時 `online`。開いている video node は承認済み capture node 2 個だけ（metadata node・他 node は 0）。`/dev/snd` 等 audio descriptor は全工程で 0（内蔵マイクの ALSA capture device は存在） | PASS | 実機確認済み |
| A-11 | source 1 を監査付き `update_source(enabled=False)`: `offline`、source 1 frame 0、source 2 は継続（3 秒で 90 frame）、source 1 の descriptor は閉じる。再有効化で `online` | PASS | 実機確認済み |
| A-12 | lifespan 停止: 0.20–0.31 秒で `stopped`、両 source `offline`、video descriptor 0 | PASS | 実機確認済み |
| A-13 | 同じ DB で clean restart: 再承認なしで両 source 0.69–0.80 秒で `online`（serial 一意） | PASS | 実機確認済み |
| A-14 | log: 全工程の log に serial / device path / by-id / topology / source UUID の出現 0。出力は固定 event 名のみ | PASS | 実機確認済み |
| A-15 | 非対応 profile 要求（4K MJPG、60fps、一覧外 15fps、H264、YUYV 1080p）: driver 調整後の profile（1080p / 30fps / MJPG / 640x480）を negotiated として正しく記録するが、health は `online` | 手順 6 の期待（visibly unavailable, never healthy）と不一致 | 実機確認済み（下記 重要-2） |
| A-16 | 同じ物理カメラ A を source 2 にも Owner 承認: **受理される**。source 2 は EBUSY で `degraded ↔ offline` を反復し、restart 後もどちらの source が取得するかは起動順依存 | FAIL | 実機確認済み（下記 重要-1） |

本記録で見つかった問題（修正は別 PR / Owner 判断）:

- **重要-1**: `prepare_approval()` は候補が現 scan に 1 個あることだけを確認し、
  別 source に承認済みの同一 physical camera（同一 `strong_key`）を拒否しない。
  同型 serial 付きカメラで Owner が候補を取り違えると、1 source が恒常的に
  flapping し、restart 後の割当が起動順に依存する。
- **重要-2**: 非対応の desired profile が driver に黙って調整され、`online` のまま
  になる（negotiated profile の記録自体は正確）。MANUAL_TEST 手順 6 の期待と
  合わない。desired と negotiated の不一致を `degraded` / 拒否とするかは Owner 判断。
- **提案-1**: registry の negotiated fps は driver の frame interval（30）で、実配信
  fps は記録されない。1 回目の計測では両カメラとも実配信 16.65 fps（V4L2 sequence
  の欠落 0、gstreamer の独立経路でも約 15 fps、`exposure_auto_priority=1`）だったが
  health は `online`・negotiated 30 のままだった。2 回目（数十分後）は 30.0 fps。
  照度の評価はしていない（映像を閲覧していないため）。露出優先による
  frame rate 低下と推定されるため、L 節の低照度確認で実 fps を記録すること。
- **提案-2**: `CaptureSession.step()` は frame ごとに `LinuxDiscovery.scan()` を実行する
  （1 回 0.73–0.80 ms、2 source × 30 fps で 60 scan/s。capture CPU の約半分に相当）。
  無効化された source も retry ごとに scan する。
- **提案-3**: 監査付き承認経路では `degraded` を経由せず `offline → online`
  （negotiated profile は `offline` の間に書かれる）。手順 4 の記述か実装を揃える。
- **提案-4**: `MmapCapture` は Python `mmap` が fd を複製するため、1 source あたり
  video descriptor が 5 個（本体 + buffer 4）になる。停止時にすべて閉じることは確認
  済み。「one descriptor」という docstring とは差がある。

**要人手**（物理操作が必要。下記の観測は Claude が観測用 script を起動した
状態で行う想定。state directory は repository 外に置き、終了後に削除する）:

1. **抜線（手順 5 / A-4 実機版）**: 2 source とも `online` の状態で、カメラ A の
   USB ケーブルだけを抜く。期待: A の source だけが 1–2 秒以内に `offline`、
   B は 30 fps 前後を維持、service は `running`、log に識別子なし、A の video
   descriptor は閉じる。
2. **別ポートへ再接続（手順 6）**: 抜いた A を、B とも元とも異なる USB ポートに
   挿す（`/dev/videoN` 番号が変わることを期待）。期待: 同じ logical source が
   新しい frame 受信後にだけ自動で `online` に戻り、B の source には影響しない。
3. **2 台のポート入替**: 両方を抜き、互いのポートに入れ替えて挿す。期待: 各
   logical source が port ではなく serial に従って元のカメラへ戻る。
4. **再起動 / 再列挙**: 観測用 state を保持したまま host を再起動（または両方を
   抜いて逆順に挿し直し node 番号を入れ替え）、service 相当を再起動。期待:
   `/dev/videoN` の再利用で別カメラを黙って bind しない。
5. **非 serial 同型機（手順 7 / Ambiguous identical-device test）**: 使用機は serial
   付きのため不可。serial を報告しない同型 UVC 2 台を用意できる場合のみ実施し、
   抜き差し・並べ替えで `manual_intervention_required`、restart 後も latch 維持、
   明示再承認後にだけ復帰することを確認する。用意できなければ mock 確認のみのまま。
6. **レンズ遮蔽・低照度（L 節と共通）**: 片方のレンズを覆う、および室内照明を
   落とす。期待値を定めた上で、実配信 fps・health・image quality 表示を記録する
   （提案-1 の再現確認を兼ねる）。
7. **deployment launcher / systemd（手順 1, 2, 8）**: 管理者所有の deployment 設定
   （root 所有ファイル）と systemd unit のインストールが必要なため Owner が実施。
   `--check` の検証（未知 key・device path・重複 UUID・5 個目）、`systemctl stop`
   中の descriptor close、hung driver 時の `local_uvc_stop_failed`。
8. **3–4 source**: カメラが 2 台のため未実施。追加の UVC を接続して実施。
9. **authorized preview（手順 10）**: 認可済み viewer route と browser 統合の完成後。

### Ambiguous identical-device test

Where possible use two identical UVC devices without a usable unique serial, or a controlled mock reproducing that identity ambiguity.

- [ ] disconnect/reorder devices;
- [ ] system does **not** arbitrarily choose one as the old source;
- [ ] source enters `manual_intervention_required`;
- [ ] owner can explicitly re-approve a physical mapping;
- [ ] healthy monitoring resumes only after approval.

### 実機記録 2026-09-30: 抜き差し・ポート入替・再列挙・遮蔽（Issue #101）

```text
Date: 2026-09-30
ServerSentinel version / Git commit: runtime は PR #99 HEAD a0497ee、
  観測 helper は PR #96 HEAD beab9f4 の scripts/manual/uvc_watch.py
  （いずれも本記録時点で未マージ）
Main Ubuntu version / hardware: Main Server 候補ホスト（正確な OS/kernel・
  hardware はローカル記録のみ）
Camera source(s) / model(s): 同一機種 USB UVC カメラ 2 台（シリアルあり、異なる）
USB topology: 2 台とも同じ USB バス上（controller・port はローカル記録のみ）
Tester: 物理操作（抜き差し・ポート入替・レンズ遮蔽）は人が実施。状態・fps・
  descriptor・kernel log の観測と記録は Claude Code（video group の非 root
  ユーザー、sudo 不使用）
```

`uvc_watch.py` は frame を件数だけ数えてメモリ上で破棄し、disk へは 1 frame も
書いていない（画像の保存・閲覧なし）。serial・by-id 名・device path・USB port・
source UUID は本記録に含めない。以下、カメラ A = `src1`、カメラ B = `src2`。
「区分」の *人手* は人が物理操作した項目、*観測* は Claude が watch 出力と
kernel log から確認した内容を示す。

| 手順 | 操作（人手） | 観測結果（Claude） | 判定 |
|---|---|---|---|
| 0 | 片方のレンズを覆って A/B を判別 | 覆ったカメラの source だけ 30 → 約 17 fps、他方は 30 fps のまま。両方 `online` を維持 | PASS |
| 1 | A だけを抜く | `src1` が `offline`（`approved_device_absent`）、service は継続。kernel log では A の抜線直後に同じ port で短い切断/再列挙の揺れがあり、約 7 秒後に**触れていない B** も切断・再列挙した。`src2` は `identity_matched` で自動復帰し 30 fps に戻った。ただし B の切断が表面化するまでの約 5 秒間、`src2` は **0 fps のまま `online`** を報告した | `src1` の `offline` 化・service 継続・`src2` の自動復帰（取り違えなし）は PASS。**「他 source が影響を受けず frame を出し続ける」は FAIL**: B の一時切断は同一バスの相互リセット（既知制約として許容、下記）だが、その間 0 fps を `online` と表示したのは **不具合**（下記） |
| 2 | A を別ポートへ挿す | 1 回目は同じ kernel port に列挙されたため再試行。再試行では A が別 port・別 `/dev/video` node に列挙され、`src1` は serial 照合で再承認なしに `online` へ戻った | PASS |
| 3 | A と B のポートを入れ替え、A を覆う | 両方 `online` に戻り、A を覆うと下がるのは `src1` だけ（割当は port ではなくカメラ個体に追従）。`manual_intervention_required` にならない。入替中に B 側で約 4 秒間 **0 fps のまま `online`** | 割当の追従は PASS。入替中の 0 fps `online` 表示は **FAIL**（手順 1 と同じ不具合） |
| 4 | runtime 停止 → 両方抜いて逆順に挿し直し → `--approve` なしで再起動 → A を覆う | `/dev/video` 番号は承認時と逆順になったが、両方 `identity_matched` で正しい source に戻り、A を覆うと下がるのは `src1` だけ。遮蔽中に A が 1 回 USB 切断し、自動復帰した | PASS |
| 5 | A のレンズを 30 秒覆う | fps は約 16–17 に低下（MJPEG frame size は約 150 → 220 KiB に増加）、状態は `online` のまま、V4L2 の error flag 付き frame なし、timeout なし。単体診断（1 台 / 2 台同時）と計装した runtime 実行でも同じ | 観測を記録（#22 の材料） |
| 5 | 部屋の照明を落とす | **未実施**（室内照明を消せなかった） | 未実施 |

全手順を通して `audio_fds=0`（video-only を維持）。停止時は `video_fds=0 audio_fds=0`。

見つかった問題・未解決事項:

- **不具合（#11）**: frame が届かなくなっても、切断が検出されるまで `online` を
  報告し続ける（frame-stall watchdog なし。手順 1 で約 5 秒、手順 3 で約 4 秒）。
  既知の loss を healthy と表示しない不変条件に反する。修正は PR #99 に積む
  stacked PR #111（stall を `degraded`（`video_frame_stalled`）として表示）。
  **#111 はまだ実機で検証していない**。#111 の実機確認で手順 1・3 を再実施する。
- **原因未特定の flapping**: 再起動後の実行で A を覆っている間に、約 1 分間
  `capture_failed` → reopen の反復と A の USB 切断 2 回が発生した。その後の
  3 回の実行では再現しなかった。原因は特定していない。
- **運用上の注意（既知制約）**: 同じ USB バス上で片方のカメラが列挙されるたびに、
  約 1 秒後にもう片方がリセットされる事象を 3 回以上観測した（いずれも
  software 側は取り違えなく自動復帰）。host 側の事象として #112 に記録したが、
  Owner 判断（2026-09-30）により、取り違えなく自動復帰する限り既知制約として
  許容し、#112 は not planned で close した。一時切断中の健全性表示が正しいことは
  #111 側で確認する。別 controller / 給電付き hub での再確認は任意
  （#101・#11 の close や merge を妨げない）。

Issue #101 の要再確認項目:

- [x] 手順 0: 識別・両 source `online`・`audio_fds=0`;
- [x] 手順 1: 抜いた A の `src1` が `offline`（`approved_device_absent`）、service 継続、
      同一バスの相互リセットで一時切断した B の `src2` は `identity_matched` で
      取り違えなく自動復帰（影響を受けたのは `src1` だけではない。B の一時切断中に
      `src2` が示した状態名は本記録に残しておらず、`src2` の isolation と切断中の
      表示は下の 2 項目で不合格として扱う。この項目で合格とするのは `src1` の
      `offline` 化・service 継続・取り違えのない復帰のみ）;
- [ ] 手順 1: 触れていない `src2` が影響を受けず frame を出し続けること
      （不合格: 同一バスの相互リセットで一時切断。相互リセット自体は既知制約として
      許容。その間の表示は次項）;
- [ ] 手順 1・3: 切断/入替中に 0 fps の source が `online` を表示しないこと
      （不合格。#111 で修正中、#111 の実機確認で再実施）;
- [x] 手順 2: 別 port・別 node で serial 照合により再承認なしで復帰;
- [x] 手順 3: port 入替で割当がカメラ個体に追従;
- [x] 手順 4: 再列挙・逆順 node でも再承認なしで正しい source に復帰;
- [x] 手順 5: レンズ遮蔽 30 秒の fps・状態を記録;
- [ ] 手順 5: 室内照明を落とした低照度での fps・状態（未実施）;
- [ ] 遮蔽中の `capture_failed` / reopen flapping と USB 切断（原因未特定、再現せず）;
- [ ] （任意）別 USB controller / 給電付き hub 構成での相互リセットの有無。

## B. Remote Linux capture node / `media-capture-agent`

Use the intended secondary Ubuntu machine and room-overview camera.

Installation/service:

- [ ] development checkout can run the agent during development;
- [ ] `media-capture-agent.service` installs/starts cleanly when installer exists;
- [ ] normal process runs as a dedicated non-root account;
- [ ] no GUI/tray is required;
- [ ] service name/process is `media-capture-agent` and does not impersonate unrelated software;
- [ ] microphone/audio device is not opened;
- [ ] media root is deployment-configured outside the checkout;
- [ ] ring-buffer and incident writes use the approved dedicated media filesystem when configured;
- [ ] installer/startup and runtime admission verify expected mount/filesystem/device, dedicated-account writability, free space, and safety reserve;
- [ ] using a disposable test volume, expected media-mount loss or substitution produces a visible degraded/failed state and refuses unsafe writes;
- [ ] that failure never creates or uses a fallback media directory on the root filesystem.

Use a disposable volume or controlled mount-identity mocks for failure checks; do not unmount or alter production storage for this test.

Pairing/security:

- [ ] owner creates a short-lived one-time pairing code;
- [ ] initial pairing is encrypted and authenticates the intended Main Server using Owner-approved bootstrap trust before sending the code;
- [ ] missing/mismatched Server trust and plaintext bootstrap attempts fail without exposing the code;
- [ ] expired code is rejected;
- [ ] reused code is rejected;
- [ ] agent identity is unique/revocable;
- [ ] post-pairing traffic is mutually authenticated/encrypted;
- [ ] revoked agent cannot reconnect;
- [ ] an unpaired LAN host cannot submit media;
- [ ] capture-node credential cannot access dashboard/admin APIs.

Connectivity:

- [ ] agent works over the same private LAN without joining Tailscale;
- [ ] agent initiates connection toward the main host;
- [ ] main host does not require SSH/admin access to the capture machine;
- [ ] ingest listener exposes no dashboard/settings/recording-browser routes;
- [ ] firewall/interface restrictions are documented and do not replace mTLS.

Health:

- [ ] agent-online / camera-online shown separately;
- [ ] camera USB unplug leaves agent online and camera offline;
- [ ] reconnect returns online only after safe identity match;
- [ ] agent stop/crash becomes node offline;
- [ ] main-host restart/reconnect is reported truthfully;
- [ ] heartbeat does not falsely imply that video frames are arriving.

Apply the exact-model, UVC-capability, stable-identity, and reconnect checks in section A to capture-node cameras as well as Main Server cameras.

### Record: Issue #12 sandboxed UVC capture re-run (2026-09-30, PR #88 head `4be6aa9`)

Environment: remote capture node, Landlock ABI 4, GStreamer 1.24, one
serial-bearing MJPEG UVC camera with a metadata node, non-root operator account
(development harness, not the generated service unit).

Checked (pass):

- [x] traced launch: the child opens only `/proc/self/fd/<N>` (approved node);
  `/dev`, `/sys/class`, `/sys/bus` enumeration fails with `EACCES`;
- [x] the non-approved metadata node, other device nodes, `/etc` and `/proc`
  outside the allowed paths, writes under `/tmp` and TCP connect fail with
  `EACCES` inside the sandbox;
- [x] only `coreelements` and `video4linux2` are loaded; no audio plugin or
  library, no `gst-plugin-scanner`, no registry file (`GST_REGISTRY_DISABLE`
  honoured);
- [x] `v4l2src` streams with `/sys` denied: 1080p30, 720p30 and 360p30 MJPEG at
  about 30 fps with no missing frames and no queue drops; Agent/GStreamer CPU
  about 1-2 %; child memory slightly lower than before the sandbox;
- [x] `close()` in about 0.02 s with no leftover process;
- [x] `SIGSTOP` of the child: `capture_failed` after about 6.5 s, then relaunch;
- [x] `SIGKILL` of the Agent: child exits in under 1 s; next start requires
  re-approval;
- [x] an unsupported 4K30 profile: `capture_failed` with backoff;
- [x] an injected Landlock ABI of 0: the launcher refuses to start;
- [x] lint, Agent unit tests and Agent ring/storage E2E pass on the node.

Pending: dedicated service account; generated systemd unit (`DevicePolicy`
allowlist, `ProtectHome`); USB unplug/replug; a second identical camera.

### Record: Issue #12 pre-launch MJPEG profile check (2026-09-30, Main host)

Environment: Main development host (not a deployed service), Landlock present,
distribution GStreamer, one of two serial-bearing MJPEG UVC cameras of the same
model, operator account in `video`, scratch harness with the production
`LinuxDiscovery`, `open_video_device`, `match_mjpeg_profile` and
`GStreamerLauncher` (only the sandbox helper file's root-ownership check was
bypassed because the development checkout is user-writable). Frames were counted
and discarded; no device values recorded.

- [x] 3840x2160@30, 1920x1080@60 and 1280x720@25: one mode check, then
  `offline`/`capture_unsupported` on every one of 24 polls over 12 s with zero
  GStreamer launches;
- [x] 1920x1080@30: mode check returns the requested profile, one launch,
  `degraded`/`capture_starting` then `online`/`video_ready` after about 1 s,
  about 30 fps with a draining consumer.

Pending: replug and Owner re-approval re-evaluation on hardware; a camera
advertising stepwise/continuous sizes or fractional (e.g. 30000/1001) intervals;
a serial-less camera staying `capture_unsupported` across polls (mock-only so far);
the remote capture node.

### Capture-node verification record (2026-09-30, Issue #12)

Environment (coarse by design; exact models, versions, serials, paths and host
identifiers stay in the private local test record): remote capture node
(x86_64 Linux), one serial-bearing UVC camera (MJPEG), non-root operator account.
Code: PR #88 HEAD `7840f4a`, driven by a local harness around `UvcCapture` and
`GStreamerLauncher`. Frames were counted and discarded in memory; nothing was
stored or viewed. No systemd unit or dedicated service account was used, so the
Installation/service checkboxes above remain open.

- [x] discovery binds only the video capture node; the UVC metadata node is
      excluded, audio is not enumerated, 0 probe failures;
- [x] real hardware: the single camera was discovered as a source keyed by its
      vendor/product/serial/interface identity (values in the private record),
      and that source was approved and brought online (see below);
- [x] synthetic (harness-injected enumeration, not physical): with a changed
      node path, port or device number injected, the identity still matches;
      an injected different serial is absent; an injected duplicate serial
      requires manual intervention. This checks the matching logic on the
      capture node only; the physical cases are the two pending items below;
- [x] a never-approved source reports `manual_intervention_required` /
      `owner_approval_required`, starts no process, and performs only read-only
      `QUERYCAP`/`ENUM_FMT` probes;
- [x] after approval the source is online in ~1.0 s; steady-state MJPEG
      1080p30/720p30/360p30 measured 30.02/30.01/29.90 fps with 0 missing
      frames and 0 queue drops, JPEG SOF dimensions matching the request;
      agent+GStreamer CPU ≤ 2.9 %, RSS ≤ 33 MiB (agent) + 10 MiB (child);
      camera warm-up is ~35 frames at ~13.5 fps followed by a pause of up to
      336 ms before steady 30 fps;
- [x] the child argv references video only through `/proc/self/fd/N`; its
      environment is limited to `GST_REGISTRY`, `LC_ALL`, `PATH`; it runs in
      its own process group;
- [x] unsupported profiles (4K30, 1080p60, 720p25) never become online and
      report `capture_failed` with 1/2/4/8 s backoff (not `capture_unsupported`);
- [x] `close()` completes in 0.02 s leaving no child, no process-group member
      and no video descriptor;
- [x] `SIGSTOP` of the child yields `capture_failed` after the stall timeout
      (~6.5 s); the child is reaped and relaunched to online;
- [x] `SIGKILL` of the agent (no systemd): the child exits in < 1 s and the next
      start requires re-approval;
- [x] `/dev/snd` is never opened (strace over the full lifecycle, cold and warm
      GStreamer registry);
- [ ] **FAIL:** during v4l2 plugin initialisation the `gst-launch` child opens
      every `/dev/video*` node `O_RDWR`, including non-approved and metadata
      nodes; with a cold registry it also loads ALSA/PulseAudio/PipeWire plugin
      libraries (no audio device or socket use observed). Observed at PR #88
      HEAD `7840f4a`; fix in progress on PR #88. This record must be re-traced
      and updated on the fixed HEAD after PR #88 merges (it stays FAIL until
      then);
- [ ] pending: dedicated service account and systemd unit with a
      `DevicePolicy`/`DeviceAllow` video-node allowlist (check whether the
      over-broad open above then fails with `EPERM` and whether capture still
      starts) — requires root;
- [ ] pending (real hardware): USB unplug and replug into another port (source
      offline while the agent stays up; the same identity matches on the new
      port/node; same source returns online only after a new frame);
- [ ] pending (real hardware): a camera with a different serial is not bound
      to the approved source, and a second identical camera
      (duplicate/no-serial ambiguity) requires manual intervention.

## C. Room-overview camera placement

For the intended wide room view:

- [ ] full room/important area is visible;
- [ ] entrance/zone is visible if entrance logic is desired;
- [ ] server area is visible if the overview source is expected to contribute evidence;
- [ ] normal people/movement do not permanently occlude important regions;
- [ ] mount is stable;
- [ ] lighting variation is measured;
- [ ] person-detection feasibility is measured at the actual room-wide placement and entrance;
- [ ] optional owner-verification feasibility is measured at that placement, with insufficient face size/quality reported as unavailable rather than assumed reliable;
- [ ] camera placement complies with institutional/local rules.

Do not upload room geometry or imagery to GitHub.

### Capture-profile benchmark

Compare at minimum where camera capabilities allow:

- [ ] 4K candidate and highest useful resolution at approximately 10–15 fps; record unsupported modes explicitly when the camera lacks them;
- [ ] 1080p/15 fps;
- [ ] actual resolution, FPS, codec, and bitrate are recorded for each candidate;
- [ ] camera-native compressed format vs re-encode path;
- [ ] hardware-accelerated encode path where available;
- [ ] LAN throughput;
- [ ] capture-node CPU/GPU/VRAM;
- [ ] main-host CPU/GPU/VRAM;
- [ ] dropped frames;
- [ ] recording quality;
- [ ] person/entrance detection quality.

Choose defaults from measurements, not assumptions.

#### 実機記録 2026-09-30: Main Server 上の local UVC capture resource（Issue #17）

環境は A 節の 2026-09-30 記録と同じ（serial 付き同型 UVC × 2、USB 2.0、非 root）。
実 `LocalUvcRuntime`（V4L2 MMAP、transcode なし、frame はメモリ上で件数のみ数えて
破棄）を各 profile で 20 秒計測（warm-up 3 秒）。CPU は process 全体の CPU 時間 /
経過時間（**1 core = 100%**）、RSS は FastAPI app 込みの process
全体。2 回目の計測（実配信 30 fps）を採用し、1 回目（露出で 16.65 fps に低下）は
括弧内に示す。録画・encoder・viewer・推論・GPU 経路はまだ接続されていないため、
これは **capture 取り込みだけ** の負荷であり、deployment default の根拠にはならない。

| profile | source 数 | 実配信 fps / source | 平均 frame | 帯域 / source | process CPU | RSS |
|---|---|---|---|---|---|---|
| MJPG 1920x1080@30 | 1 | 30.0 (16.65) | 166 KiB | 40.7 Mbps | 8.1% (4.9%) | 66 MiB |
| MJPG 1920x1080@30 | 2 | 30.0 / 30.0 | 150–166 KiB | 36.8–40.7 Mbps | 10.7% (5.6%) | 84 MiB |
| MJPG 1280x720@30 | 1 | 30.0 | 100 KiB | 24.5 Mbps | 7.3% | 59 MiB |
| MJPG 1280x720@30 | 2 | 30.0 / 30.0 | 102–103 KiB | 25.0–25.3 Mbps | 10.9% | 66 MiB |
| MJPG 640x480@30 | 1 | 30.0 | 53 KiB | 13.0 Mbps | 7.2% | 55 MiB |
| MJPG 640x480@30 | 2 | 30.0 / 30.0 | 50–53 KiB | 12.3–13.0 Mbps | 10.6% | 57 MiB |
| YUYV 640x480@30 | 1 | 30.0 | 600 KiB | 147.5 Mbps | 7.3% | 55 MiB |
| YUYV 640x480@30 | 2 | 30.0 / 30.0 | 600 KiB | 147.5 Mbps | 10.3% | 57 MiB |

- 全ケースで V4L2 sequence の欠落 0、MJPG frame の SOI/EOI marker 異常 0。
  1 source 時の数値には、無効化したもう 1 source の retry scan も含まれる。
- 未承認 idle は 0.25%。CPU の大部分は frame ごとの discovery rescan（A 節 提案-2）。
- 実機確認済み: 1080p/15 fps・4K は本カメラでは非対応（要求しても 1080p/30 に調整。
  A 節 重要-2）。camera-native MJPG の取り込みで transcode なし。
- 未確認: recording/viewer/inference 経路・codec・GPU/VRAM・LAN・capture node・
  3–4 source・録画品質・検知品質（該当経路が未接続、またはハードウェア不足）。

`python -m app.media.profiles.measure`（synthetic scheduler baseline、実カメラ・
codec・GPU は測らない）を同 host で実行した結果: 3000 packet × 4096 byte /
source、queue 64 packet、`prefer_hardware`（synthetic harness に hardware 候補がない
ため全経路 `software_fallback` と正しく表示）で、CPU 時間は viewer 0 / 1 の順に
1 source 18.8 / 24.1 ms、2 source 38.6 / 43.6 ms、3 source 62.4 / 68.3 ms、
4 source 75.1 / 85.2 ms。RSS peak 約 20 MiB、drop 0、全 source `healthy`。

The synthetic profile core tests do not satisfy the following integration checks:

- [ ] run the selected real decoder on all compressed reference packets; verify independent inference cadence and actual resized image dimensions, including B-frame reordering and stream restart;
- [ ] compare durable recording codec/profile/quality before, during, and after changing viewer quality; record any discontinuities explicitly;
- [ ] count viewer-only codec processes, handles and memory before the first subscriber, with subscribers, and after the last leaves; confirm cleanup and bounded failure recovery;
- [ ] apply recording and viewer queue pressure separately; verify bounded memory, visible loss, and keyframe recovery without claiming continuous evidence;
- [ ] verify copy eligibility against actual codec configuration, container, timestamps and color metadata; unsupported copy/transcode paths remain unavailable;
- [ ] record only sanitized aggregate resource measurements; no deployment identifiers, room imagery, media payloads, or exact private network values enter GitHub.
- [ ] on the Main Server and Capture Node, run `python -m app.media.profiles.measure` for 1, 2, 3 and 4 sources with and without viewers as a synthetic scheduler-overhead baseline; it does not measure codecs/cameras/GPU and its output is not a deployment default;
- [ ] with the real room-overview camera, list the room-overview profile set with measured `RoomOverviewCriteria`; confirm admission rejects it unless the room-overview option is requested and that inference/viewer stay downscaled;
- [ ] on a host without the accelerator (or with it disabled), confirm `prefer_hardware` selects software with visible `hardware_unavailable` / `software_fallback`, `require_hardware` reports the path unavailable, and recording never reports the accelerated path as active; re-enable the accelerator and confirm the next adapter start uses it.

## D. Source registry / mixed topology

Validate:

- [ ] 1 active source;
- [ ] 2 active sources;
- [ ] 3 active sources;
- [ ] 4 active sources;
- [ ] fifth activation rejected under default limit;
- [ ] mixed `local_uvc` + `remote_agent` works;
- [ ] source rename/role change works;
- [ ] detection profiles remain independent of source type;
- [ ] each local/remote source's admitted capture/recording/inference/viewer set
  comes from that source's inspected capabilities; a profile supported only by
  another camera/node is rejected without replacing the active configuration;
- [ ] removing one source does not corrupt recordings/events for others.

## E. Server ROI / movement

Per configured server source:

- [ ] ROI/polygon placement works;
- [ ] reference/calibration saves and can be replaced;
- [ ] small lighting changes do not trigger movement;
- [ ] person standing in front of server does not immediately become movement;
- [ ] partial occlusion clears without false critical event;
- [ ] controlled displacement/rotation triggers event;
- [ ] camera movement is distinguished from server-only movement where practical;
- [ ] one event can link evidence from other active sources.

## F. Camera tamper and source health

- [ ] move/rotate camera mount;
- [ ] cover/obstruct lens;
- [ ] disconnect USB;
- [ ] reconnect USB;
- [ ] interrupt agent process/network for remote source;
- [ ] meaningful health/tamper changes are visible/audited;
- [ ] trivial vibration does not flood critical alerts;
- [ ] known loss is never shown as healthy.

## G. Network interruption / backpressure and agent evidence protection

Remote-agent scenarios:

- [ ] LAN off ~10 seconds;
- [ ] LAN off ~2 minutes;
- [ ] switch/AP/network restart if safe;
- [ ] main ServerSentinel service restart;
- [ ] capture-node restart;
- [ ] bandwidth throttling/backpressure test in a controlled environment.

Agent ring core on a real disk (capture host, 2026-09-30). The capture-host
session ran the Issue #16 ring core with a disposable loop-mounted ext4 media
filesystem, generated (synthetic) segment bytes, an injected clock and the real
`MediaStore` mount/free-space/reserve checks. No camera, real segmenter,
authenticated transport or UI was involved, so the product checklist items
below stay unchecked. Private host details are kept out of the repository.

- [x] duration-mode FIFO kept exactly the selected duration;
- [x] a Main-loss incident covered T-600 s..T+600 s complete and was retained across further FIFO;
- [x] 60-day expiry ran only under a trusted clock;
- [x] lazy unmount, a substituted directory and another filesystem each became `STORAGE_HARD_STOP` (`storage_path_unavailable` / `mount_replaced`) with no fallback write; remounting the same device recovered the ledger;
Before any re-verification that switches to a new ledger on the same media
root, expire or delete the previous run's incidents and ordinary media through
the previous ledger. Its segments are otherwise unknown orphans to the new
ledger: they are never deleted automatically and block configuration.

- [x] **capacity mode** — re-verified 2026-09-30 on the sizing-fix head (see section Q record). Originally: the run found every realistic capacity refused as `insufficient_ledger_capacity` (the former 512-byte row model needed a ledger ~48x the capacity and ~33x that again as journal headroom). Repeat with the same profile shape (two sources, 4 Mbit/s, 10 s segments, 700 MiB, 32 MiB ledger cap): configuration must be admitted, `ledger_required_bytes` must stay within the cap, and T-10/T+10 must complete;
- [ ] **hard stop while writes are refused** — refusal side re-verified 2026-09-30 (see section Q record); steady-FIFO false hard stop fixed afterwards, pending re-verification. Originally: the run found 83 `segment_storage_refused` appends near exhaustion while status stayed `STORAGE_PRESSURE / post_loss_headroom_reduced`. Repeat the near-reserve fill: every refused interval must read `STORAGE_HARD_STOP / segment_write_refused_at_reserve`, free space must stay at or above the reserve, and status must leave hard stop once space is released.

Ring-buffer configuration:

- [ ] owner can select **duration mode** and UI shows projected/actual disk usage;
- [ ] owner can select **capacity mode** and UI shows estimated effective duration;
- [ ] non-owner cannot change buffer mode/value;
- [ ] current bytes, protected-incident bytes, filesystem free space, and safety reserve are visible;
- [ ] unsafe values produce warning and are rejected before violating safety reserve;
- [ ] duration/capacity/profile admission verifies space for pinned T-10 plus T+10 capture simultaneously, estimated from bounded/negotiated bitrate and segment/container overhead with existing protected incidents, other filesystem use, and hard reserve; shared segments count once and only eligible ordinary data outside required pre-loss is reclaimable;
- [ ] a disposable filesystem/quota that fits only 10 minutes plus reserve causes configuration rejection; repeat with existing protected incidents and unrelated filesystem consumption removing post-loss headroom, without deleting unexpired evidence;
- [ ] a sufficient bounded-profile budget admits the setting and supports the complete window without crossing reserve; no new numeric reserve threshold is inferred from the test;
- [ ] runtime uncertainty or later loss of effective pre-loss coverage/post-loss headroom becomes degraded/warning with actual coverage/gaps rather than silently healthy.

Unexpected Main Server communication loss:

- [ ] agent pins the 10 minutes immediately before loss when available;
- [ ] agent continues local recording for 10 minutes after loss;
- [ ] resulting protected incident targets 20 minutes total;
- [ ] reconnect does not erase the protected incident;
- [ ] segment gaps/shortened protection are reported truthfully;
- [ ] protected incident has a 60-day agent-side expiry;
- [ ] expiry cleanup removes it automatically after 60 days (use test clock/accelerated retention harness rather than waiting 60 real days where available);
- [ ] restart or trusted-clock recovery after that deadline expires the incident immediately; delayed finalization/late media never extends `ended_at + 60 days`;
- [ ] ordinary ring-buffer pressure does not delete an unexpired protected incident;
- [ ] disk pressure produces explicit warning/hard-stop behavior before unsafe writes.

Critical preservation and lifecycle:

- [ ] an authenticated Main Server critical preserve request pins the requested available interval and reports partial coverage/gaps accurately;
- [ ] the Owner can inspect protected-incident bytes, coverage, and expiry timestamps;
- [ ] an explicit Owner manual delete can remove a protected incident before expiry and an unauthorized identity cannot delete it;
- [ ] eligible ordinary ring-buffer data is reclaimed before unexpired protected evidence, and safety reserve still blocks unsafe writes;
- [ ] configured dedicated-media mount loss/substitution refuses ring-buffer/incident writes with no root-filesystem fallback, including during post-loss capture.

Record:

- state transition;
- reconnect time;
- recording gaps;
- duplicate/missing media;
- queue/memory growth;
- agent buffer bytes;
- protected incident bytes/expiry;
- audit event;
- manual-intervention requirement if automatic recovery is unsafe.

### LAN baseline measurement (2026-09-30, Issue #15; no transport candidate yet)

This is a baseline of the private LAN path from the remote capture node to the
Main Server, not a transport evaluation. It was a short measurement on an idle
LAN; the transport comparison and the impairment matrix above remain pending.
No checkbox above is completed by it.

- RTT (200 ICMP echoes): p50/p95/p99/max 2.61/3.17/3.50/5.63 ms, 0 % loss;
- TCP one-way throughput (10 s, two runs): 940.7 / 939.4 Mbps;
- UDP constant rate, 1200-byte payload, 20 s each: 30/40/60/100 Mbps all 0 %
  loss; reordered datagrams 0/0/19/1; RFC 3550 interarrival jitter
  0.370/0.350/0.297/0.125 ms;
- observed camera MJPEG bitrate: ≈ 60 Mbps (1080p30), ≈ 30 Mbps (720p30),
  ≈ 26 Mbps (360p30).

Pending once a transport exists (human/root steps; prefer a dedicated NIC or
VLAN for `netem` so unrelated traffic is not impaired):

- [ ] LAN cable pull for ~1 s, ~5 s and ~2 min;
- [ ] switch/AP restart;
- [ ] `netem` loss, delay and rate limits (including rates below the observed
      MJPEG bitrate) to exercise backpressure;
- [ ] Main ServerSentinel service restart;
- [ ] capture-node reboot.

## H. Clock synchronization

- [ ] main/capture node normally synchronize through NTP/chrony or equivalent;
- [ ] measured offset is visible/diagnosable;
- [ ] controlled excessive skew causes degraded state/warning;
- [ ] timeline does not silently present unreliable remote timestamps as exact;
- [ ] recovery clears degraded state appropriately.

Pending (2026-09-30): controlled clock skew on the capture node via
`timedatectl` requires root and was not performed in the capture-host session.

## I. Live view from phone, Mac, and desktop

Local/private path:

- [ ] phone browser can open live dashboard when authorized;
- [ ] Mac browser can open live dashboard when authorized;
- [ ] desktop browser can open live dashboard when authorized;
- [ ] browser viewers obtain media only from the Main Server and never connect directly to `media-capture-agent`;
- [ ] a live URL copied to an unauthorized identity cannot retrieve or play media;
- [ ] 1-source layout usable;
- [ ] 2-source layout usable;
- [ ] 3–4 source grid usable where applicable;
- [ ] source/node health visible;
- [ ] selected camera expands cleanly;
- [ ] live start time measured;
- [ ] latency measured;
- [ ] near-real-time quality is evaluated with stability/reconnect prioritized over absolute minimum latency;
- [ ] reconnect works;
- [ ] adaptive quality works;
- [ ] one bad source does not hide health of others.

Demand-driven processing:

- [ ] no-viewer state does not perform unnecessary viewer-only transcoding;
- [ ] first viewer starts needed packaging/transcoding;
- [ ] multiple viewers remain bounded;
- [ ] viewer disconnect returns resources toward idle state.

## J. Tailscale / invitation visibility and authorization

Use test identities/accounts appropriate for the deployment. ServerSentinel does **not** modify Tailscale ACLs/Grants or store Tailscale administrative credentials; any policy administration remains outside the application and existing policy may remain unchanged.

### Shared Tailscale account

The research-room Tailnet is shared, so run these with two people (or two browser profiles) using the **same** Tailscale login.

- [ ] an invited person with a registered ServerSentinel credential passes authentication, and the authenticator asks for user verification each time;
- [ ] invite two people, have both register and sign in with their own passkeys under the **same** Tailscale login, and confirm each lands in their own principal with their own permissions (for example one `live:view`-only, one `recordings:view`-only); then revoke one of them and confirm the other keeps working;
- [ ] each credential is registered on an authenticator the invited person controls; confirm no credential is left in a shared OS profile or behind a shared device unlock;
- [ ] with the invited person signed out, an uninvited person on the same Tailscale login and the same device is refused;
- [ ] a session ends after its idle/absolute lifetime, and the explicit sign-out control works on a shared machine;
- [ ] the refusal is the generic response: no product/version string, camera names/counts, recording or timeline data, or deployment metadata, and the credential prompt itself carries none of them;
- [ ] a revoked person receives the same response as an uninvited person;
- [ ] revoking one credential leaves the principal's other credentials working, and revoking the principal blocks all of them promptly;
- [ ] if a synced passkey is in use, confirm that revoking it takes effect on every device it synced to, and record that revocation is credential-scoped rather than per-device;
- [ ] the owner screen shows each credential's backup-eligibility as read at registration; if the deployment requires device-bound credentials, registering a backup-eligible authenticator is refused with a message the person can act on;
- [ ] register a backup-eligible passkey before it has synced, then sign in again after it syncs: the owner screen stops showing it as not backed up, because backup state follows the latest verified sign-in;
- [ ] present an otherwise valid assertion whose backup-eligibility flag differs
  from registration: it is refused, the credential is shown as inconsistent
  with the reason, all sessions using it stop, and it cannot authenticate or
  satisfy step-up again;
- [ ] when that was a non-owner's last usable credential, re-invite the person
  and register a replacement; separately confirm an Owner with no other usable
  credential recovers only through the privileged local bootstrap path;
- [ ] no human route grants access on the proxy identity header alone;
- [ ] a passkey that reports `none` attestation registers successfully, and a registration whose attestation statement is present but invalid is refused;
- [ ] where the owner screen shows a last-observed Tailscale login/device, confirm it is owner-visible only, that it is cleared when the principal is revoked or deleted, and that a diagnostic export does not contain it;
- [ ] with trusted proxy identity enabled, inspect persisted sessions and confirm
  they contain only a keyed binding, never the raw login/device; a mismatched
  identity is refused, diagnostics/exports omit the binding, and sign-out,
  expiry and revocation clear it;
- [ ] present a signed-in session's cookie with a different trusted-proxy
  identity (for example through a second Tailscale login or a shared-in
  device): the request gets the generic response, the original holder keeps
  working, the audit log shows one `detect_session_proxy_identity_mismatch`
  entry with no login/device value, and repeating the replay within ten
  minutes adds no further entry;
- [ ] on the Main Server, confirm the session-binding key file in the data
  directory is a regular file of the service account with mode `0600`, that the
  data directory is not group/other writable, that a changed mode, extra hard
  link, symlink or wrong size makes startup refuse the key instead of replacing
  it, and that the key does not appear in logs, the database or a diagnostic
  export;
- [ ] record that reachability is expected for every holder of the shared account and is not treated as a finding;
- [ ] the dashboard origin is reserved for ServerSentinel and is a secure context (HTTPS, or `http://localhost` for a strictly local browser); confirm WebAuthn registration and sign-in actually work there, and record that an ordinary-HTTP non-loopback origin makes them impossible;
- [ ] the startup and daily reservation check enumerates the real listeners and every proxy route for the whole name across all schemes and ports, and closes human access and notifies the Owner on any other answer; record that this bounds rather than prevents, so a process binding between checks can collect credentials until the next check;
- [ ] the first owner redeems a console-displayed single-use authorization once from a browser at the reserved origin, and it cannot be redeemed again;
- [ ] record the configured entropy of enrollment codes and bootstrap authorizations and confirm it meets the stated minimum; guessing attempts against a wrong code are rate-limited and give the same generic response;
- [ ] a first-time invitee redeems an enrollment code and registers a credential without already holding one, and the same code cannot be redeemed twice;
- [ ] two browsers submitting the same code at once end with exactly one credential registered; the other attempt gets the generic response and nothing is left half-applied;
- [ ] an absent, unknown, expired or already-redeemed code returns the same generic response as an uninvited person, and the enrollment step returns no camera, recording or timeline data;
- [ ] an owner operation (revoke a user, change a retention/security setting, delete a recording) asks for a fresh user verification even inside an existing owner session, and cancelling it leaves everything unchanged;
- [ ] with a stale owner session open on a shared machine, a second invited person's own passkey cannot satisfy the step-up: the assertion is refused, the operation does not run, and the owner session's freshness is unchanged.

Record the residual limits instead of testing them away: a credential its holder deliberately lends, and a session left unlocked on an unattended machine, are outside what the application can detect.

### Issue #10 WebAuthn ceremony core with real browsers and authenticators (pending)

`server/app/auth/passkeys.py` and `webauthn.py` are verified only against
synthetic software authenticators in `server/tests/test_webauthn_ceremonies.py`.
No real browser, passkey provider, security key or device has exercised them.
Once the Issue #10 routes are mounted, run these checks at the reserved
secure-context origin, using synthetic test identities (`*.invalid`):

- [ ] register and sign in with at least one of each of the following, and
  record the COSE algorithm each one actually used:
  - a synced platform passkey (for example iCloud Keychain or Google Password
    Manager);
  - a device-bound platform authenticator;
  - a roaming security key.
- [ ] confirm each browser honours `attestation: "none"`: registration succeeds,
  and record any authenticator whose statement is refused because it is not
  `none` or `packed` self attestation;
- [ ] confirm `userVerification: "required"` makes every registration, sign-in
  and step-up prompt for a PIN, device unlock or on-device biometric, and that
  a flow with UV declined or unavailable is refused with the generic response;
- [ ] record the BE/BS flags each real authenticator reports at registration
  and after it syncs, and confirm the owner view matches;
- [ ] record the signature-counter behaviour of each authenticator (always 0,
  or increasing). For a counting security key, confirm that replaying an older
  captured assertion is refused (the challenge is single use). Do not claim
  that a real clone was detected unless one was actually produced;
- [ ] let a registration or sign-in prompt sit past the five-minute challenge
  lifetime, then complete it and confirm it is refused. Cancel a prompt and
  confirm nothing changes;
- [ ] open the dashboard at `https://<reserved-host>:<other-port>`, and at an
  origin that is not the reserved one, and confirm that neither a ceremony
  started there nor its response completes;
- [ ] with `http://localhost` on the Main Server's own browser, confirm the
  local owner ceremony works, and confirm a plain-HTTP non-loopback origin
  cannot use WebAuthn at all;
- [ ] inspect the database after these runs. It holds only credential ids,
  COSE public keys, counters, BE/BS flags, labels and timestamps, plus the
  SHA-256 digests of challenges still pending. It holds no raw challenge,
  client data, signature or biometric data. Logs contain none of these either.

### Uninvited ordinary Tailnet member

- [ ] if existing Tailnet policy makes the Main Server node visible/reachable, document that fact rather than claiming node invisibility;
- [ ] ServerSentinel invitation is still required before application data is served;
- [ ] unauthorized response is generic/non-branding where practical;
- [ ] no ServerSentinel product/version, API schema, health detail, camera names/counts, thumbnails, recording data, timeline data, or deployment metadata leaks through errors/alternate endpoints;
- [ ] LAN path cannot spoof trusted Tailscale identity headers.

### Invited user with `live:view` only

- [ ] can view current live streams;
- [ ] can view only current source health needed for live viewing;
- [ ] cannot list/play recordings;
- [ ] cannot access historical timeline/events;
- [ ] cannot access privileged settings.

### Invited user with `recordings:view` only

- [ ] can list/play recordings in browser when application authorization passes;
- [ ] can access historical timeline/events;
- [ ] does not gain live view unless separately granted;
- [ ] no official recording download/export control is present;
- [ ] playback URL copied to an unauthorized identity does not work.

### User with both

- [ ] live, browser playback, and historical timeline all work;
- [ ] cannot manage cameras/users/settings unless owner.

### Revocation

- [ ] app permission revoke blocks subsequent requests promptly;
- [ ] Tailnet membership alone remains insufficient for ServerSentinel application data;
- [ ] no Tailscale policy mutation is performed by ServerSentinel.

Do **not** claim invisibility from Tailnet Owners/Admins or infrastructure administrators, or node invisibility when existing Tailnet policy exposes the node.

## K. Manual/event recording

- [ ] manual recording start/stop;
- [ ] 20-minute maximum enforced;
- [ ] event recording includes configured 30 s pre / 120 s post when resource conditions permit;
- [ ] one event can contain multiple source recordings;
- [ ] manifests use source IDs, not fixed role filenames;
- [ ] playback source labels are correct;
- [ ] compressed pre-roll strategy remains bounded;
- [ ] no unnecessary long decoded-frame RAM history.

## L. Low light / detector-specific quality gating

Progressively degrade lighting/blur/visibility.

- [ ] quality transitions `sufficient -> degraded -> insufficient` appropriately;
- [ ] live/recording may continue when frames still exist;
- [ ] owner verification becomes `unknown/unavailable` before unreliable identity result;
- [ ] **person detection also becomes unknown/unavailable when its own quality prerequisites fail**;
- [ ] insufficient person quality is never displayed/stored as trustworthy `no person`;
- [ ] entrance/presence logic does not infer absence from skipped person inference;
- [ ] recovery uses suitable hysteresis;
- [ ] no automatic torch/light behavior exists.

## M. Video-only behavior

- [ ] the local capture path does not open microphone/audio devices or capture monitoring audio; MVP has no audio-enabling option;
- [ ] `media-capture-agent` does not request/open microphone devices;
- [ ] browser live playback contains no audio track in MVP;
- [ ] recordings contain no monitoring audio in MVP.

## N. Owner-only face verification

Use only the deployment owner's own enrollment during manual testing. Never upload enrollment/reference images or real-person result clips to GitHub.

Issue #25 currently validates private local persistence, authorization/generation/quality boundaries and no-egress normal/error smoke with generated shapes and a synthetic verifier only. No production face model/weights/threshold is selected. Keep all real-model/Owner/room checks below open; record the Owner-approved code/weights/license/artifact/threshold decision locally before enabling the adapter.

- [ ] explicit biometric explanation;
- [ ] owner enroll/delete/re-enroll;
- [ ] re-enrollment/deletion invalidates old and in-flight match receipts; shared/general diagnostics and explicit Owner exports never include the private template DB/journals/backups;
- [ ] separate face crops in one frame each need their own sufficient quality assessment; one clear face cannot lend its quality to another blurred/dark face;
- [ ] poor enrollment image rejected/retried;
- [ ] template remains local and absent from logs/normal diagnostics;
- [ ] normal frontal/angle/distance variations tested;
- [ ] low-light/blur/partial occlusion tested;
- [ ] result includes quality/confidence;
- [ ] ambiguous input becomes `unknown`;
- [ ] no non-owner enrollment feature exists;
- [ ] verification and anonymous tracking do not create or retain persistent non-owner face-crop/template/embedding/profile libraries, whether named or anonymous; ordinary authorized recordings remain subject to recording retention and must not be used to build such libraries.

## O. Entrance / anonymous tracking / presence

Where room geometry supports entrance logic:

- [ ] owner entry/exit;
- [ ] anonymous person entry/exit;
- [ ] multiple people close together;
- [ ] partial occlusion;
- [ ] reversal/loiter near line does not spam events;
- [ ] crossing back within hysteresis and then walking around the finite line endpoint does not create a false entry; frame gaps/occlusion/session reset do not infer unseen crossings;
- [ ] unknown people receive no real names;
- [ ] no cross-camera biometric re-identification claim;

Presence safety applies even when entrance inference is unavailable:

- [ ] manual presence override wins;
- [ ] ambiguous/low-quality owner observation does not force presence;
- [ ] only `PRESENT` suppresses ordinary occupancy automation by default;
- [ ] repeat controlled server-movement and camera-tamper scenarios in each of `PRESENT`, `PROBABLY_PRESENT`, `ABSENT`, and `UNKNOWN`, including Owner manual overrides;
- [ ] in every case, verify the actual critical detection event, preserved recording/Agent incident evidence where configured, and configured immediate critical notifications; an armed indicator alone does not satisfy acceptance;
- [ ] `PRESENT` and manual overrides do not suppress any of those three outcomes; configured Slack receives the immediate notification, and dashboard/audit faults remain when Slack is disabled or delivery fails.

## P. Unified security timeline

Create a controlled scenario such as:

```text
Owner exits
Anonymous person enters
Server movement occurs
Camera disconnects
Anonymous person exits
```

- [ ] timestamps ordered correctly across local/remote sources;
- [ ] source attribution correct;
- [ ] linked recordings correct;
- [ ] confidence/quality shown where applicable;
- [ ] offline/gap states visible;
- [ ] system never labels the person culprit/thief/attacker.

## Q. Storage pressure / hard stop

Use a disposable/test volume.

Issue #21 unit/container scenarios cover temporary synthetic files, reserved
constructor recovery, starvation/cleanup/star races, audit failure, retention,
mock Slack and DST/rollback scheduling. They do not establish deployed volume,
real codec, configured Slack, browser playback or human authorization acceptance.
Keep the following deployment checks open; do not use production data for fills.

The lifespan runtime wiring (`server/app/monitoring/`) is exercised only with
disposable directories, a test clock, a synthetic inventory probe and an
intercepted Slack transport. On the deployment, additionally check:

- [ ] without `monitoring.storage_limits` (or the whole `monitoring` object)
      `--check` fails and the unit does not start, so it never runs without the
      startup/daily hardware integrity check and recording self-test;
- [ ] with configured thresholds and `recording_filesystem`, `--check` passes and
      the service reports `monitoring_started`; a wrong UUID/device/mount point is
      refused by `--check`;
- [ ] storage state transitions appear in `storage_state_audit`, and expired
      unstarred recordings/state-audit rows are removed by the running service;
- [ ] detaching or substituting the recording mount while running yields one
      immediate `recording_health_failure`, `STORAGE_HARD_STOP`, and no new file
      in the substituted directory or on the root filesystem;
- [ ] a startup-time failure (for example free space below the hard reserve,
      or a transiently unresolvable filesystem UUID) yields one immediate
      `recording_health_failure` and refused writes; once the condition clears,
      the runtime recovers within 15 minutes without a restart and without a
      second alert.

- [ ] metadata database and media use the expected filesystem, and configured
      journal/temp overhead safely covers recovery, cleanup and migrations;
- [ ] configured Slack receives one safe immediate critical alert and one daily
      aggregate; a failed/unconfigured channel leaves local/UI faults visible;
- [ ] slow/unavailable Slack does not block recording; full queues, pending
      shutdown/crash delivery and failed completion persistence remain visible;
- [ ] after deployment restart/DST change, summary sends at the configured local
      time without duplicate dispatch, and uncertain `pending` delivery is visible.

- [ ] retention deletes expired unstarred data;
- [ ] allocation/free-space pressure reclaims oldest eligible unstarred data;
- [ ] unrelated filesystem consumption affects admission;
- [ ] starred data not auto-deleted;
- [ ] `STORAGE_PRESSURE` suppresses specified ordinary/manual admission;
- [ ] bounded critical allowance never crosses hard reserve;
- [ ] `STORAGE_HARD_STOP` occurs before unsafe write;
- [ ] warnings/audit visible;
- [ ] recovery uses hysteresis.

Never intentionally fill a production filesystem to zero free bytes.

### Agent storage/ring verification record (2026-09-30, Issue #16)

Environment: remote capture node (x86_64 Linux), non-root operator account,
disposable loop-mounted ext4 volume. Synthetic segments and a synthetic trusted
clock drove the real `MediaStore`; no camera media was written. Profile: 2
sources, 10 s segments, 4 Mbps, safety reserve 256 MiB. Mount identity values
stay in the private local record. Code: `main` at `83d387f` (the pre-fix base
of PR #104; `agent/` unchanged on `main` since `bec201b`).

- [x] `--check` passes on the approved mount and refuses a wrong filesystem
      UUID, device minor or mount source, a reserve larger than free space, a
      media root on the root filesystem and mount point `/` (no files created);
- [x] duration mode 900 s keeps exactly 900 s per source (FIFO) after 30 min
      written;
- [x] unexpected loss produces a complete incident covering T−600..T+600 s per
      source with no gaps, retained through a further 30 min of FIFO writes;
      `STORAGE_PRESSURE` / `post_loss_headroom_reduced` is reported when the
      next incident cannot fit; expiry is set to end + 60 days and is not
      applied under an untrusted clock;
- [x] oversized configurations (capacity 4 GiB, duration 3600 s) are refused
      with `insufficient_simultaneous_pre_post_budget`;
- [x] lazy unmount while running, an empty same-name directory on the root
      filesystem, and a different filesystem at the mount path each refuse
      writes with `STORAGE_HARD_STOP` (`storage_path_unavailable` /
      `mount_replaced`) and create no fallback file; remounting the approved
      volume recovers the ledger;
- [ ] **FAIL:** capacity mode is not configurable at realistic sizes (the
      ledger requirement is ≈ 48 × capacity). Fix in PR #104 (Refs #16);
      re-verify on a real disk after it merges;
- [ ] **FAIL:** a write refused because of the safety reserve is reported as
      `STORAGE_PRESSURE` / `post_loss_headroom_reduced`, never
      `STORAGE_HARD_STOP`. Fix in PR #104 (Refs #16); re-verify on a real disk
      after it merges.

The real segmenter/profile, authenticated transport, Owner UI and systemd
deployment checks in section G and the Issue #16 note in *Test metadata* remain
open.

### Agent ring real-disk re-run (Issue #16, 2026-09-30)

Environment: the capture host, a disposable loop-mounted ext4 media
filesystem, generated (synthetic) segment bytes, an injected trusted clock and
the real `MediaStore` mount/free-space/reserve checks. No camera, segmenter,
transport or UI. Run on the PR #104 sizing/hard-stop fix head (`4fce0df`).

- [x] capacity mode, two sources at 4 Mbit/s with 10 s segments, 700 MiB under a 32 MiB ledger cap: admitted, `ledger_required_bytes` 13,901,824, capacity horizon 710 s;
- [x] capacity FIFO stayed within 700 MiB and the 710 s horizon;
- [x] a capacity-mode Main-loss incident covered T-600 s..T+600 s complete and was retained (ledger file about 23.7 MB);
- [x] near-reserve fill (duration 900 s, two sources): from minute 9 the refused appends (83 in total) read `STORAGE_HARD_STOP / segment_write_refused_at_reserve`;
- [x] an external fill produced hard stop; deleting it cleared status to `degraded / pre_loss_coverage_gap` and appends resumed;
- [x] regressions: 900 s duration FIFO, loss incident and 60-day expiry unchanged;
- [ ] **FAIL, fixed — pending re-verification**: in the same near-reserve run, minutes 16–20 accepted every append (FIFO reclaimed segments older than 900 s at each append) while status still read `STORAGE_HARD_STOP / segment_write_refused_at_reserve`. Status credited reclaim only as of `now`, when the segment the next append reclaims was not yet eligible. Status now evaluates each source's next append at its own capture phase (`max(now, last trusted segment end + cadence)`); re-run and confirm that accepted steady-state appends read `STORAGE_PRESSURE` (short pre-loss headroom), not hard stop, while real refusals still read hard stop;
- [x] regression on the fix head: lazy unmount / an empty same-name directory on the root filesystem / another filesystem each refused writes with `STORAGE_HARD_STOP` (`storage_path_unavailable` / `mount_replaced`), no fallback write; remounting the approved volume passed `--check` and resumed appends on the recovered ledger.

## R. Long-duration / performance

Run at least:

- [ ] 1 hour;
- [ ] 8 hours;
- [ ] 24 hours.

Record:

- source types/count;
- capture/record/view resolution/FPS/bitrate;
- detector inference cadence;
- main CPU/GPU/VRAM/memory;
- capture-node CPU/GPU/VRAM/memory;
- disk write rate;
- USB topology/bandwidth;
- LAN throughput;
- live-view latency;
- disconnect/reconnect count;
- dropped frames;
- service crashes;
- false health states.

Record separate performance results for 1, 2, 3, and 4 active sources, including a long-duration mixed-source run. If required hardware is unavailable, mark the affected acceptance cases unperformed rather than PASS. Final defaults come from these measurements.


## S. Main-host hardware integrity / recording-health self-test

Current Issue #23 automation uses generated inventory and synthetic compressed
bytes only. The lifespan runtime now runs startup/daily integrity comparison and
recording-health checks and bridges faults to durable local notification rows
and optional Slack (mock-verified only). Before physical acceptance, wire the
approved Owner authorizer and the actual source/encoder/codec callbacks; until
then the self-test reports `UNAVAILABLE` and no baseline can be approved. Verify optional read-only tools under the
dedicated non-root account; unavailable fields must stay unknown. Do not publish
collected identifiers or self-test bytes.

### Hardware baseline and startup/daily comparison

Establish an Owner-approved baseline, then validate both startup and scheduled daily checks.

- [ ] CPU model/topology/signature data is captured where available;
- [ ] RAM slot/capacity/part/serial data is captured where available;
- [ ] NVMe/M.2 device model/serial/WWN-style identity/capacity is captured where available;
- [ ] HDD/recording-drive model/serial/WWN-style identity/capacity is captured where available;
- [ ] GPU model/GPU UUID/serial/PCI identity is captured where available;
- [ ] ServerSentinel startup triggers an integrity comparison;
- [ ] a running service performs the comparison at least once every 24 hours;
- [ ] results distinguish `OK`, `CHANGED`, `MISSING`, `NEW_DEVICE`, and `UNVERIFIABLE`;
- [ ] a missing/changed approved component does not silently update the baseline;
- [ ] only the Owner can approve a replacement/new baseline;
- [ ] Owner approval is audited;
- [ ] same-model replacement with no exposed stable unique identifier is reported as an identification limitation rather than falsely guaranteed;
- [ ] serials/UUIDs are redacted or hashed in normal operational logs and general diagnostics; raw identifiers remain absent from telemetry/public diagnostics/GitHub artifacts.

Use controlled inventory mocks for destructive/expensive substitution cases where physical replacement is impractical. Real hardware swaps are optional and must not damage production equipment.

#### 実機記録 2026-09-30: storage identity の SATA 修正（Issue #23）

Main Server 実機で、非 root の通常ユーザー（sudo なし）のまま `LinuxProbe` の
storage probe と `compare()` を直接実行した（read-only）。識別子の値は記録していない。

| 対象 | 使われた identity 源 | 再取得との比較 | 区分 |
|---|---|---|---|
| NVMe（1 台） | `serial` + `wwid`（修正前と同一の値・key） | `OK` | 実機確認済み |
| SATA HDD（1 台、libata） | `scsi_wwid`（NAA）+ `vpd_pg80_serial`。修正前は identity なし（`UNIQUE_ID_UNAVAILABLE`） | `OK` | 実機確認済み |

- 同 SATA disk の VPD page 0x83 parser の結果（NAA designator）は kernel の
  `device/wwid` と一致し、VPD page 0x80 から空でない unit serial を得た。
- 修正前の probe で作った baseline と修正後の probe を比較すると、NVMe は `OK`、
  SATA は `UNVERIFIABLE` / `IDENTIFIERS_OR_PROPERTIES_INCOMPLETE`（即時扱い）
  となり、新しい identity が黙って受け入れられないことを確認した。解消には
  Owner による新 baseline の承認が必要。
- 未確認: USB bridge 接続 disk・SAS/SCSI disk の実機、専用 service account での
  実行、Owner baseline 承認・監査、startup/daily 実行と通知。上の checklist は
  それらの確認まで未チェックのままとする。

### Recording-health daily self-test

- [ ] enabled sources have fresh frames or an explicit truthful offline/degraded state;
- [ ] recorder/encoder state is checked;
- [ ] configured recording root resolves to the expected filesystem/device;
- [ ] on a disposable test volume, missing/unmounted or substituted recording filesystems refuse recording and self-test media writes; no fallback directory is created or used on the root filesystem or another unintended filesystem, even while reporting degradation;
- [ ] writability, current free space, and safety reserve are checked;
- [ ] a bounded temporary media segment is written through the recording path;
- [ ] the segment is flushed/fsynced;
- [ ] the segment is reopened and container/duration/size/decode readability is validated as appropriate;
- [ ] self-test-owned temporary/partial media is deleted locally after success, write/read/decode failure, and cancellation;
- [ ] process interruption and reboot leave only bounded self-test artifacts, which are reconciled/cleaned at next startup before new self-test media is written;
- [ ] cleanup verifies the expected filesystem and self-test ownership and never deletes ordinary recordings or protected incidents;
- [ ] simulated missing/read-only storage or cleanup failure reports failure and blocks further self-test media writes until safe cleanup succeeds;
- [ ] leftover bytes count against storage admission/safety reserve, with no root-filesystem fallback or retained/uploaded diagnostic media;
- [ ] available SMART/NVMe health data is read and surfaced without unsupported lifetime prediction;
- [ ] a failed write/reopen/decode test creates a recording-health failure state;
- [ ] the self-test runs at least once every 24 hours.

### Immediate owner alerting

For each condition below, verify the system does not wait only for the 23:00 daily summary:

- [ ] approved CPU/RAM/NVMe/HDD/GPU becomes `CHANGED` or `MISSING`;
- [ ] expected recording device/mount is substituted or missing;
- [ ] recording-health write/reopen/decode fails;
- [ ] available SMART/NVMe health reports a material critical warning;
- [ ] `NEW_DEVICE`/`UNVERIFIABLE` creates at least a visible warning and escalates when recording integrity cannot be assured;
- [ ] Slack receives the immediate alert when Slack is configured;
- [ ] when Slack is disabled, dashboard/audit fault state remains visible.

Do not upload hardware serials, local mount identifiers, real temporary test media, or private infrastructure details to GitHub.

#### 実機記録 2026-09-30: inventory probe のみ（Issue #23）

A 節の同じ host で、非 root ユーザーのまま `LinuxProbe().collect()` と
`compare()` を直接実行した（read-only。baseline 承認・startup/daily 実行・
self-test・通知は runtime 未接続のため未実施）。識別子の値は記録していない。

| 対象 | 結果 | 区分 |
|---|---|---|
| CPU | 1 socket、model/family/stepping/cores/logical CPU 数を取得。一意 ID なし → `UNVERIFIABLE` / `UNIQUE_ID_UNAVAILABLE`（誤って OK にしない） | 実機確認済み |
| RAM | `dmidecode` は非 root で不可、DMI table は root 専用 0400 → `MEMORY` 全体 `UNVERIFIABLE` / `PROBE_UNAVAILABLE` | 実機確認済み（Owner 判断が必要） |
| NVMe | serial / WWID と容量・model を取得。再取得との比較 `OK` | 実機確認済み |
| SATA HDD | 容量・model のみ。`UNIQUE_ID_UNAVAILABLE` | **FAIL（下記 重要-3）** |
| GPU | discrete GPU は UUID / serial / PCI を取得して `OK`。CPU 内蔵 GPU は一意 ID なしで `UNVERIFIABLE` | 実機確認済み |
| SMART / NVMe health | 非 root で `smartctl` 不可 → 2 台とも `UNVERIFIABLE`（正常扱いしない） | 実機確認済み |
| baseline なし | 全 kind `UNVERIFIABLE` / `BASELINE_REQUIRED` | 実機確認済み |
| repr | `Component` の repr に location / 識別子を含まない | 実機確認済み |

- **重要-3**: storage probe は `/sys/class/block/<dev>/wwid` と
  `/sys/class/block/<dev>/device/serial` だけを読む。SATA/SCSI disk にはこの 2 つが
  存在せず、非 root で読める `/sys/class/block/<dev>/device/wwid`（および
  `device/vpd_pg80`）があるにもかかわらず、録画 volume 候補の HDD が
  `UNIQUE_ID_UNAVAILABLE` になる。「取得できる最も強い stable identifier を使う」
  という #23 の scope と合わない。
- 要人手 / Owner 判断: RAM（DMI）と SMART を最小権限で読む方法（例: 専用 helper
  や capability 付与）の決定。決定後、専用 service account で再実行する。
- 未確認: Owner baseline 承認と監査、startup/24 時間比較、`CHANGED` / `MISSING` /
  `NEW_DEVICE`、recording-health self-test（現状 `UNAVAILABLE`）、即時通知。


## T. No telemetry / developer reporting

- [ ] inspect Main/Agent/Web dependency inventories, installed packages, and dashboard bundles for analytics, advertising/tracking SDKs, telemetry, and developer-operated crash upload; the prohibition includes opt-in features;
- [ ] inspect controlled startup, ordinary operation, error handling, and configuration paths using browser request inspection/local network observation; no prohibited reporting occurs;
- [ ] explicitly configured product integrations are checked separately and never excuse unrelated reporting; no telemetry feature is introduced without a new explicit Owner decision and ADR changing PRIV-003;
- [ ] traces and deployment identifiers remain local; publish only sanitized pass/fail results, never raw monitoring data, secrets, or private network logs.

### Issue #12 foundation acceptance (pending physical execution)

The synthetic CI tests do not complete these checks. On an isolated Capture Node:

- [ ] Build/verify the versioned Agent artifact and run `--check` as the dedicated
  non-root account; runtime/media directories are outside source/install trees.
- [ ] Inspect the generated `media-capture-agent.service`, its dedicated UID,
  explicit video-node allowlist and empty capabilities; account/device permissions
  remain narrowly configured. Verify process command line and unit name (Linux
  kernel `comm` truncates names longer than 15 visible bytes).
- [ ] Confirm `--check` succeeds both outside and inside the generated systemd
  mount namespace when the media root is a subdirectory of an approved mount.
  A bind of another backing directory on the same device must be rejected.
- [ ] Record the Owner-approved filesystem UUID only in the private deployment
  configuration. On a disposable volume, replace the filesystem while reusing
  the mount path and device name, restart the Agent, and verify `--check` and
  new writes refuse the replacement rather than treating it as the approved
  storage.
- [ ] Start/stop through systemd after #11/#13/#14 integration; verify no GUI/tray,
  no microphone opens, no audio setting and no inbound listener/SSH dependency.
- [ ] Unplug an approved UVC camera: source becomes offline while node heartbeat
  continues. Reconnect obeys stable identity and ambiguous-device approval.
- [ ] Inject excessive clock offset, uncertainty and wall-clock steps using mocks
  or an isolated test process; timing degradation remains visible and is not
  interpreted as reliable event ordering.
- [ ] Use an isolated test filesystem to exercise mount disappearance, replacement,
  read-only state and reserve pressure at startup and runtime. Check descriptor
  pinning and no fallback-directory creation without altering production mounts.
- [ ] Restart at storage hard stop: inventory and authorized cleanup remain
  possible; new allocations and installer `--check` fail until reserve is restored.
- [ ] For each refused `--check` case above, confirm exit status 1 and exactly one
  stderr line ending in the fixed reason code listed in `agent/README.md`
  (`--check --json`: only `{"ok": false, "reason": ...}` on stdout), and that no
  UUID, device number, path, mount source, size or username is printed. Expected
  codes: wrong `filesystem_uuid` → `filesystem_uuid_mismatch`; wrong `major` or
  `minor` → `mount_device_mismatch`; wrong `source` → `mount_source_mismatch`;
  approved mount unmounted → `mount_missing` (media root absent) or
  `media_root_on_root_filesystem` (media root path exists on `/`);
  `mount_point` set to `/` while the media root is on a separate mount →
  `mount_point_is_root`; mount replaced during checks → `mount_replaced`; a
  same-device bind of another directory → `mount_identity_mismatch`; read-only
  mount → `mount_readonly`; media root not writable by the service account →
  `not_writable_by_service_account`; reserve above free space (including above
  filesystem size) → `insufficient_free_space`; malformed/unprotected config →
  `config_invalid`. A passing `--check` still prints the unchanged success line.
- [ ] Confirm network observation after authenticated transport integration shows
  only Owner-configured Main communication, including error/reconnect paths.

Publish only pass/fail summaries; keep configs, mount identity, host identifiers,
credentials and captured media private.

### Issue #12 Agent UVC capture adapter (pending physical execution)

CI verifies `UvcCapture` only with synthetic JPEG-shaped bytes, fake sysfs/udev
trees and fake or synthetic Python subprocess pipelines. None of the following is
verified. Use an isolated Capture Node, a serial-bearing USB/UVC camera pointed at
an empty wall or test chart (no people, no private room details), and a small
local harness that constructs `UvcCapture` + `GStreamerLauncher`; the production
CLI does not wire it yet. Never upload frames, serials, by-id names, topology or
device numbers.

Preparation:

- [ ] Install the distribution GStreamer package providing `gst-launch-1.0`,
  `v4l2src` and `fdsink`; confirm the executable and its parent directories are
  root-owned and not group/world writable, and record the package versions and
  licenses for the Owner dependency decision.
- [ ] Create a dedicated non-root service account that is a member of the
  `video` group (and not `audio`); confirm it can open the camera's `/dev/videoN`
  read-write and cannot open `/dev/snd/*`.
- [ ] Record, privately, that the camera exposes a non-empty USB serial and
  advertises `MJPG` (`v4l2-ctl --list-formats-ext` as the service account).

Capture:

- [ ] As the service account, a never-approved source reports
  `manual_intervention_required`/`owner_approval_required` and starts no process.
- [ ] After `approve()` of the exact current candidate, the source reports
  `degraded`/`capture_starting` and then `online`/`video_ready` only after frames
  arrive; check actual frame size/rate against the requested MJPEG profile.
- [ ] `ps`/`/proc/<pid>/cmdline` of the child show `device=/proc/self/fd/<N>`
  and no `/dev/videoN`, serial or other private value; its environment contains
  only the minimal variables; `/proc/<pid>/fd` of the child shows no audio device.
- [ ] Verify `v4l2src` accepts the inherited descriptor path on this GStreamer
  version; if it does not, record the failure (`capture_failed`) and stop.
- [ ] Configure a profile the camera does not list in
  `v4l2-ctl --list-formats-ext` (size and, separately, frame rate): the source
  reports `offline`/`capture_unsupported` on every poll with no `gst-launch-1.0`
  process ever started; unplug/replug (or Owner re-approval) re-evaluates once.
  If the camera lists a fractional rate such as 29.97, a 30 fps profile starts at
  that rate.
- [ ] With no consumer draining frames, health shows `capture_overloaded` rather
  than `video_ready`; with a consumer, drops stop and health returns to online.
- [ ] Unplug the camera: the source becomes `offline`/`camera_missing` within one
  heartbeat, the pipeline process group is gone, and node heartbeat stays online.
  Replug into a different port: the serial camera rebinds automatically and
  streams again.
- [ ] Stop the stream by suspending the child (`SIGSTOP`): the
  source reports `capture_failed` after the stall timeout, the stopped process
  group is killed and reaped, and relaunch follows bounded backoff.
- [ ] If a camera/driver fault can be reproduced that blocks V4L2 ioctls or
  `open()`, confirm the node heartbeat keeps arriving on schedule while the
  source reports `discovery_failed`/`capture_failed`, and that only one probe
  thread remains blocked.
- [ ] Connect a second camera of the same model and serial (or two identical
  non-serial cameras): no automatic binding; `identity_ambiguous` persists across
  a clean Agent restart until the Owner re-approves.
- [ ] Kill the Agent with SIGKILL during capture: systemd removes the child with
  the service cgroup, and the next start requires re-approval
  (`owner_approval_required`).
- [ ] Under the generated systemd unit (`DevicePolicy=closed`), confirm every
  video node of the attached cameras (including UVC metadata nodes) is in the
  device allowlist; otherwise discovery reports `discovery_failed` and never
  binds. Record whether re-enumeration to another `/dev/videoN` breaks the
  allowlist (an Owner decision for the installer device policy).
- [ ] Confirm the kernel reports Landlock (`/sys/kernel/security/lsm` contains
  `landlock`); on a kernel without it `GStreamerLauncher` must refuse to start.
- [ ] With the camera plus its UVC metadata node (and, if available, a second
  camera) attached, trace one launch as the service account
  (`strace -f -e trace=openat,open,execve,connect`; the registry is disabled,
  so one launch suffices): after
  `landlock_restrict_self` the child opens only `/proc/self/fd/<N>` read-write;
  `/dev`, `/sys/class`, `/sys/bus` and every other `/dev/video*`/`/dev/snd/*`
  open fails or is absent; only `libgstcoreelements.so` and
  `libgstvideo4linux2.so` are loaded (no ALSA/PulseAudio/PipeWire plugin or
  library), no `gst-plugin-scanner` is executed, and no registry file is read
  or created. Recheck frame rate/size against the earlier unsandboxed baseline.
- [ ] Confirm the launcher refuses a sandbox helper or Python interpreter that
  is not root-owned or is group/world writable (e.g. a development checkout).
- [ ] Note that a stalled camera (frames stop without the pipeline exiting)
  keeps reporting `online`/`video_ready` until the stall timeout expires
  (`CaptureLimits.stall_timeout`, default 5 s), then `capture_failed`; confirm
  the observed delay.

Publish only pass/fail summaries.

## U. Privacy-safe diagnostic export / support bundle

Run this only on the intended Main Server using synthetic, non-production diagnostic inputs. Do not upload, commit, attach, or paste the generated bundle, its manifest, private deployment data, raw identifiers, monitoring media, credentials, or biometric material into GitHub.

- [ ] an Owner initiates a diagnostic export from the deployed application; no background, scheduled, or error path creates or transfers a bundle without that explicit action;
- [ ] an uninvited client, invited non-Owner identity, and capture-node credential each fail to create, list, retrieve, or select media for an export through every browser and direct API/copied-URL path; the response reveals no bundle metadata or media;
- [ ] before export, the bundle remains deployment-local; observe the controlled export operation locally and verify that it does not automatically upload/share to a developer or third-party endpoint;
- [ ] use harmless synthetic sentinel inputs to verify credentials, pairing secrets, private keys, and sensitive headers are excluded;
- [ ] verify Owner biometric templates/embeddings are excluded even from an explicitly initiated export, and no selected export authorizes external biometric processing/storage;
- [ ] verify raw hardware serials/UUIDs are absent or redacted/hashed, while the manifest reports only safe categories and exclusion reasons;
- [ ] verify raw monitoring media is absent by default and can be included only after an additional explicit Owner selection; do not use real monitoring media for this check;
- [ ] before authorization, the confirmation names the included categories and every individually selected raw-media item; selecting one synthetic item includes only that item and selecting none includes no media;
- [ ] the manifest records no excluded value, media ID, path, or other private deployment identifier, and the bundle stays deployment-local until the Owner separately chooses how to share it;
- [ ] an export directed at a directory outside the approved storage filesystem, or attempted while the approved mount is missing or substituted, is refused before any space is reserved and never falls back to the root filesystem;
- [ ] cancelling the Owner request or disconnecting mid-export leaves no bundle, partial file, or held reservation behind; repeat the disconnect and confirm archives do not accumulate;
- [ ] with the production producers composed on the deployed Main Server, confirm the bundle's `diagnostics/*.json` holds only fixed states, reason codes, counts and the version: no camera name, role label, capture-node name, UVC/hardware serial, device path, pairing code, Slack webhook URL or Owner template bytes appear (search the bundle locally for the synthetic canaries you configured);
- [ ] stop or leave unconfigured one subsystem at a time (monitoring runtime, camera registry, audit stores) and confirm its fields report `unavailable` with `not_configured` or `dependency_unavailable`, never `ok`, and that no invented counts appear for it;
- [ ] select one synthetic recording segment by its `segment.<id>` media ID and confirm only that segment is copied; confirm Owner biometric or unknown IDs are refused and leave no bundle;
- [ ] record only sanitized PASS/FAIL and aggregate results locally; do not retain the test bundle after the local verification policy permits deletion.

Results: **NOT RUN — Owner authorization/UI integration, production composition of the #49 producers and Main Server network observation remain pending. Synthetic tests do not complete this acceptance.**

## V. Deployed Main Server install / update / rollback lifecycle

Issue #47 remains open. The synthetic CI tests do not complete these checks: they require an actual deployed Main Ubuntu Server installed from a versioned artifact or the documented Docker Compose path, kept separate from any development checkout. Use a disposable host and disposable storage; never run the destructive cases against a production deployment. This section covers Main Server lifecycle data only: capture-agent protected incidents belong to Issue #16 and no capture node is part of this section's environment, so record them as not applicable here and verify their survival in the Issue #28 full-deployment acceptance. Do not commit, attach, or paste release artifacts, private deployment paths, hostnames/IPs, listener addresses, configuration values, credentials, mount/device identities, hardware identifiers, audit contents, or recorded media into GitHub.

- [ ] install the versioned artifact / documented Compose path on a clean Main Ubuntu host without relying on a mutable development checkout; the service runs under its intended dedicated non-root runtime identity;
- [ ] configuration and credentials resolve outside the release checkout, remain admin-managed and runtime-readable but not writable; state/database, recordings, and audit logs use their documented separate mutable locations and are writable only by the intended runtime account;
- [ ] the human listener stays private-by-default behind the intended trusted-proxy boundary after install; it is not exposed to the public Internet and the proxy cannot be bypassed from an ordinary LAN client;
- [ ] before updating, seed a non-vacuous baseline: at least one ordinary recording, one starred recording, one registered camera source, several audit records, and synthetic Owner/invitation records with independent `live:view` / `recordings:view` grants plus a revoked test invitation, so that the comparisons below cannot pass on empty inventories;
- [ ] record a pre-update inventory (version/commit, recording count and sizes, starred recordings, audit record count with oldest/newest timestamps, camera source registrations, Owner presence, and nonidentifying invitation logical IDs with their permission/revocation state, plus Owner-approved hardware baseline) in local sanitized notes only; never record principal identity values, credentials, invitation values, or permission-bearing URLs, and mark each inventory that is empty or not applicable as such instead of counting it as preserved;
- [ ] counts, sizes and boundary timestamps alone cannot detect replaced content, so also record content evidence for the same baseline: each seeded recording's stable logical ID with its locally computed file digest, container duration and a decodable playback sample, and the audit rows' per-row digests or an equivalent chained digest over the whole retained set, not only the first and last rows; keep the digests and logical IDs deployment-local;
- [ ] update to a newer version through the documented lifecycle; the reported version changes and every item of the pre-update inventory survives except for intended, documented migrations;
- [ ] after the update, re-verify the content evidence, not just the counts: the same recording logical IDs are present with unchanged digests, durations and decodable playback, and the audit digests match row for row apart from rows the update itself legitimately appended, each of which is accounted for; a documented migration that intentionally rewrites stored bytes states in advance which logical IDs it rewrites and how the new content is re-verified, and any other digest change is a failure;
- [ ] when the previous version can safely read the retained state, roll back through the documented lifecycle; the service starts and the same inventory is still intact — no recording, starred recording, or audit record is deleted, truncated, or silently rewritten, proven by the same logical IDs, digests, durations, decodable playback samples and audit row digests rather than by matching counts and boundary timestamps;
- [ ] when rolled-back code cannot safely read forward-migrated state, startup refuses and reports the incompatibility truthfully instead of destructively downgrading or discarding data; follow and record the documented recovery path, then compare the same recorded inventory after it restores a startable version/state;
- [ ] repeat update and rollback with an in-progress recording and with storage near the safety reserve; no partial media is left counted as healthy, and the reserve is still honored afterwards;
- [ ] on a disposable volume, safely simulate a missing/unmounted or substituted runtime mount and restart: install, update, and rollback refuse unsafe writes, report an explicit failed/degraded result, and never create or use a silent root-filesystem fallback directory;
- [ ] start with missing or unreadable deployment configuration: the service fails closed with an actionable error and does not invent defaults for storage roots, listener boundary, or secrets;
- [ ] after update and after every rollback that starts successfully, the startup hardware-integrity comparison and the recording-health self-test run again; after a safe rollback refusal, run them only after the documented recovery restores a startable version/state. A changed approved component still requires Owner approval and still produces the immediate Owner notification of section S;
- [ ] record only sanitized PASS/FAIL results and version identifiers locally; keep deployment paths, host identity, configuration, audit contents, recording and audit digests, logical IDs, and media private.

## W. First-run setup wizard / initial configuration

Issue #48 remains open. The synthetic CI and browser integration tests do not complete these checks: they require a freshly installed deployed Main Server with no prior state, reached from a real browser over the intended private access path. Use a disposable deployment and synthetic test identities. Do not publish deployment URLs/hostnames, invitation values, secrets, raw hardware identifiers, biometric material, or monitoring media.

- [ ] on a deployment with no existing state, the first-run wizard is reachable only through the intended private listener/trusted-proxy boundary; an unauthenticated or uninvited ordinary network client cannot read or complete wizard steps and learns nothing about the deployment beyond a generic denial;
- [ ] Owner bootstrap creates exactly one Owner: with two browsers/tabs submitting the bootstrap step concurrently, and with a resubmitted/replayed bootstrap request, exactly one Owner exists afterwards and later attempts are refused rather than creating a second Owner or overwriting the first;
- [ ] after Owner creation, re-opening the wizard does not re-run bootstrap, reset the deployment, or let an unauthenticated visitor claim ownership;
- [ ] as the deployment Owner, run the wizard through Welcome, owner bootstrap, storage, hardware baseline / recorder self-check, locale/time, sources, profiles, optional verification/Slack, and private human-access steps;
- [ ] interrupt the wizard at each step (close the browser, restart the service, reboot the host); it resumes at the same step, previously completed steps are preserved, and no step silently repeats Owner creation;
- [ ] with the wizard open in two Owner browser tabs, advance a step in one tab and then act on the same step in the other: the stale tab's transition is refused, the tab reports that the result could not be confirmed and reloads the committed state, and no completed step is downgraded;
- [ ] each wizard step change attempt by the Owner (including a no-op that requests the current status) appends exactly one `transition_setup_wizard_step` audit record carrying only the fixed action, the step's logical ID and the outcome (no requested status, setting value, secret or identifier); a refused change (stale tab, skipping a required step, a later step before an earlier one, completing a step other than Welcome without its integration) is recorded as `failed` and leaves the state unchanged;
- [ ] an invited `live:view` / `recordings:view` test identity sees no Setup screen, and any wizard read or transition it attempts is refused with a generic denial, records a `denied` outcome for a transition attempt, and changes nothing;
- [ ] a step whose integration is not yet available can be deferred as unavailable (or an optional step skipped) and resumed later; it is never shown as completed, and the screen does not report setup complete while any required step is not completed;
- [ ] the storage step verifies the configured recording root's mount, write permission, free space, and safety reserve; on a disposable volume, a missing/unmounted or substituted filesystem is refused with a truthful error and no root-filesystem fallback is created;
- [ ] the hardware-baseline / recorder self-check step records the Owner-approved baseline, reports unavailable identifiers as `UNVERIFIABLE` rather than as a guarantee, and audits the Owner approval;
- [ ] the locale/time step records time configuration, and excessive clock offset/uncertainty stays visible instead of being presented as reliable event ordering;
- [ ] the source and profile steps complete with zero sources and with 1–4 configured sources; no step assumes a fixed two-camera topology, and absent capture hardware yields a truthful pending/unavailable state rather than a false ready state;
- [ ] skip the optional Owner face verification and Slack steps; skipping leaves them disabled, unavailable dependent features remain explicitly pending rather than appearing complete, and completing them never enrolls a non-owner identity or enables audio capture;
- [ ] the private-access step presents network-level private/Tailscale reachability and ServerSentinel invitation/permission as two independent approvals; Tailnet membership alone never becomes an application invitation, and the wizard neither requests Tailscale administrative credentials nor offers to modify ACLs/Grants;
- [ ] invitations created in the wizard grant `live:view` and `recordings:view` independently, and a `live:view`-only test identity still cannot reach recordings or the historical timeline after the wizard finishes;
- [ ] wizard screens, summaries, generated diagnostics, and service logs expose no settings secrets, pairing values, raw hardware serials/UUIDs, or biometric data;
- [ ] the wizard shell stays usable while unfinished areas remain pending, and completing it leaves the deployment in the documented post-setup state;
- [ ] record only sanitized PASS/FAIL results locally; keep deployment identifiers, invitation values, and any captured frames private.

## X. Security / admin audit log and 90-day retention

Issue #50 remains open. The synthetic CI tests do not complete these checks: they require the deployment-local audit store of a running Main Server, real service restarts, and a clock advanced across the retention boundary. Use a disposable Main Server database, synthetic test actors, synthetic logical target IDs, and synthetic sentinel values; drive retention with an accelerated/test clock or back-dated synthetic audit rows, and never back-date or delete production audit data. Seed the audit fixtures independently of the other subsystems, so that these checks run on the Issue #50 audit store together with whatever recording and retention data the deployment already has. Items naming the unified factual timeline (#26) or capture-agent protected incidents (#16) apply only where those capabilities are already deployed; where they are not, record them as not applicable — never PASS — and repeat the full comparison during the Issue #28 full-deployment acceptance. Do not enter or publish real secrets, biometric material, hardware serials/UUIDs, private network values, audit contents, actor identities, or monitoring media.

- [ ] approve a hardware baseline as the deployment Owner and verify one fixed-action success record with a logical target ID;
- [ ] change a security/admin setting and revoke one test camera, source, or capture node; each record carries actor category, fixed action, target kind, logical target ID, UTC time, and outcome, and nothing more identifying than that;
- [ ] invitation, permission grant/change/revocation, and authorization denials are recorded with their outcome; attempt an Owner-only operation as an invited non-owner principal and verify the mutation does not run while the denied audit outcome is retained;
- [ ] induce a safe synthetic mutation failure and verify a failed audit outcome is recorded without submitted values or exception text;
- [ ] using synthetic sentinel inputs, verify records contain no credentials, pairing secrets, private keys, sensitive headers, raw biometric templates/embeddings, raw hardware serials/UUIDs, or raw media;
- [ ] inspect deployed database permissions and confirm the audit store stays deployment-local with no upload/reporting path; any inclusion in a diagnostic export follows the explicit-Owner-action and redaction rules of section U;
- [ ] audit entries state observed actions and outcomes without asserting culprit, guilt, or causality; where the unified factual timeline is deployed, the audit log stays separate from it and the timeline gains no admin/security detail through it;
- [ ] server-side authorization restricts audit reading to Owner-level access: a non-owner identity with `live:view`, `recordings:view`, or both cannot read, alter, or delete audit records, including through copied URLs, and a capture-node credential cannot reach the audit routes at all;
- [ ] confirm the configured audit retention default is 90 days and is independent of the 20-day recording retention: changing one does not change the other;
- [ ] run retention with a test clock just past 90 days: only expired audit rows are removed while boundary and newer rows remain; run cleanup twice and confirm the second run is idempotent;
- [ ] with the deployment near its storage pressure/hard-stop thresholds, confirm audit writes and retention cleanup are admitted by the same storage reservation: a refused admission fails visibly and records no row instead of spending the hard filesystem reserve;
- [ ] immediately before and after cleanup, compare every non-audit lifecycle inventory the deployment actually has — recording inventory, starred recordings, protected incidents, and their retention/expiry times, plus factual timeline events and capture-agent protected incidents wherever those capabilities are deployed: cleanup applies only to expired audit rows and changes no recording or protected-incident lifecycle; list every inventory that was not yet available instead of reporting it as unchanged;
- [ ] interrupt cleanup (stop the service mid-run, simulate a read-only or full audit volume): the store stays consistent, the failure is reported as a visible fault instead of a silent success, and the next run completes without losing unexpired rows;
- [ ] audit writes survive service restart and are not lost by an unclean shutdown; a security-sensitive mutation and its durable audit record commit together, so a failed audit write fails or rolls back the mutation and surfaces a visible fault rather than silently dropping history;
- [ ] record only sanitized PASS/FAIL counts and timings locally; keep audit exports, actor identities, and deployment values private.

## Y. GitHub review-gate enforcement

Issue #4 remains open. The offline tests do not complete these checks. Follow
`docs/REVIEW_GATE_SETUP.md` after Owner App registration and trusted publisher
implementation. Use harmless synthetic documentation PRs against an isolated
test branch and an equivalent strict rule before activating protection on `main`.
The candidate generator targets `main` only; review any test-branch adaptation
explicitly. Do not alter production protection to make a negative test pass.

- [ ] record the App ID/slug/installation, immutable trusted publisher revision, applied rules, and both required check names with expected App sources;
- [ ] missing either review blocks merge; pending, failed, cancelled, unavailable, skipped and neutral reviewer outcomes each produce a blocking/pending App check (never a skipped/neutral check conclusion, which GitHub accepts);
- [ ] both trusted reviews of the exact current repository/PR/HEAD/base/merge-base/diff allow merge only after independent CI and thread gates pass;
- [ ] push a new PR HEAD and confirm old reviews cannot permit merge;
- [ ] advance the base without changing the PR HEAD and attempt merge immediately, including before the publisher handles the base update; strict protection blocks it;
- [ ] repeat base advancement with a new base already in the PR HEAD's ancestry: checks only on the old test-merge SHA cannot satisfy the new merge context, and no same-name success exists on PR HEAD;
- [ ] check targets are the current GitHub test-merge commit with the pinned base/head parents; missing/stale merge refs block publication;
- [ ] incorporate the new base into the PR, rerun both reviewers, and confirm only the new current context becomes eligible;
- [ ] a same-repository test workflow publishes the identical check names with its ordinary `GITHUB_TOKEN`; even a success from GitHub Actions cannot satisfy the dedicated-App requirement;
- [ ] a same-name commit status and a check from a different synthetic test App cannot satisfy the requirement;
- [ ] copied successful receipt JSON, a forged `Reviewed commit` comment, and a wrong PR/repository/base/diff receipt fail;
- [ ] a newer pending/failed authoritative attempt cannot be hidden by an older successful check; out-of-order completion cannot re-enable stale evidence;
- [ ] fork review completes through the trusted path; fork/same-repository PR code never receives reviewer credentials, the App key or publisher token;
- [ ] a PR retarget, base change during either review, missing API page, provider/API error, malformed receipt and unavailable publisher each fail closed;
- [ ] inspect the App's selected-repository grant and verify the publisher cannot alter source, workflows, branch protection, collaborators or repository administration;
- [ ] demonstrate recovery from a stopped publisher without disabling protection, changing expected issuers or adding bypass actors;
- [ ] record public test PR/run/check IDs, non-secret context digests, rule snapshots and observed GitHub merge refusals, then re-read the production rule after activation.

Never use a real secret as a fixture or publish an App key/token, reviewer token,
raw private API response, or monitoring data. Cleanup only the identified
synthetic test branches/PRs; no production data or unrelated rule deletion.

### Agent ring ledger budget follow-up (#16)

- [ ] Configure an explicit ledger maximum, fill runtime storage toward its reserve on shared and separate filesystems, and verify startup/recovery/metadata writes refuse safely without deleting protected media.
- [ ] Trigger an unexpected authentication loss with the socket still open; verify one T-10/T+10 incident. Remove a synthetic older protected segment after fresh pre-roll is complete and verify overall status remains degraded.

## Issue #20 — Target Main detector acceptance (pending)

- On the target Main Server, run the generated motion workload for 1–4 sources; measure CPU, resident memory, cadence, drops, evaluation latency and sustained health/recording continuity. Record approved per-source budgets without exporting host identifiers.
- Before any person model is loaded, verify exact implementation/runtime/weights licenses, immutable versions, local artifact SHA-256 and the complete dependency notices. Confirm no runtime downloads, alternative-model fallback, reporting or unapproved outbound attempts on normal and failure paths.
- Benchmark the accepted person backend on CPU; GPU is optional and separately measured. External benchmark media stays local under its terms and is never committed or attached to GitHub/CI. No real-model accuracy or target-host performance was verified by synthetic unit tests.
- Stop/delay inference, inject quality loss, stale frames and a wedged plugin in the isolated worker: result must become unknown, loss/throttling remain visible, and capture/recording/health/storage-safety work must continue.
- [ ] On the target Main Server under the production systemd unit, start each configured binding's worker via `maintain()` and record start latency, resident/virtual memory and descriptor use; size `address_space_bytes`/`open_files` so the approved person model loads with margin (native runtimes reserve large virtual ranges) and record the chosen values.
- [ ] With the real person adapter loaded, `SIGSTOP` the worker and separately `SIGKILL` it mid-evaluation: the published result must become `unknown` (`detector_timeout` / `detector_crashed`) within the configured timeout, never `absent`; the child must be reaped (no zombie), restart only after the backoff, and latch after the configured consecutive failures until `recover()`.
- [ ] Kill the Main service process while a worker is mid-evaluation and verify the worker exits (parent-death signal) instead of surviving as an orphan.
- [ ] Confirm the worker inherits the unit's filesystem/network confinement and that its stdio produces no journal output on failure paths.
- [ ] Deploy with the `detection` object omitted and then with one required key removed: `--check`/startup must not start inference, and every source's detector observation must remain `unknown`.

## ADR-0003 follow-up: accepted human-access boundary

These checks belong to #10/#19/#27/#28 during runtime integration, matching the
follow-up recorded in accepted ADR-0003. They are not completed
by the Issue #6 synthetic policy model.

- Verify the reserved hostname serves ServerSentinel alone on every scheme and
  port: enumerate the Serve/reverse-proxy mappings for that name, request
  unrelated paths and other ports, and confirm nothing else answers. Then add a
  second mapping on the same origin, and separately on another HTTPS port of the
  same hostname, and confirm startup refuses to serve instead of continuing,
  including when the configuration cannot be read.
- Confirm the port case really is a cookie leak before relying on the check:
  with a session established, request the second port and observe that the
  browser attaches the `__Host-` session cookie there, which is why the whole
  hostname rather than one origin is reserved.
- Bind an unrelated HTTPS listener directly to the node's Tailscale address from
  a separate local process, creating no proxy mapping. Verify the startup and
  daily listener enumeration detects it, closes human access and notifies the
  Owner, and record explicitly that a bind occurring between two checks is not
  detected until the next one. Then verify the recorded deployment isolation
  (dedicated network identity, or single-purpose node) actually prevents that
  bind, since the application cannot.
- Verify Owner bootstrap provisions the first credential locally: the command
  creates the Owner and a single-use short-lived enrollment authorization, human
  access stays closed until it is redeemed once from the reserved origin with a
  matching identity and user verification, and a second redemption, an expired
  authorization, or a browser connection carrying only the shared login is
  refused with the generic response. Confirm the value appears only on the local
  console and never in logs, audit records, URLs, referrers or diagnostics on
  either the local or the manually transferred remote path.
- Issue an enrollment authorization, run recovery for the same Owner identity
  before redeeming it, and confirm the pending authorization is refused
  afterwards and that only a newly issued one completes recovery. Step the clock
  backwards past its issue time and confirm redemption is refused rather than
  effectively extending the short lifetime.
- Confirm a verified shared-account login with an active invitation but no
  credential-backed session is refused like an uninvited one, that user
  verification is required at every authentication, that revoking one credential
  ends only its own sessions, and that an Owner operation with a stale
  verification performs nothing. Step the host clock backwards after a step-up
  and restore a session record holding a future verification time: both must
  require the step-up again instead of counting as fresh.
- From ordinary LAN and Tailnet clients, attempt direct IPv4/IPv6 upstream access
  and forged identity/forwarded headers, including Docker-published ports. Verify
  no bypass to human routes, assets, health, schema, or SPA/error fallbacks.
- On the installed Serve version, verify spoofed headers are replaced, tagged
  devices have no human identity, and shared-but-uninvited users receive the same
  generic denial. Reject malformed/duplicate/unsupported-encoding identities.
- Verify first-visitor ownership is impossible; local administrator confirmation
  creates exactly one Owner, and a concurrent attempt cannot add a second Owner.
- Check phone/Mac/desktop same-origin session establishment, cookie attributes,
  CSRF rejection, logout, expiry, restart/clock discontinuity, copied cookie/URL
  rejection, and independent live/recordings/history permissions.
- While each supported live/playback transport is actively delivering, revoke
  access from another session. New requests fail after commit; measure delivery
  cancellation across workers and blocked writes against the Owner-approved bound.
  Distinguish server delivery from bytes already buffered in the browser.
- Interrupt local recovery before/after durable commit, restore an authorization
  backup, and simulate unavailable state. Verify fail-closed admission and no
  restored sessions, media deletion, or network-policy mutation.
- Keep real identities, network details, credentials, and media deployment-local.
  Record sanitized outcomes only. No real execution is claimed by the ADR PR.
