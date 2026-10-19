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

#### 実機記録 2026-09-30: 重複承認の拒否と非対応 profile の表示（Issue #11 修正後）

serial 付き同型 USB UVC camera 2 台（正確な model はローカル記録のみ）を接続した Main Server 候補機で、
修正後のコードを video group の非 root ユーザーが実行した。`create_app()` の
lifespan、実 `LinuxDiscovery` / `MmapCapture`、`LocalUvcRuntime.reapprove()` →
`OwnerAdministration.approve_uvc()` の監査付き経路を使用（Owner authorizer のみ
stand-in）。一時 DB は repository 外に作り実行後に削除した。frame は件数だけを
数えて破棄し、保存・閲覧していない。serial・device path・by-id・USB port・UUID
は記録しない。「カメラA/B」「S1/S2」は一時ラベル。

| 確認内容 | 結果 |
|---|---|
| S1 にカメラA を承認して `online` の状態で、S2 にも同じカメラA を承認 | 拒否（`ValueError`、汎用 reason）。`approve_camera` 監査は `succeeded`, `failed`。S2 の承認行は作られない |
| 拒否後 10 秒間 | S1 `online`（300 frame）、S2 `offline`・health event 0・worker failure 0（EBUSY flapping なし）。開いている video node はカメラA だけ |
| S2 に別のカメラB を承認 | `online` |
| 修正前に作られうる重複承認（S2 の承認 evidence をカメラA に書き換えた DB）で再起動、config 順 S1→S2 / S2→S1 の両方 | 両 source とも `manual_intervention_required`（`approval_conflict`）、frame 0、video descriptor 0。起動順に依存しない |
| 上記状態で S1 にカメラA を再承認 | 拒否（S2 が有効なまま保持しているため） |
| Owner が S2 を無効化 | S1 が自動で `online`、S2 `offline`。開いている video node はカメラA だけ |
| desired profile 4K MJPG 30 / 1080p MJPG 60 / 1080p MJPG 15 / 1080p H264 30 | `degraded`（`capture_profile_unavailable`）、negotiated `1920x1080@30 MJPG` を記録、frame 0、video descriptor 0、4 秒間の health event 0（再 open の反復なし） |
| desired profile 1080p YUYV 30 | `degraded`、negotiated `640x480@30 YUYV` を記録、frame 0 |
| 対応 profile（720p MJPG 30 / 480p YUYV 30）と 1080p MJPG 30 への復帰 | `online`、4 秒で 120 frame |
| 全工程の audio descriptor / 停止後の video descriptor | 0 / 0 |

未確認: 抜線・ポート入替・再起動を伴う物理操作、非 serial 同型機、3〜4 source、
実配信 fps の記録（registry は driver の frame interval のみ保持）。

追記（2026-10-11）: 抜線・ポート入替・再列挙は 2026-09-30 の Issue #101 記録と
2026-10-07 の物理抜線記録で、低照度の実配信 fps は 2026-10-07 の P-6 で記録済み。
非 serial 同型機は、手元の C960 が 2 台とも serial を報告するため実機では確認
できない。Owner 判断（2026-10-11）により当面は A-5 の mock（実機 evidence 由来）
で受け入れ、非 serial の同型カメラを導入する時点で実機確認を必須とする
（下記「Ambiguous identical-device test」）。3〜4 source は未確認のまま。

#### フレーム停止 watchdog / presence scan 抑制の実機再確認（実施済み: 2026-10-05 非破壊部分、2026-10-07 Owner 立会いの物理抜線・遮蔽。下記記録）

2026-09-30 の Main Server 候補機（C960 2 台）の抜き差し試験で、source が 0 fps の
まま約 4〜5 秒 `online` と表示された。修正（frame-progress watchdog、live 中の全
device scan を `presence_scan_seconds` 間隔へ抑制）は synthetic fake でのみ確認
済み。次を実機で再確認するまで未検証とする。

1. 2 台を `online` にし、片方を抜線する。抜線から `online` 以外（`degraded`
   `video_frame_stalled` または `offline`）になるまでの時間を記録する。既定値
   （`frame_stall_seconds` 1.0、watchdog 0.25 秒間隔）で概ね 1.5 秒以内を期待。
   もう片方の frame 継続も記録する。
2. 同一 USB bus 上でもう片方が再列挙される場合も含め、抜線・再接続を 10 回以上
   繰り返し、停止中に `online` のままの区間がないこと、frame 再開後にだけ
   `online` へ戻ることを確認する。`video_frame_stalled` から復帰した source の
   negotiated profile が registry に残っていること、停止が
   `frame_stall_reopen_seconds` を超えた場合は `offline` になり再 open されることも
   確認する。profile 残存は `scripts/manual/uvc_watch.py` で記録する。この script は
   1 秒ごとの行に、各 source の registry `negotiated_capture_profile` を
   `profile=幅x高さ@fps/pixel_format` の形で health・実測 fps と並べて出力する
   （例: `src1=degraded 0fps profile=1920x1080@30/MJPG`）。未記録なら
   `profile=none`、driver が報告しなかった項目は `?` と表示する（既定値で補わない）。
   profile は script が毎秒読んでいる registry 行から取り出しており、device の追加
   open や `/dev/snd` へのアクセスはしない。`degraded`（`video_frame_stalled`）の間と
   `online` 復帰直後の行で `profile=none` にならないことを確認し、該当行（serial・
   device path を含まない）を記録へ転記する。`frame_stall_reopen_seconds` を超えて
   `offline` になった行では `profile=none` になってよく、再 open 後の `online` 行で
   profile が再び記録されることを確認する（Issue #173、P-5、Issue #193。出力は
   synthetic registry の unit test でのみ確認済みで、実機記録は Owner 立会いで行う）。
3. レンズを覆う・暗室にするなど低照度で 5 分以上連続取得し、`video_frame_stalled`
   への遷移が 0 回であること（fps 低下で flap しないこと）を確認する。
4. 30 fps × 2 台で 60 秒取得し、live 中の全 device scan が概ね
   `presence_scan_seconds` ごと（既定 1 秒）に抑えられていること、frame 欠落・
   `capture_failed` が増えていないことを確認する（件数のみ記録）。
5. 抜線時に `STREAMOFF`/unmap/close が戻るまでの時間が長い場合でも、teardown
   開始時点で `offline`（`video_capture_closed`）になり、teardown 中に `online`
   と表示されないことを確認する（teardown の所要時間も記録する）。teardown 中の
   遷移は synthetic fake（close が戻らない capture）でのみ確認済み。
6. 記録には serial・device path・by-id・USB port・UUID を含めない。

PR #111 は、上記を実機 C960 で再確認してからマージする。

##### 実機記録 2026-10-05: 非破壊の実カメラ確認（PR #111 head `03bb04f`）

```text
Date: 2026-10-05
ServerSentinel version / Git commit: PR #111 head 03bb04f（#122 の scan 間隔修正を含む、未マージ）
Main Ubuntu version / hardware: 稼働中の Main Server（正確な OS/kernel・hardware は
  INTEGRITY-007 によりローカル記録のみ）。ServerSentinel service は未稼働、
  開始前に video node を保持する process がないことを確認
Camera source(s) / model(s): 本節冒頭と同じ serial 付き同型 USB UVC × 2
USB topology: 2 台とも同じ USB バス上（controller・port はローカル記録のみ）
Tester: Claude Code（Owner 承認 2026-10-05 の非破壊確認。video group の非 root
  ユーザー、sudo・systemd・udev・USB reset/unbind・抜線は不使用）
```

実行方法: repository 外の一時 directory に置いた driver script から、
`create_app()` lifespan を一時 SQLite（実行後削除）で起動し、実 `LinuxDiscovery`
と実 `MmapCapture` で 2 source を構成した（既定 timing: `frame_stall_seconds`
1.0、`frame_stall_reopen_seconds` 5.0、`presence_scan_seconds` 1.0、
`retry_delay_seconds` 0.5）。承認は `LocalUvcRuntime.reapprove()` →
`OwnerAdministration.approve_uvc()` の監査付き経路（authorizer は stand-in）。
discovery は scan 回数・所要時間だけを数える wrapper、capture は実
`MmapCapture` を包み、指定時間だけ frame を source へ渡さない wrapper
（**software 注入の停止**。実 device は開いたまま、USB には触れない）。frame は
件数・byte 数・JPEG SOI/EOI・V4L2 sequence だけをメモリ上で数えて破棄し、
画像の保存・閲覧はしていない。serial・by-id・device path・USB port・UUID は
記録しない。カメラA/B（`src1`/`src2`）は serial の hash 順の一時ラベル。

| # | 確認内容 | 結果 | 区分 |
|---|---|---|---|
| R-1 | discovery: capture node 2 個、失敗 0。両方 `MJPG`/`YUYV`・serial・by-id・topology あり。`model_key` 同一、serial-backed `strong_key` は 2 個で相異なる | PASS | 実機 |
| R-2 | 承認後 `online` まで 0.57–0.71 秒。negotiated `1920x1080@30 MJPG` が registry に記録 | PASS | 実機 |
| R-3 | 2 台同時 90.3 秒（1080p30 MJPG）: 各 2708 frame = 30.00 fps、V4L2 sequence 欠落 0、JPEG marker 異常 0、最大 frame 間隔 37 ms、health event 0、worker failure 0。別 process での再実行 60.2 秒も各 1805 frame = 30.00 fps・欠落 0 | PASS | 実機 |
| R-4 | live 中の全 device scan（手順 4）: source ごとに 0.97–0.98 回/秒（90.3 秒で各 88 回、60.2 秒で各 59 回）、連続 scan の最小間隔 1002–1032 ms、1 回 0.8–1.0 ms（中央値）。修正前（2026-09-30）は frame ごとの scan で 2 source 計約 60 回/秒 | PASS | 実機 |
| R-5 | `src1` に 2.5 秒の software 停止: 1.01 秒後に `degraded`（`video_frame_stalled`）、停止解除後の最初の frame で `online`（注入から 3.03 秒）。negotiated profile は registry に残存。`src2` は 30.09 fps・欠落 0 | PASS | 実機 + software 注入 |
| R-6 | `src1` に 8 秒の software 停止: 1.03 秒で `degraded`（`video_frame_stalled`）、5.04 秒で `offline`（`video_capture_closed` → `video_capture_failed`）、5.6 秒で identity path から再 open（`degraded`/`identity_matched`）、停止継続中は再び `degraded`（`video_frame_stalled`）、frame 再開後 8.85 秒で `online`。停止中に `online` の区間なし。`src2` は 29.99 fps・欠落 0 | PASS | 実機 + software 注入 |
| R-7 | `src2` の worker を read 内で 7 秒 block（watchdog 経路）: watchdog が 1.19 秒で `degraded`（`video_frame_stalled`）、5.19 秒で `offline`（`video_capture_failed`）。worker 復帰後に戻り値の frame を破棄して再 open、注入から 8.07 秒で `online`。`src1` は 30.02 fps・欠落 0 | PASS | 実機 + software 注入 |
| R-8 | 停止・再 open 時の close（`STREAMOFF`/unmap/close）所要: 2–218 ms。lifespan 停止 0.20–0.24 秒、停止時は close 前に `offline`（`video_capture_closed`）を通知、停止後 video/audio descriptor 0/0、registry は両方 `offline` | PASS（hung teardown は未再現） | 実機 |
| R-9 | 全工程で audio descriptor 0、video descriptor は 1 source あたり 5（本体 + mmap buffer 4、上記 提案-4） | PASS | 実機 |
| R-10 | `src1` の scan に 0.6 秒の software 遅延を 15 秒注入（#122 の遅い scan の模擬）: scan 0.60 回/秒、連続 scan 最小間隔 1604 ms（= 完了から 1 秒）。frame 間隔の最大 603 ms（遅延中も scan は完了起点で間引かれ、frame ごとの scan にならない）。遅延中の配信は 21.14 fps（scan 中に driver が frame を破棄）で、窓 1 秒未満のため `online` のまま | PASS（scan 間隔）。scan 中の frame 欠落は注入による想定内 | 実機 + software 注入 |
| R-11 | R-10 の注入終了直前に、**カメラA が自発的に USB 切断・再列挙した**（kernel log に disconnect → 再列挙。人も script も USB に触れていない）。`src1` は即座に `offline`（`video_capture_closed` → `video_capture_failed` → `approved_device_absent`）、再列挙後 `identity_matched` から新しい frame 受信で `online`（`offline` 検出から約 2.9 秒）。`src2` は継続（10 秒窓で 29.03 fps、sequence 欠落 10、再列挙中の scan 最大 274 ms）。今回はもう片方のリセット（#112）は発生せず | 状態表示・取り違えなしの復帰は PASS。切断原因は未特定 | 実機（偶発） |

R-11 の切断は、2026-09-30 の「原因未特定の flapping」と同種の可能性がある。
0.6 秒の DQBUF 停止が誘因かは判断できない（7 秒 block の R-7 では切断なし）。
production 機での USB 再列挙を避けるため、遅延注入の再試行はしていない。

本記録で満たした手順: 4（scan 抑制・欠落なし）。手順 2 の「`video_frame_stalled`
から復帰した source の negotiated profile 残存」「reopen bound 超過で `offline` →
再 open」は software 注入でのみ確認（物理停止ではない）。手順 5 の
「close 前に `offline`」は通常 close でのみ確認。

**要人手（Owner が物理操作。観測用 script は Claude が起動して記録する）**:

1. 準備: ServerSentinel service を止めたまま、`fuser /dev/video*` で保持 process が
   ないことを確認し、観測 script（2 source を承認して 0.05 秒ごとに状態・fps・
   kernel の USB event を表示）を起動する。両方 `online`・30 fps を確認する。
2. 手順 1: カメラA の USB ケーブルだけを抜く。抜いた時刻（秒単位）を声かけ/メモで
   記録する。期待: `src1` が 1.5 秒以内に `online` 以外（`degraded`
   `video_frame_stalled` または `offline`）になる。`src2` が同一バスの相互リセットで
   一時切断した場合も、その間 `online` を表示しないこと。
3. 30 秒待ってから同じポートに挿し直す。期待: 新しい frame 受信後にだけ
   `src1` が `online` に戻る。カメラ B で 2〜3 を繰り返す。
4. 手順 2: 2〜3 を交互に合計 10 回以上繰り返す（抜線間隔 30 秒以上）。各回の
   `online` 以外になるまでの時間と、`online` に戻るまでの時間を記録する。
5. 手順 3: 片方のレンズを不透明なもので 5 分以上覆い（可能なら室内照明も落とす）、
   `video_frame_stalled` への遷移 0 回と実配信 fps を記録する。
6. 手順 5: teardown が長い場合の `offline` 表示は抜線時の close 所要時間から確認する
   （hung teardown の人工再現は行わない）。
7. 終了後、script を止めて video descriptor 0 を確認し、一時 state を削除する。

上記の要人手手順は 2026-10-07 に実施した（次の記録）。

##### 実機記録 2026-10-07: Owner 立会いの物理抜線・遮蔽（PR #111 head `3ead6b5`）

```text
Date: 2026-10-07 20:06–20:23（ローカル時刻）
ServerSentinel version / Git commit: PR #111 head 3ead6b5（main を merge 済み、未マージ）
Main Ubuntu version / hardware: 稼働中の Main Server（正確な OS/kernel・hardware は
  INTEGRITY-007 によりローカル記録のみ）。ServerSentinel service は未稼働
Camera source(s) / model(s): 本節冒頭と同じ serial 付き同型 USB UVC（C960）× 2
USB topology: 2 台とも同じ USB バス上（controller・port はローカル記録のみ）
Tester: Owner（物理抜線・挿し直し・レンズ遮蔽・室内照明）、Claude Code（観測 script
  の起動と記録。sudo・systemd・udev 操作・USB reset/unbind は不使用、カメラには触れない）
```

実行方法: 2026-10-05 記録と同じ観測方法。repository 外の一時 directory の driver
script から `create_app()` lifespan を一時 SQLite（実行後削除）で起動し、実
`LinuxDiscovery` と実 `MmapCapture` で 2 source を構成した（既定 timing:
`frame_stall_seconds` 1.0、`frame_stall_reopen_seconds` 5.0、`presence_scan_seconds`
1.0、`retry_delay_seconds` 0.5）。今回は software による停止注入なし。frame は
件数・byte 数・JPEG SOI/EOI・V4L2 sequence だけをメモリ上で数えて破棄し、画像の
保存・閲覧はしていない。kernel の USB/UVC event は種別と時刻だけを記録した。
カメラA/B（`src1`/`src2`）は serial の hash 順の一時ラベル。

Owner の物理操作（各操作は 30 秒以上の間隔）: B 抜線 20:07:58 / 挿入 約20:09:05、
A 抜線 約20:10:19 / 挿入 約20:11:20、B 抜線 約20:13:00 / 挿入 約20:13:44、
A 抜線 約20:14:29 / 挿入 約20:15:05。続いて室内照明を落とし、片方のレンズを
20:17:29–20:22:41（5 分 12 秒）遮蔽、20:23:31 に遮蔽解除を報告。

同一バス上の自発的な相互リセット（#112）が多発し、必要な 10 回を大きく上回る
切断・再接続が得られたため、Owner と合意のうえ手動抜線は 4 回で打ち切った。
17 分間で kernel の USB disconnect は 23 回（うち物理抜線 4 回）、`src1`(A) は
open 38 回・`online` 以外への遷移 25 回、`src2`(B) は open 6 回・遷移 5 回。

| # | 確認内容 | 結果 | 区分 |
|---|---|---|---|
| P-1 | 手順 1: 最後の frame から `online` 以外になるまで、全 30 episode で 1.13 秒以内。descriptor error / close 経路（26 件）は `offline`（`video_capture_closed`）まで 0.01–0.10 秒（1 件のみ 0.69 秒）、watchdog 経路（4 件: B 1.00 / 1.01 / 1.00 秒、A 1.13 秒）は `degraded`（`video_frame_stalled`）。期待値 1.5 秒以内を満たす。もう片方は同一バスの相互リセットでしばしば同時に切断したが、その間も `online` を表示しなかった（他方の継続性は #112 の host 問題として別途扱う） | PASS | 実機 |
| P-2 | 手順 2（回数）: 物理抜線・挿入 4 回 + 自発的な再列挙（kernel disconnect 23 回、source の非 online episode 計 30 回）で、「10 回以上」は自発的再列挙と手動 4 回の合計で満たした | PASS（回数要件） | 実機 |
| P-3 | 手順 2: 1 秒ごとの観測で、`online` 表示中に frame 0 の区間は 0 回。`online` への復帰は全て再 open 後の新しい frame 受信（`video_capture_ready`）による。復帰は再列挙待ちを含め 1.57–99.87 秒 | PASS | 実機 |
| P-4 | 手順 2: 停止が `frame_stall_reopen_seconds` を超えた場合の `offline` → 再 open を物理的な停止で確認。B は 20:10:26 に 1.01 秒で `degraded`（`video_frame_stalled`）、最後の frame から 5.0 秒で `offline`（`video_capture_failed`）、再列挙後に再 open し `online`。A は 20:15:11 に 1.13 秒で `degraded`、5.1 秒で `offline`、再 open 後 `online` | PASS | 実機 |
| P-5 | 手順 2: `video_frame_stalled` から復帰した source の negotiated profile 残存 | 未記録（観測 script が profile を出力していない。2026-10-05 R-5 の software 注入でのみ確認） | — |
| P-6 | 手順 3: 室内照明を落とした状態で片方のレンズを 5 分 12 秒遮蔽。`video_frame_stalled` への遷移 0 回、bad JPEG 0。照明を落とした時点で両方とも auto exposure により約 30 → 約 16 fps に低下し、遮蔽中の実配信は A 平均 16.4 fps（USB reset 中の約 5 秒を含む。online 時のみでは 16.6）、B 平均 16.7 fps・最小 15.8 fps。遮蔽解除後は両方 29.9 fps。遮蔽中の 20:21:12 に A が自発的な USB reset で一時 `offline`、約 4.8 秒で `online` へ復帰（遮蔽とは無関係の #112 事象） | PASS | 実機 |
| P-7 | 手順 5: close（`STREAMOFF`/unmap/close）所要は最大 5.5 秒（約 5 秒の close が 3 回: 5308.9 / 5008.2 / 5503.0 ms、他は 0.0–341 ms）。3 回とも teardown 開始時点で `offline`（`video_capture_closed`）が通知され（close 完了の 5.0–5.5 秒前）、teardown 中に `online` 表示なし | PASS | 実機 |
| P-8 | 全期間で worker failure 0、watchdog failure 0、sink failure 0、dropped 0、bad JPEG 0（A 18218 frame、B 20564 frame）。V4L2 sequence 欠落は A 391、B 264 で、切断・再列挙の前後に集中。lifespan 停止 0.23 秒、停止後 video descriptor 0、registry は両方 `offline`、一時 state 削除済み | PASS | 実機 |

本記録と 2026-10-05 記録で満たした手順: 1、2（profile 残存は software 注入のみ）、3、
4（2026-10-05）、5（hung teardown の人工再現はせず、物理抜線時の約 5 秒 close で確認）。

Host 側の所見（ServerSentinel の不具合ではない。詳細は #112）: 相互リセットの
多発後、udev worker が約 1 分停止し（`udevadm settle` が timeout）、その間 video
node は udev の権限設定前（root 所有・0600）のままで開けなかった。ServerSentinel
はこの間 `offline`（`approved_device_absent`）を表示し続けた（fail closed）。kernel
は USB control 転送の timeout（-110）と、カメラの audio interface の sample rate
設定失敗を記録した。

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

追記（2026-10-11）: 低照度は 2026-10-07 の実機記録 P-6（室内照明を落とした状態で
5 分 12 秒遮蔽）で記録済み。非serial同型機（手順 7）は実機では未実施のまま、
Owner 判断（2026-10-11）により A-5 の mock（実機 evidence 由来）で当面受け入れ、
非 serial の同型カメラを導入する時点で実機確認を必須とする。3–4 source・browser
viewer（手順 10）・deployment launcher/systemd（手順 1, 2, 8）・Owner 承認経路
（#10）・P-5（profile 残存の実機記録）は未了のため、Issue #11 は引き続き close しない。

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

#### Issue #11 / D3 local camera admin CLI on the Main Server (pending; requires the Owner)

Verified only with a temporary SQLite database, a pseudo-terminal, a fake
device discovery with invented USB ids/serials/paths and a fake `/proc` tree
(`server/tests/test_uvc_admin_cli.py`; one test checks the real `/proc` of the
CI container with a child process holding a temporary file). The command has
not been run on the real Main Server, against a deployment database or with a
real camera. These steps change the real registry and approvals and restart
the production service, so they need the Owner present
(`server/docs/DEPLOYMENT.md`, "Creating sources and approving cameras
locally"). Record serials, ports and device paths only in the private local
record.

- [ ] with the service running, run `create-source` and `approve` as the
  service account: each refuses `service_running` before asking for the
  confirmation and changes nothing; `candidates` and `sources` still work;
- [ ] stop the service; run `candidates` with both C960 connected: two lines,
  each a `cam-` label, `usb=<vendor>:<product>`, `serial=present`, the
  advertised formats and `approved_for=` the source currently approved (or
  `-`); with stdout and stderr redirected to a file, confirm neither holds a
  serial, `/dev/video*`, a by-id name or a USB port; run it twice and confirm
  the labels are the same, then re-plug one camera and confirm only its
  label changed (a `chmod` / `setfacl` of `/dev/videoN` leaves the label
  unchanged; only a change of the sysfs entry's own metadata changes it
  without a re-plug, and `approve` then refuses the old label as
  `candidate_not_found`);
- [ ] `create-source --name <name> --profile 1920x1080@30/MJPG`, type
  `CREATE`: stdout holds only the new UUID and the next steps, and the audit
  log holds one `create_source` record (actor `owner`) with that UUID; type
  anything else: `owner_confirmation_declined`, nothing changes; with four
  enabled sources a fifth refuses `active_source_limit_reached`;
- [ ] add the UUID to `local_uvc.source_ids`, `--check`, then `approve <uuid>
  <label>`, type `APPROVE`: one `approve_camera` record; `sources` shows
  `approval=approved configured=yes`; start the service and confirm the
  source goes `degraded` then `online` with that camera (MANUAL_TEST §A
  runtime procedure steps 4–6), and that the other camera's source is
  untouched;
- [ ] approve the camera already held by another enabled source:
  `camera_approved_for_another_source`; an unknown or stale label (after a
  re-plug): `candidate_not_found`; a source whose profile's pixel format the
  camera does not advertise: `camera_format_unsupported`;
- [ ] when a camera without a serial or two cameras sharing one serial are
  available: `candidates` shows `serial=absent` / `serial=shared` and
  `approve` refuses `camera_without_serial` / `camera_serial_not_unique`
  (until then accepted with the mock, Owner decision 2026-10-11 for §A
  step 7);
- [ ] run as root, as another account and without a controlling terminal
  (`systemd-run`, `cron`): `run_as_service_account` /
  `controlling_terminal_required`, each changing nothing;
- [ ] with the service inside a VM/LXD guest (Owner decision D2), confirm the
  command is run inside that guest; from the host it cannot see the guest's
  service (documented limit: a VM's own kernel, an unprivileged LXD
  container's shifted uids);
- [ ] while another local admin command of the service account holds the
  database (for example `bootstrap_cli` waiting at its confirmation), run
  `create-source`: `service_running`, with the hint naming the other admin
  commands.

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
   Owner 判断（2026-10-11）: 手元の C960 は 2 台とも serial 付きで実機確認は
   不可能。当面は A-5 の mock（実機 evidence 由来）で受け入れ、非 serial の同型
   カメラを導入する時点で本手順の実機確認を必須とする。
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

上記は実機では未確認。手元の C960 は 2 台とも一意の serial を報告するため、
serial を持たない同型機の曖昧性は物理的に再現できない。Owner 判断（2026-10-11）:
当面は 2026-09-30 記録の A-5（serial を除去した実機 evidence による mock で
`manual_intervention_required` / `identity_not_unique`、重複 serial で
`duplicate_identity`）を証跡として受け入れる。非 serial の同型カメラを導入する
時点で、本節の実機確認を必須とする（受け入れ前に未確認のまま運用しない）。
mock での受け入れは Issue #11 全体の close を意味しない。

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
      許容。その間の表示は次項。Owner 判断 2026-10-11: #112（not planned で close）と
      同じ同一バス上の C960 相互リセットという既知制約として扱う。取り違えなく自動
      復帰するため、本項目の不合格は #101 の close を妨げない）;
- [x] 手順 1・3: 切断/入替中に 0 fps の source が `online` を表示しないこと
      （2026-09-30 は不合格。#111 の修正後、2026-10-07 の Owner 立会い物理抜線・
      挿し直し記録 P-1・P-3 で、`online` 表示中に frame 0 の区間 0 回を確認。
      修正後のポート入替（手順 3）の再実施はしていない。Owner 判断 2026-10-11:
      2026-09-30 のポート入替・逆順再列挙の PASS（割当の追従）と 2026-10-07 の
      修正後の物理抜線・挿し直しの PASS で十分とし、修正後のポート入替の個別再実施は
      求めない）;
- [x] 手順 2: 別 port・別 node で serial 照合により再承認なしで復帰;
- [x] 手順 3: port 入替で割当がカメラ個体に追従;
- [x] 手順 4: 再列挙・逆順 node でも再承認なしで正しい source に復帰;
- [x] 手順 5: レンズ遮蔽 30 秒の fps・状態を記録;
- [x] 手順 5: 室内照明を落とした低照度での fps・状態（2026-09-30 は未実施。
      2026-10-07 の実機記録 P-6 で記録済み: 室内照明を落とした状態で 5 分 12 秒遮蔽、
      `video_frame_stalled` への遷移 0 回。fps の値は P-6 を参照）;
- [ ] 遮蔽中の `capture_failed` / reopen flapping と USB 切断（原因未特定。同日の
      その後 3 回の実行では再現せず、2026-10-07 の P-6 遮蔽中も #112 の USB reset に
      よる一時 `offline` 1 回（約 4.8 秒で復帰）のみで、約 1 分間の反復は記録されて
      いない。Owner
      判断 2026-10-11: #112 と同じ系統の既知・未再現の事象として記録に残し、#101 の
      close を妨げない）;
- [ ] 手順 6（Issue #101 本文）: 後片付け（観測用 state directory の削除）の記録
      （個別の記録は残していない。実施したとは記録しない）;
- [ ] （任意）別 USB controller / 給電付き hub 構成での相互リセットの有無。

Owner 判断 2026-10-11: Issue #101 は上記の既存記録（2026-09-30 本記録と
2026-10-07 の Owner 立会い物理抜線・遮蔽記録）で close する。未チェックの項目は、
既知制約（#112 の同一バス相互リセット）・既知で未再現の事象・個別記録なし・任意
項目としてそれぞれ上に記載したとおりで、追加の実機作業は行わない。非 serial 同型機
（#11）の扱いは「Ambiguous identical-device test」を参照。

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

#### Issue #13 real-LAN pairing / mTLS procedure (not yet executed)

Status: **unverified**. Enrollment, the CLIs and mTLS are covered only by
loopback tests with temporary CAs (`server/tests/test_capture_mtls.py`,
`server/tests/test_capture_enrollment.py`, `agent/tests/test_node_tls.py`,
`agent/tests/test_enroll.py`, `tests/e2e/test_capture_mtls_scenarios.py`,
`tests/e2e/test_capture_enrollment_scenarios.py`). No real Main host, capture
host or LAN has run these steps. The ingest listener is not started by the
application yet, so the steps marked *(needs ingest wiring, #14/#15)* wait for
that. Use a disposable deployment CA and synthetic server name; never paste
keys, codes, certificates, bundle contents, LAN addresses or hostnames into
Issues, PRs or CI artifacts. Below, `MAIN_CLI` means the
`serversentinel-pairing` wrapper that the installer places in
`/usr/local/sbin` (Issue #180), which runs
`python -m app.cameras.remote_agent.pairing_cli` of the installed release;
`init`, `rotate-listener`, `approve` and `revoke` run as `sudo MAIN_CLI ...`
(Issue #109) and `export-bundle` and `list` as
`sudo -u <service account> MAIN_CLI ...`. Before step 1, confirm on the Main
that `ls -l /usr/local/sbin/serversentinel-pairing` shows `root root` and
`-rwxr-xr-x`, that `sudo serversentinel-pairing --help` prints
`usage: serversentinel-pairing`, and that after an `update` (and after a
`rollback`) the same command still answers, now from the release `current`
names (`readlink /opt/server-sentinel-main/current`). The wrapper's
environment independence, ownership handling and switch behavior are covered
only by synthetic tests (`server/tests/test_release.py`,
`PairingWrapperTests`); this host check is not yet executed. `AGENT_CLI` means
`python -m media_capture_agent.enroll` run from the Agent's code with
`cryptography` installed.

1. On the Main host, create the static `serversentinel-ca` account and the
   two directories as in `server/docs/DEPLOYMENT.md` ("Accounts, ownership and
   modes"), then run
   `sudo MAIN_CLI init --authority-dir <ca_dir> --listener-dir <listener_dir> --server-name <dns name>`
   (add `--service-user <account>` when the service account is not
   `server-sentinel`) with both directories outside the checkout and media
   trees. Confirm `<ca_dir>` is 0700 `serversentinel-ca` with `ca-key.pem`,
   `ca-certificate.pem` and `issuance-log.jsonl` 0600 `serversentinel-ca`;
   `<listener_dir>` is 0700 service account with `main-server-key.pem`,
   `main-server-certificate.pem` and `deployment-ca-certificate.pem` 0600
   service account; and the two directories differ. The same command without
   `sudo` refuses `privilege_separation_requires_root` and writes nothing, and
   with `--ca-user` equal to `--service-user` refuses
   `ca_account_must_differ_from_service_account`.
2. Choose the bootstrap endpoint: the Main's private-LAN IP and a port distinct
   from the dashboard (loopback-only) and any ingest port. Public addresses
   and Tailscale addresses (IPv4 `100.64.0.0/10` and IPv6
   `fd7a:115c:a1e0::/48`) are refused
   (`enrollment_bind_requires_private_address`); enrollment and ingest use the
   private LAN and need no Tailscale. On a Main that runs Tailscale, confirm
   `approve --listen` with the node's own Tailscale IPv4 and IPv6 address
   (`tailscale ip -4` / `tailscale ip -6`) each refuses before any prompt. Run
   `sudo -u <service account> MAIN_CLI export-bundle --listener-dir <listener_dir> --endpoint <ip>:<port> --output bundle.json`
   (public material only; no root) and note the printed full
   `trust_bundle_sha256`. A listener directory whose `deployment-ca-certificate.pem`
   did not issue its listener certificate must refuse
   `listener_authority_mismatch` and write no bundle. On a Main that runs Tailscale, confirm
   `export-bundle --endpoint` with its Tailscale IPv4 and IPv6 address
   (`--endpoint [<ipv6>]:<port>`) each refuses
   `trust_bundle_endpoint_tailscale_address_refused` and writes no bundle.
   The check is by address range only: a non-Tailscale private network that
   uses `100.64.0.0/10` or `fd7a:115c:a1e0::/48` is refused the same way and
   must use another private address for the Main.
3. Copy `bundle.json` to the capture host over an Owner-trusted channel (for
   example removable media). Do not copy the digest over the same channel.
4. On the capture host, as the dedicated non-root `media-capture-agent`
   account, run
   `AGENT_CLI request --runtime-root <runtime_root> --output request.json`.
   Confirm `<runtime_root>/pending-enrollment` is 0700 and its key file 0600,
   that `request.json` contains no `PRIVATE KEY`, and that no root, GUI,
   Tailscale or admin credential was needed. Confirm running it as root is
   refused (`root_refused`). Note the printed `public_key_sha256`.
5. Carry `request.json` (public) to the Main. Run
   `sudo MAIN_CLI approve --database <data_dir>/state.sqlite3 --authority-dir <ca_dir> --listener-dir <listener_dir> --request request.json --listen <ip>:<port>`
   from an interactive terminal (`request.json` readable by the service
   account; `--listen` port at or above `ip_unprivileged_port_start`);
   `<data_dir>/state.sqlite3` must be the
   database the application already created (a mistyped path refuses
   `database_not_found` and creates nothing; a database the current release has
   not yet migrated refuses `database_schema_outdated` and is left unchanged
   until the application's startup migrates it) (add `--human-host`/`--human-port` when the
   dashboard does not use the default `127.0.0.1:8000`, for example `::1`, and
   confirm `--listen` on that exact socket is refused with
   `enrollment_listener_must_differ_from_other_listeners`). Compare the displayed public-key SHA-256 with
   step 4 and type `APPROVE`. Confirm the code appears only on that terminal,
   not in the command's stdout/stderr (redirect both to files to check), and
   that the same command from a non-interactive session (for example
   `setsid ... </dev/null`) refuses with `controlling_terminal_required`.
6. Confirm the capture host is **not** joined to Tailscale. Negative checks,
   each expected to abort **without** showing `Pairing code:`:
   `AGENT_CLI pair` with a wrong `--bundle-sha256` (no connection is made);
   with `--endpoint` pointing at a host presenting a certificate from another CA
   or for another name; with `--endpoint` pointing at a plaintext service or at
   the dashboard port; with `--endpoint` set to a Tailscale address
   (`100.64.0.0/10` or `[fd7a:115c:a1e0::...]`), which refuses
   `main_endpoint_tailscale_address_refused` with no connection. If a DNS name
   that resolves to a Tailscale address is available on a disposable setup,
   confirm `--endpoint <name>:<port>` refuses the same reason after the TCP
   connect and before any TLS handshake (no Tailscale is needed on the capture
   host for the literal checks). Because the Agent settles on the first
   resolved address that connects, any capture endpoint name used in step 7
   must resolve only to the Main's LAN addresses; confirm with
   `getent ahosts <name>` on the capture host that no `100.64.0.0/10` or
   `fd7a:115c:a1e0::/48` address is returned. If a bundle exported earlier
   with a Tailscale IP literal endpoint is still around, confirm it is refused
   with `main_endpoint_tailscale_address_refused` even with a LAN `--endpoint`
   override, and re-export it. A bundle whose stored endpoint is a DNS name
   that resolves to a Tailscale address is accepted at parse time: without an
   override, confirm it refuses the same reason after the TCP connect; with a
   LAN `--endpoint` override it proceeds (re-export it anyway).
7. Run `AGENT_CLI pair --runtime-root <runtime_root> --trust-bundle bundle.json --bundle-sha256 <digest from step 2>`.
   At `Pairing code:` type the code from step 5 (the hyphen groups may be
   kept). Confirm the typed code is not echoed, the Agent prints
   `paired: node_id=...`, and the Main prints `enrollment completed` with the
   same node UUID and closes the bootstrap port (`ss -ltn` no longer lists it).
   Optionally capture the exchange with `tcpdump` on a disposable deployment and
   confirm it shows only TLS records. Do not keep or upload the capture.
8. Confirm `<runtime_root>/node-credentials` is 0700 with 0600 files and that
   the pending key was removed. Run `sudo -u <service account> MAIN_CLI list --database ...` and confirm
   it shows the node as `activated`/`active` with no digests.
9. With a fresh runtime root, repeat steps 4–5 and let the five minutes pass
   before typing the code: expect `enrollment closed: reason=expired` on the
   Main and a refused connection on the Agent. Reusing a code after success must
   also fail (the listener has closed). A key stays bound to one node for
   good: re-running `approve` with the same `request.json` after an
   interrupted, expired or unacknowledged enrollment shows
   `existing capture node: <uuid>` and re-enrolls that same node (a completed
   enrollment replaces its current certificate); it never creates a second
   node. After `revoke`, the key cannot be approved again: `approve` refuses
   with `public_key_revoked` before showing the `APPROVE` prompt.
10. Start the ingest listener bound to the Main's private-LAN IP and a port
    distinct from the dashboard and bootstrap listeners; confirm the dashboard
    listener still binds loopback only and the ingest port answers no HTTP
    route, and that a Tailscale IPv4 or IPv6 bind is refused with
    `ingest_bind_tailscale_address_refused` *(needs ingest wiring, #14/#15)*.
11. Connect from the Agent: expect a TLS 1.3 session admitted as that node.
    From another LAN host without a node certificate, with a certificate from a
    different CA, and with an expired certificate: expect refusal before any
    capture message is accepted *(needs ingest wiring)*.
12. Run `sudo MAIN_CLI revoke --database ... --authority-dir <ca_dir> --node <uuid>` and type `REVOKE`;
    confirm the last line of `<ca_dir>/issuance-log.jsonl` (read as root) is a
    `node_revocation` for that UUID. The
    open session closes on the next admission check, and reconnecting is
    refused although the certificate has not expired *(needs ingest wiring)*.
    Approving the old `request.json` again must be refused
    (`public_key_revoked`) without showing the prompt or a code.
13. Inspect Main and Agent logs, `ps` output, `/proc/<pid>/cmdline` and
    `environ` during the exchange, service environment and shell history on both
    hosts for key, code or certificate text; expect none.

14. Renewal (Owner decision 2026-09-30: 397-day default, automatic renewal):
    on a disposable deployment, issue a node certificate with a short explicit
    validity so it enters the 30-day window. Confirm that the Agent renews over
    its admitted session, that `pending-renewal/` is 0700 with a 0600 key, and
    that the old certificate keeps working until the renewed one first connects
    and is refused afterwards. Interrupt the first renewal response (for
    example drop the connection after Main stages it) and confirm the Agent's
    retry receives the same certificate (same SHA-256) and that it is admitted. A revoked node's renewal must be refused. After
    the credential expires, the node must re-pair. Block renewal (for example
    stop the Main) until the 14-day threshold and confirm the Owner sees a
    `capture_credential_warning`. *(needs transport wiring and a scheduler)*
15. Main listener certificate rotation (Issue #125), on a disposable
    deployment after step 7: record the listener `not_after`, run
    `sudo MAIN_CLI rotate-listener --authority-dir <ca_dir> --listener-dir <listener_dir>`
    and confirm it prints a new
    `not_after` about 397 days ahead, that the CA key and certificate and the
    exported bundle's SHA-256 are unchanged (the issuance log gains one
    `listener` record), that the listener directory again holds exactly the
    three 0600 files owned by the service account and no `*.next` file, and that the
    key file's SHA-256 changed (compare hashes; never print the key). Restart the listener process, then confirm the
    already-paired Agent connects with its existing trust bundle and no Agent
    change *(needs ingest wiring, #14/#15)*; until then, rerun `approve` with
    a fresh request and confirm `AGENT_CLI pair` with the unchanged bundle
    authenticates the rotated certificate. Negative checks: running
    `rotate-listener` with another deployment's `--authority-dir` refuses
    (`listener_authority_mismatch`) and changes nothing; two `rotate-listener`
    (or `init`) runs started together on the same listener directory leave
    exactly one winner and the other refuses `issuer_material_busy`. Re-running
    `approve` within a minute of a completed one binds again (no
    `enrollment_listener_bind_failed` from TIME_WAIT), while a second
    `approve` on the same `--listen` socket during a running one is refused.
16. CA validity (Issue #127), on a disposable deployment created with
    `--ca-validity-days 100 --server-validity-days 30`: `rotate-listener`
    with the default validity and `approve` refuse
    `deployment_ca_validity_insufficient` before any approval or code is
    shown; `rotate-listener --server-validity-days 30` succeeds. `init`,
    `rotate-listener` and `approve` print `ca_not_after=` and
    `warning: deployment_ca_validity_insufficient` on stderr -- the refused
    `rotate-listener` and `approve` runs too, before their `refused:` line
    and still exiting 2 -- (and
    `listener_certificate_expiring` when the listener leaf has 30 days or
    less), with stdout unchanged; a CA with 398 to 426 days left warns
    `deployment_ca_expiring` instead. A node
    renewal against such a CA is refused `renewal_ca_validity_insufficient`
    and the Owner sees `capture_trust_warning`, not the per-node warning
    *(needs transport wiring and a scheduler)*.

17. CA key separation (Issue #109 PR1). Status: **unverified on real
    hardware**; verified only by the unprivileged tests and by
    `server/tests/test_ca_privilege_separation_root.py` as root in CI and in a
    container (`docker run --cap-add SYS_PTRACE ...`) with two numeric
    accounts. On the Main, with a disposable deployment from step 1:
    a. As the service account, `cat <ca_dir>/ca-key.pem` and
       `ls <ca_dir>` both fail with `Permission denied` (`EACCES`); as
       `serversentinel-ca` they work. Add `"capture_ca_directory": "<ca_dir>"`
       to the deployment configuration and confirm `--check` passes; then
       temporarily `chown <service account> <ca_dir>` with `chmod 000
       <ca_dir>` and confirm `--check` still fails (control, not current
       access, decides; restore owner and mode); give the service account
       write access to `<ca_dir>`'s parent only through a named ACL
       (`setfacl -m u:<service account>:rwx <parent>`) and confirm `--check`
       fails, then remove the ACL (`setfacl -x u:<service account> <parent>`); likewise
       temporarily `chmod 0755 <ca_dir>` and confirm `--check` fails
       (`ServerSentinel deployment validation failed`) and the service does not
       start; restore `0700`.
    b. While `sudo MAIN_CLI approve ...` waits at `Type APPROVE`, confirm from
       another root shell that its process tree has two processes: the command
       (`/proc/<pid>/status` `Uid`/`Gid` all the service account, `CapEff` and
       `CapPrm` `0000000000000000`, `NoNewPrivs: 1`) and its CA child (all
       `serversentinel-ca`, `CapEff` zero, no `/dev/pts/*` and no database in
       `ls -l /proc/<child>/fd`, a different session id). After `APPROVE` and
       before the Agent pairs (the code is shown), confirm the CA child is gone
       (`ps --ppid <pid>` lists nothing) and only the service-account process
       listens on `--listen`.
    c. During that serving phase, as root, scan the serving process's memory
       for the CA key: read `/proc/<pid>/maps` and every readable range of
       `/proc/<pid>/mem` and search for the 32-byte private scalar (big- and
       little-endian), the PKCS#8 DER and the first 40 base64 characters of
       `ca-key.pem` (a short Python script; keep it and its output local).
       Expect no match. As a positive control, the same scan of a root Python
       process that loaded `ca-key.pem` must match.
    d. Make the issuance log unwritable for the CA account (for example
       `chattr +i <ca_dir>/issuance-log.jsonl` on a disposable deployment):
       `approve` must refuse `issuer_unavailable` (`issuer_detail=issuance_log_unavailable`)
       after `APPROVE` without ever showing a code; remove the attribute.
       Change `<ca_dir>` to the service account's ownership: `approve` refuses
       `issuer_unavailable` before the prompt; restore the ownership.
    e. Run `sudo MAIN_CLI revoke ...` for a test node and confirm the
       `node_revocation` record; approving that node's old key again is
       refused by the ledger (`public_key_revoked`) and would also be refused
       by the CA log.
    f. With `<ca_dir>` renamed away, `sudo MAIN_CLI revoke ...` still
       revokes in the ledger, prints `ca_revocation_unrecorded` and exits 1
       (never `ca_directory_exposed`); after renaming it back a rerun records
       the revocation. Remove `capture_ca_directory` from the deployment
       configuration: `--check` fails with `capture_ca_directory is required`.
    g. Kill `sudo MAIN_CLI init ...` on a disposable deployment right after
       the CA side committed (or simulate a lost reply), then rerun the same
       `init`: the CA files are unchanged and only a listener certificate is
       issued (`init recovered`); a further rerun reports `init already
       complete`.
    h. Migration (`server/docs/DEPLOYMENT.md`): on a copy of a pre-#109
       deployment, after the `chown`, `export-bundle` refuses
       `deployment_ca_certificate_missing` until `sudo MAIN_CLI rotate-listener`
       has run once; existing nodes keep connecting.

15. Re-pairing (#116, Owner policy 2026-10-01; mock-verified only by
    `agent/tests/test_enroll.py` and
    `tests/e2e/test_capture_enrollment_scenarios.py`). Stop the
    `media-capture-agent` service first and start it again afterwards.
    a. *Expired, not revoked.* On a disposable deployment, let a node
       certificate expire (issue it with a short explicit validity). Confirm
       `AGENT_CLI request --repair expired` is refused with
       `node_identity_not_expired` before expiry and afterwards prints the same
       `public_key_sha256` as the installed key. `MAIN_CLI approve` with that
       request shows `existing capture node: <uuid>`; type `APPROVE`. Run
       `AGENT_CLI pair ... --repair expired` and confirm it prints the same
       `node_id`, that `node-credentials/` holds exactly one generation (the
       expired files are gone), that `pending-renewal/` holds no key, and that
       ingest admits the node again *(needs ingest wiring)*.
    b. *Revoked.* `MAIN_CLI revoke` the node. Confirm approving its old request
       is refused with `public_key_revoked`. Run
       `AGENT_CLI request --repair revoked` and confirm a different
       `public_key_sha256` and a 0700 `pending-repair/` with a 0600 key;
       `MAIN_CLI approve` shows `new capture node`. After
       `AGENT_CLI pair ... --repair revoked`, confirm a new `node_id`, one
       credential generation, no `pending-repair/node-key.pem`, and that
       `MAIN_CLI list` shows the old node `credential=revoked` and the new one
       `credential=active`. Confirm `pair` printed
       `config_update_required: set "node_id": "<new uuid>" ...`. Before editing
       the configuration, confirm `media-capture-agent --config <file> --check`
       and a service start both exit with `node_identity_mismatch` and that no
       capture process starts and no connection to the Main is opened
       (`ss -tnp`). Then set `node_id` to the new UUID by hand and confirm
       `--check` passes. Corrupt a copy of the credential in a disposable
       runtime root and confirm `node_credential_unavailable`. Confirm
       the new node has no camera source until the Owner approves its sources,
       and that the old node's recordings stay listed under the old node until
       retention *(needs source/transport wiring, #14/#15)*.
    c. *Serialization (#117).* With one `AGENT_CLI pair` waiting at
       `Pairing code:`, start a second `AGENT_CLI pair` (or `request`) on the
       same runtime root from another terminal: it must exit with
       `enrollment_in_progress` without connecting (check with `ss -tn`) or
       prompting. Confirm `<runtime_root>/node-enrollment.lock` is a 0600
       regular file owned by the service account and that no root was needed.

Record the Main/Agent OS, Python, OpenSSL (`cryptography` reports 4.0.2 from its
wheel) and architecture used, without private deployment values.

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

### Issue #205 Main runtime wiring (pending physical execution)

The `SceneMonitoringRuntime` wiring is verified only with synthetic, generated
frames (`server/tests/test_scene_runtime.py`). On real hardware, still to do:

- [ ] a local UVC source negotiated as uncompressed `YUYV` or `GREY` reaches the
  scene worker at the configured sample interval (default 1 sample/s) without
  delaying preview or capture, and a camera whose frames do not match the
  bound layout stays `unknown` (`frame_unusable`);
- [ ] with no stored, re-bindable calibration the source stays inactive and
  `unknown` (`calibration_provider_unconfigured` /
  `calibration_reference_unavailable`), and no critical event is produced;
- [ ] Main-host CPU of the scene worker at 1 to 4 sources while GPU benchmarks run;
- [ ] a confirmed movement/tamper reaches the presence critical timeline with
  neutral wording, in every presence state;
- [ ] unplugging the camera right after a camera shift yields one
  `source_loss_after_scene_shift` tamper, while an unplug alone stays `unknown`.
- [ ] (#224, Owner decision 2026-10-14) with the recorder's storage stalled so
  a camera loss is held, an Owner calibration refresh stays `refresh_pending`;
  after 60 s the source reports `refresh_deferred` (reason
  `critical_backpressure` while the loss is held, otherwise
  `calibration_refresh_deferred`) with `unknown` conclusions, and
  `scene_calibration_refresh_deferred` is logged once; the state clears when
  the refresh runs;
- [ ] (#224) stopping the Main service while critical evidence is still
  undelivered (recorder storage stalled) adds that count as `lost` to the
  presence timeline gap marker, and Owner status reports `timeline_gap` after
  restart; with the outbox close made to fail (for example a refused storage
  admission), the next start reports an interrupted gap instead. This needs
  the outbox wired into Main first (follow-up).

### Issue #217 MJPG decoder on real C960 frames (pending physical execution)

`MjpgLumaLayout` (simplejpeg 1.9.0, Owner decision 2026-10-11) and its per-source
decode child process (`mjpg_worker.py` / `mjpg_child.py`, Owner decision
2026-10-11 on PR #225) are verified only with synthetic, generated JPEGs and
synthetic stand-in children in a network-less, CPU-limited container as an
unprivileged user (`server/tests/test_scene_mjpg.py`). Real camera frames show a real room: keep
any captured frame in memory or in a private, non-repository temporary
directory, delete it after the check, and record only the aggregate numbers
below (no image, no hash of an image, no host/serial values). On the Main host
with each EMEET C960 negotiated as `MJPG` (1080p30 and 720p30), still to do:

- [ ] **DHT presence**: for at least 300 consecutive frames per camera, whether
  every frame carries `DHT` segments or none does (UVC MJPG often omits them
  and relies on the standard tables); all frames must pass the pre-check
  (`inspect_frame`) either way;
- [ ] **bytes after `EOI`**: per camera, the distribution (min / median / max)
  of bytes between the `EOI` marker and the V4L2 `bytesused` end, and what
  they contain (zeros, `0xFF`, other). Set `maximum_trailing_bytes` from this
  (the code default 8192 is provisional) and confirm no real frame is refused
  as `trailing_bytes_exceeded` / `trailing_marker`;
- [ ] **frame size against the byte budget**: per camera and profile, the
  distribution (min / median / max) of `bytesused` over at least 300 frames,
  in a lit and in a dark, noisy scene, compared with `frame_byte_budget`
  (2 bytes per negotiated pixel plus 256 KiB and the trailing bound); no real
  frame may be refused as `frame_too_large`;
- [ ] **other pre-check refusals**: count of real frames refused by any
  pre-check or strict-decode reason over 10 minutes per camera, from the
  source status `undecodable_reasons` (expected 0 apart from genuine transfer
  errors; a systematic refusal means the camera's MJPG differs from the
  reviewed shape and must be reported, not relaxed silently);
- [ ] **post-check refusal rates on real scenes**: over at least 30 minutes per
  camera, in a lit and in a dark room, the counts of the post-decode reasons
  `undecoded_band` (exactly-128 trailing MCUs; a real uniform mid-grey area at
  the bottom right is a known false positive), `decoded_shape_mismatch` and
  `decoder_timeout` (the per-frame deadline, which replaces the earlier
  in-process `decode_too_slow` check), plus `decoder_crashed` /
  `decoder_protocol` (expected 0);
- [ ] **garbled-but-decoded rate**: with the camera fixed on a static scene,
  the fraction of decoded samples whose luma differs from the median of their
  neighbours by more than 16 on more than 5% of pixels (synthetic entropy
  mutants showed about 10% such frames, including a bottom band clamped to 0
  that the band check does not refuse). Record only the aggregate rate; a
  non-zero rate means the quality gate / temporal confirmation must absorb it
  and is reported to the Owner, not hidden by widening the band check to 0/255
  (that would hide a covered lens);
- [ ] **decode time**: median / p95 / max wall time of `MjpgLumaLayout.luma()`
  (child round trip) at the configured reference scale on real frames, with 1
  and with 4 sources at 1 sample/s, while other sessions' GPU benchmarks run;
  confirm it stays far below the 500 ms per-frame deadline (no
  `decoder_timeout`) and that capture/preview frame rates are unchanged; also
  the child start time after bind (frames before it are `decoder_starting`)
  and that a child start never lengthens another source's sample cycle, and
  each child's RSS
  (`/proc/<pid>/status` `VmRSS`; about 30 MiB synthetic) for 4 sources;
- [ ] **decode child inside the systemd sandbox**: inside the real
  `server-sentinel.service` unit (its `ProtectSystem=strict`,
  `RestrictAddressFamilies=`, `NoNewPrivileges=`, `SystemCallFilter=` /
  `MemoryDenyWriteExecute=` if added, and the non-root service user):
  one child per active MJPG source appears under the unit's cgroup
  (`systemctl status server-sentinel` / `systemd-cgls`) as
  `venv/bin/python -I -B .../mjpg_child.py`, owned by the service user, with
  `PPid` = the Main process, `NoNewPrivs: 1`, nice 10 and the expected
  `/proc/<pid>/limits` (address space 256 MiB, open files 16, processes 0,
  core 0, file size 0; `environ` / `fd` are not readable by design); the
  simplejpeg and numpy wheels import inside it (the source does not report
  `frame_decoder_unavailable` or `frame_decoder_failing`) and a real frame
  decodes; check the journal for `SIGSYS`/seccomp or address-space denials;
- [ ] **decode child sandbox on the Main host (Issue #269)**: mock-verified
  only (CPU-limited container on the Main host's Linux 7.0 kernel, Landlock
  ABI 8, CPython 3.12 and 3.14; GitHub Actions `ubuntu-24.04`); not yet run
  inside the deployed unit with a real camera. As the service user, never with
  sudo, with one MJPG source active and decoding:
  - record `uname -r`, the Landlock ABI (`/sys/kernel/security/lsm` contains
    `landlock`) and the deployed interpreter version;
  - each `mjpg_child.py` process shows `Seccomp: 2` and one more
    `Seccomp_filters` than the Main process in `/proc/<pid>/status`, and
    `NoNewPrivs: 1`;
  - the source stays `active` (not `frame_decoder_sandbox_unavailable` /
    `frame_decoder_failing`), real frames decode at 1 sample/s for at least
    one hour with `decoder_crashed` = 0, and the journal / `dmesg` / audit log
    show no `SIGSYS` (`audit: type=1326`) for `mjpg_child.py`; a non-zero
    count means the deployed interpreter or library makes a system call the
    allowlist lacks: record the syscall number from the audit line (not the
    frame) and report it, do not widen the filter in place;
  - the 4K and 1/8-scale reference decodes from the decode-time item above
    still succeed (allocation paths under the filter);
  - `scene_frame_decoder_sandbox_unavailable` is absent from the journal; on a
    kernel without Landlock (not the Main host) it must appear once and the
    source must be `degraded` with every frame `unknown`;
- [ ] **child failure handling on the real host** (as the service user, never
  with sudo; cameras untouched): `kill -KILL <child pid>` gives one
  `decoder_crashed` refusal and a new child pid after about 1 s;
  `kill -STOP <child pid>` gives one `decoder_timeout` and the stopped child is
  gone; `systemctl stop server-sentinel` leaves no `mjpg_child.py` process and
  finishes within the scene stop bound; `kill -KILL` of the Main process leaves
  no orphaned `mjpg_child.py` (parent-death signal);
- [ ] a camera unplugged mid-frame or a USB transfer error yields
  `frame_undecodable` (`unknown`), never `ABSENT` movement or tamper.

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
- [ ] **hard stop while writes are refused** — refusal side re-verified 2026-09-30 (see section Q record); steady-FIFO false hard stop fixed afterwards, pending re-verification. Originally: the run found 83 `segment_storage_refused` appends near exhaustion while status stayed `STORAGE_PRESSURE / post_loss_headroom_reduced`. Repeat the near-reserve fill with **at least two sources whose real bitrate is below the max bound** (single-source or max-size synthetic bytes cannot reveal a false steady-FIFO hard stop): every status sampled before a refused append must read `STORAGE_HARD_STOP / segment_write_refused_at_reserve`, or `STORAGE_PRESSURE` (normally `segment_write_at_risk_at_maximum_bitrate`) when the refused segments exceed the recent-bitrate estimate (mean plus two standard deviations of the batch's recent real allocations, deviations added as if perfectly correlated, or measured from synchronized sources' recent batch history, Issue #130) (the refusal is announced before it happens, never as healthy); accepted steady-FIFO appends with fixed-size segments must not read hard stop, and with **variable segment sizes** (real VBR) record the false hard-stop rate (hard stop read before a minute whose every append succeeded) and every refusal's preceding status: Issue #130 mock runs with normally distributed sizes read hard stop before 45 of 400 such accepted samples with two 60 s sources (47 with the pre-#130 charge) and announced all 9 refusals with hard stop, so a higher rate, or any refusal after a healthy status, is a failure; record the share of refusals that followed pressure rather than hard stop, since every estimate below the bound misses some tails (`agent/docs/RING_BUFFER.md`); also record the per-append size history so the deviation factor (2, Owner decision 2026-10-05) can be tuned; free space must stay at or above the reserve; and status must leave hard stop once space is released. Known limitation (also documented in `agent/docs/RING_BUFFER.md`): immediately after a refusal the refused segment's `missing` row counts as that source's last write, so status may show `STORAGE_PRESSURE / post_loss_headroom_reduced` until the next refusal is imminent again, and the refused interval's coverage gap is hidden behind pressure in the status priority; record the refused intervals from the append results.

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

### Agent-to-Main transport PoC (Issue #15, ADR-0007 — pending physical execution)

Synthetic continuity tests do not verify any transport. For each candidate
(WebRTC, QUIC, authenticated HTTP/WebSocket streaming; SRT was dropped by the
Owner decision of 2026-10-11, see ADR-0007) on the real Main
Server, capture node and UVC camera over the private LAN, and for 1, 2, 3 and 4
sources (record which sources are real cameras and which are synthetic input):

- [ ] the session is mutually authenticated with the ADR-0006 mTLS identity; an unpaired, revoked or wrong-deployment certificate delivers no media;
- [ ] the ingest listener is not the human dashboard listener and serves no human/admin route; the capture credential cannot call a human/admin API;
- [ ] deterministic impairment matrix: 1 s, 5 s and ~2 min link loss; sustained packet loss; added jitter; a deliberately slow Main consumer;
- [ ] after each impairment, reported gaps match the units actually missing (exact count when the capture epoch continued, unknown extent after a capture restart); a lossless reconnect reports no gap;
- [ ] no interval with known loss is presented as healthy; flow shows degraded/interrupted during and after loss until the gap is recorded;
- [ ] a retry after a lost acknowledgement never duplicates media in the recording;
- [ ] sender and receiver queue depth and memory stay bounded under slow consumer and link loss;
- [ ] a fifth source is refused by the active-source limit.

Record per run: reconnect time, reported vs actual gap, maximum queue depth,
CPU/GPU/VRAM on Main and Agent, bitrate, informational LAN latency,
codec/container and recording-extraction impact, and the exact dependency
versions/licences. Enter the results in the ADR-0007 validation table; do not
attach private addresses, credentials or real footage.

### 実機記録テンプレート: Issue #15 transport PoC 計測ハーネス（未実施）

手順は [`scripts/manual/transport_poc/README.md`](scripts/manual/transport_poc/README.md)
（step 0 の read-only inventory、使い捨て materials、1 scenario ずつの実行、kill switch
`systemctl --user stop 'ss-poc15-*'`、1 日 3 時間上限、cleanup checklist）。ハーネスの PR
時点の確認は同一 host の loopback・synthetic 入力だけで、以下は**どれも実機では未実施**です。
TCP の packet loss / jitter は root の `netem` を使わないため `unmeasured` のまま残し、
QUIC / WebRTC はこのハーネスの対象外です。

```text
Date / tester:
ServerSentinel Git commit (harness HEAD):
Main host（粗い値のみ）/ capture host（粗い値のみ）:
Candidate(s): a_framed / b_chunked / b_segment
Sources: n=  real cameras=  synthetic (gst / builtin)=
Profile / bitrate:
CPU cap (Main CPUQuota / capture CPUQuota):
Run id(s):
Total run time today (≤ 3 h):
```

- [ ] step 0 inventory を両 host で取得し、47200–47214 が未使用であることを確認した;
- [ ] G1: `auth_unpaired` / `auth_other_ca` / `auth_revoked` / `auth_revoked_live` で受理 media 0、`route_probe` でハーネス receiver に human route なし（製品の human/admin API は上の transport PoC 項目で別途確認）;
- [ ] G2: 各 impairment 後の報告 gap が実欠落と一致（epoch 内は完全一致、capture 再起動は範囲不明）、重複 commit 0、sender の unit 収支（末尾 drop を含む）が照合済み（`drop_accounting` が `pass`）;
- [ ] G3: receiver queue / kernel send queue の滞留 byte（`TIOCOUTQ` と `ss -tmi` の skmem `w`）/ VmHWM が設定上限内で warmup 後に増加しない;
- [ ] G4: 手動操作なしで再接続し p95 ≤ 10 s（再接続時間は impairment の終了から。2 host の Main 側停止・再起動は Main 時計「window 終了 → 後続接続の `session_hello`」+ Agent 時計「`connected` → `first_accept`」で、Main の停止時間を含めない。#237 の変更後の 2 host / 実 LAN での確認は**未実施**）;
- [ ] #237 の harness 修正（heartbeat 応答記録と停止の協調、`stopped` / `stopping` 記録、応答への echo 付け直し、fast `slow_stop_10s` 4 s）を含む HEAD で実行し、2 host run の receiver 記録に `stopping`（`coordinated: true`）、Main 側 orchestrator 記録に `sigstop` の後の `stopped` があることを生記録レビューで確かめた（未実施）;
- [ ] G5: 無音断の検知 ≤ 15 s、Main の未 commit 区間が Agent 保護区間 [T−600 s, T+600 s] に含まれる;
- [ ] G6: CPU 制限下の 4 source で backpressure 0、5 source 目は拒否;
- [ ] 全 run が非 fast（`--fast` なし。summary の各 run 行と候補行の `fast` が `false`、`fast_runs` が 0）;
- [ ] 2 host の run では G5 の Main `interrupted`（proxy blackhole）が件数照合（window との時刻対応なし）であることを結果に併記した（Main 側停止・再起動の Agent 検知と再接続は session nonce で対応付け済み）;
- [ ] 1 / 2 / 3 / 4 source の各構成を候補ごとに実行した（`normal` / `sources_2` / `sources_3` / `capacity_4`、summary の `*_missing_source_counts` が 0）、全 run の `integrity` が `pass`（別実行の記録の混入・子 process の異常終了なし）;
- [ ] 副次: 30 分 soak（full matrix とは別の日に実行）で予期しない切断 0、overhead ≤ 10 %、実カメラ passthrough 1 台あたり Agent CPU ≤ 1 core の 50 %、latency p95（参考）;
- [ ] cleanup checklist を完了（使い捨て CA / ledger / node 鍵 / holder state を削除、`ss-poc15-*` scope なし）;
- [ ] ADR-0007 へ転記する前に、Claude と Owner が全 run の生 JSONL 記録（各 run directory の
  orchestrator / receiver / sender / proxy と holder の記録。summary だけではない）を確認し、
  summary の判定が記録と食い違わないこと（想定外の `fail` / `unmeasured`、記録の欠落・混在、
  不自然な時刻や件数が無いこと）を確かめ、確認した run id と確認者を記録した;
- [ ] 結果を ADR-0007 Validation 表へ転記し、real / synthetic の内訳と未測定項目を明記した。

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

### Issue #205 CP-5 Web live screen (pending; needs the CP-4 routes)

Mock-verified only: `web/tests/live.test.mjs` and `web/tests/browser.mjs`
(headless Chrome, synthetic route answers, a generated JPEG). Not yet run
against the real Main Server routes, a real camera or a physical device.

- [ ] phone (Safari) and Mac/desktop browser over the reserved HTTPS origin: Live shows each permitted source and a moving picture from one `local_uvc` source;
- [ ] a `live:view`-only viewer sees Live and no recording, timeline or history; a `recordings:view`-only viewer has Live disabled and the browser sends no `/api/live/` request;
- [ ] the picture is drawn without a CSP violation report (developer console) on Safari and Chrome;
- [ ] putting the tab in the background or locking the phone closes the viewer session (server viewer count drops) and returns it on return;
- [ ] unplugging the camera marks the picture not current or ends the view; it never keeps showing an old frame as current;
- [ ] revoking `live:view` or the person while watching ends the view and clears the picture;
- [ ] sign-out from the dashboard returns to the sign-in shell and the old cookie no longer opens `/app/`;
- [ ] no download, save or export control is offered (browser capture of the screen remains possible and is not claimed otherwise).

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
- [ ] the dashboard origin is reserved for ServerSentinel and is a secure context (HTTPS; the human composition accepts only the reserved `https` origin and there is no `http://localhost` Owner route, Owner decisions 2026-10-11 and 2026-10-16); open it by URL from a Tailscale-joined viewer device outside the Main Server (phone, Mac or desktop), confirm WebAuthn registration and sign-in actually work there, and record that an ordinary-HTTP non-loopback origin makes them impossible;
- [ ] the startup and daily reservation check enumerates the real listeners and every proxy route for the whole name across all schemes and ports, and closes human access and notifies the Owner on any other answer it can see; confirm separately (kernel forwarding step) that no DNAT/REDIRECT/TPROXY/`sk_lookup`/IPVS forwarding reaches the reserved address, and record that this bounds rather than prevents, so a process binding between checks can collect credentials until the next check;
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
- [ ] confirm there is no `http://localhost` Owner route (Owner decision,
  2026-10-11): from the Main Server's own browser, `http://localhost` and
  `http://127.0.0.1` on every Main Server port reach no ceremony and get only
  the generic denial or a refused connection, and the Owner signs in through
  the reserved `https` origin like everyone else. Also confirm a plain-HTTP
  non-loopback origin cannot use WebAuthn at all;
- [ ] inspect the database after these runs. It holds only credential ids,
  COSE public keys, counters, BE/BS flags, labels and timestamps, plus the
  SHA-256 digests of challenges still pending. It holds no raw challenge,
  client data, signature or biometric data. Logs contain none of these either.

### Issue #10 phase 1 human route foundation (pending)

`server/app/auth/human_surface.py` is verified only with a synthetic ASGI driver
(`server/tests/test_human_surface.py`): no socket, Tailscale Serve, browser or
real authenticator has exercised it. The production launcher builds the
composition from an enabled `human_access` deployment section (CP-1), not yet
exercised on real hosts. Once a deployment enables it, verify on the Main Server
with synthetic `*.invalid` identities:

- [ ] through the installed Tailscale Serve, record the `Host` header and peer
  address the loopback upstream actually receives; the surface requires exactly
  one `Host` equal to the reserved `<hostname>[:<port>]` and a loopback peer,
  so a Serve that rewrites `Host` keeps every route denied (fail closed);
- [ ] record whether the installed Serve replaces a client-supplied
  `Tailscale-User-Login` and how it forwards a duplicate; the surface refuses a
  repeated, comma-joined or encoded login;
- [ ] from another LAN host, send requests with a forged `Tailscale-User-Login`
  and `X-Forwarded-For: 127.0.0.1` to every Main Server address and port and
  confirm none reaches the human upstream (it binds loopback only) and every
  response is the generic denial or a refused connection;
- [ ] sign in with a passkey at the reserved origin and confirm
  `GET /api/session` returns only the caller's own role and permissions, that
  the cookie is `__Host-session` with `Secure; HttpOnly; SameSite=Strict` and
  no `Domain`, and that every other path (live, recordings, events, timeline,
  health, version, download) is the generic denial for both a `live:view`-only
  and a `recordings:view`-only person;
- [ ] repeat sign-in attempts quickly and confirm they are refused with the
  generic denial after the burst, that one value-free
  `human_request_rate_limited` log event appears, and that sign-in works again
  after a short wait; record that people sharing one Tailscale login share
  this limit;
- [ ] stop the reservation check from passing (for example remove the Serve
  mapping) and confirm sign-in and the session route are denied until it
  passes again.

### Issue #10 phase 2 S1 sign-out and CSRF (pending)

Verified only with the synthetic ASGI driver and synthetic stores
(`server/tests/test_human_gated_authorization.py`,
`tests/e2e/test_access_matrix_scenarios.py`); no browser, Tailscale Serve or
real authenticator has exercised sign-out or the CSRF header yet; the production launcher mounts the human routes only from an enabled
`human_access` deployment section (CP-1), not yet exercised on real hosts.
Once a deployment enables it, verify on a shared machine (one OS account and browser profile, the shared
Tailscale login, synthetic `*.invalid` people with their own passkeys on
roaming authenticators):

- [ ] person A signs in, the dashboard reads `GET /api/session` and keeps the
  returned `csrf` only in memory; confirm the value never appears in the URL,
  browser history, server logs or the audit log;
- [ ] A signs out; confirm the response is `204` with
  `Set-Cookie: __Host-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`,
  that the browser no longer sends the cookie, and that the audit log holds one
  `sign_out_principal` record with A's logical UUID only;
- [ ] press the Back button and reload the previous dashboard page, and replay
  A's old cookie value (copied before sign-out, for example with a request
  tool on the loopback upstream path); every request is the generic denial,
  identical to an uninvited caller's;
- [ ] person B then signs in with B's own passkey in the same browser profile
  and sees only B's permissions; A's old cookie stays denied;
- [ ] send the sign-out without `X-CSRF-Token`, with another session's token,
  with a modified token, without `Origin`, and from another origin; each is the
  generic denial, the session still works afterwards and no audit record is
  written;
- [ ] stop the reservation check from passing and try to sign out; confirm the
  generic denial (accepted by Owner decision D7), that the session is still
  present once the check passes again, and record that an emergency revocation
  while access is closed is done over SSH with the local command;
- [ ] record that sign-out ends this session only: a synced passkey of A can
  still sign in on any device that holds it until the Owner revokes that
  credential.

### Issue #10 phase 2 S2 console bootstrap, redemption and recovery (pending)

Verified only with the synthetic ASGI driver, software authenticators and a
pseudo-terminal (`server/tests/test_invitation_redemption.py`,
`server/tests/test_bootstrap_cli.py`, `tests/e2e/test_access_matrix_scenarios.py`);
no real terminal session, browser, Tailscale Serve or authenticator has
exercised them. The production launcher mounts the human routes only from an
enabled `human_access` deployment section (CP-1), not yet exercised on real
hosts. Once a deployment enables them, on the Main Server with a synthetic
`*.invalid` Owner name:

- [ ] over SSH, run `bootstrap` as the service account
  (`server/docs/DEPLOYMENT.md`, "Owner bootstrap and recovery"); confirm the
  code appears only on that terminal, not in stdout redirected to a file,
  journald, the application log, the audit log or the shell history, and
  that the audit log holds `invite_principal` and
  `issue_principal_invitation` with the Owner's logical UUID only;
- [ ] run it again with stdin/stdout redirected and from a context without a
  controlling terminal (for example `systemd-run` or `cron`): it refuses with
  `controlling_terminal_required` and changes nothing; run it as root: it
  refuses with `run_as_service_account`; run `bootstrap` a second time: it
  refuses with `owner_already_configured`; set
  `"invitation_lifetime_hours": 2` and confirm the console code's expiry is two
  hours after issuance;
- [ ] in a real browser at the reserved `https` origin, enter the console
  code once, register a passkey (user verification is prompted), and
  confirm the registration response is `204` with no cookie and no application
  data, that the code is in no URL, browser history entry or server log, and
  that the Owner then signs in and `GET /api/session` reports `owner`;
- [ ] enter the same code again, a mistyped code, and a code after its
  lifetime (24 hours, or the deployment's `invitation_lifetime_hours`): each is
  the generic denial, identical to an uninvited caller's;
- [ ] issue a code, set the Main Server's wall clock back by two hours, enter
  the code while the clock is still set back: it is the generic denial (clock
  rollback on the same boot); only then restore the clock. Issue another code,
  reboot the host and redeem it within its lifetime: it works (the wall clock
  decides after a reboot; for the unit's wait for `time-sync.target`, see the
  section V clock synchronization item);
- [ ] issue a code, lower `"invitation_lifetime_hours"` and restart the
  service: the code already issued keeps its original expiry (intended);
- [ ] with the optional `"invitation_lifetime_hours"` set, run `rollback` to an
  installed release that predates the key: the installer refuses before any
  change, naming no configuration value, and `current`, `previous` and the
  unit are unchanged; remove the key and the same `rollback` proceeds;
- [ ] submit a few wrong codes and confirm the application log holds
  `invitation_redemption_refused` (first refusal, then at 2, 4, 8, ...) with no
  code, identity or reason;
- [ ] submit a dozen wrong codes quickly from one browser: after the burst of
  5 they are refused before the server does any work (one value-free
  `human_request_rate_limited` log event), a correct code is refused too until
  12 seconds pass, and sign-in for another person keeps working meanwhile;
  record that people sharing one Tailscale login share this limit, and that
  another Tailscale login's redemption is not slowed (no global redemption
  bucket);
- [ ] in two browsers, open the registration with the same valid code and
  finish both at once: exactly one credential is registered and the other
  gets the generic denial;
- [ ] with a deployment that requires device-bound credentials, try a synced
  passkey: the fixed `device_bound_credential_required` response appears, the
  code stays usable, and a device-bound authenticator then registers;
- [ ] run `recover` while the Owner and an invitee are signed in and an
  invitation is pending: both sessions end on their next request, the pending
  invitation and the old Owner passkey (on every synced device) no longer
  work, the new console code registers a replacement Owner passkey (on the
  same synced authenticator that held the revoked one, which must not refuse
  it as already registered), and the audit log holds `invalidate_human_sessions`, `revoke_principal_credential`
  and `issue_principal_invitation`; recordings and capture nodes are
  unchanged.

### Issue #10 phase 2 S3 Owner step-up (pending)

Verified only with the synthetic ASGI driver, software authenticators and a
synthetic boot clock (`server/tests/test_human_step_up.py`,
`tests/e2e/test_access_matrix_scenarios.py`); no browser, Tailscale Serve,
real authenticator or real clock step has exercised it, and the production launcher mounts the human routes only from an enabled
`human_access` deployment section (CP-1), not yet exercised on real hosts; the `403 step_up_required` contract is
exercised through the S4b administration routes in the tests. Once a
deployment enables the routes, on a shared machine (one OS account and browser profile,
the shared Tailscale login, a synthetic `*.invalid` Owner and a synthetic
`*.invalid` invitee, each with their own passkey on a separate roaming
authenticator):

- [ ] two people at one workstation, Owner session left stale: the Owner
  signs in, performs one Owner operation, and walks away without signing
  out; after more than five minutes the invitee, at the same browser
  profile, starts an Owner operation: it answers `403
  {"detail":"step_up_required"}` and does nothing; the invitee completes the
  step-up prompt with the invitee's own passkey (presented through the
  browser's "use another device/security key" choice): the step-up is the
  generic denial, the operation still answers `403`, the audit log has no new
  `verify_principal_step_up` record, and the Owner's session verification
  time is unchanged; record that the browser may refuse to offer a
  credential outside `allowCredentials` at all, which is the same outcome;
- [ ] the Owner returns and completes the step-up with the Owner's own
  passkey (user verification prompted): `204`, one `verify_principal_step_up`
  record with the Owner's logical UUID only, and the retried operation runs;
  record that the stale Owner session served every non-Owner request to
  whoever sat at the machine meanwhile (residual: a session left unlocked on
  an unattended machine), and that signing out before leaving is the
  mitigation;
- [ ] wait exactly past five minutes after the step-up and confirm the next
  Owner operation answers `403` again;
- [ ] cancel the step-up prompt, decline user verification, and let the
  prompt time out: each leaves the operation undone, the session's
  verification time unchanged and no audit record, and the application log
  shows `owner_step_up_refused` (first refusal, then at 2, 4, 8, ...) with no
  token, challenge, credential or identity;
- [ ] send the step-up requests without `X-CSRF-Token`, with another
  session's token, without `Origin` and from another origin: each is the
  generic denial; as the invitee (non-Owner) call both step-up routes with
  the invitee's own valid session and CSRF token: the generic denial;
- [ ] stop the reservation check from passing between the options and the
  finish request: the finish is the generic denial and nothing is refreshed;
- [ ] right after a step-up, step the Main Server's wall clock back by two
  minutes (on a disposable host, with NTP stopped) and retry an Owner
  operation: it is not served as fresh (`403`, or the generic denial while the
  clock is behind the session's last activity); restore the clock, step up
  again and confirm it works; reboot the host after a step-up and confirm the
  next Owner operation asks for a step-up again;
- [ ] repeat the step-up quickly many times: after a burst of 5 it is
  refused with the generic denial before any work (one more every 12
  seconds), with one value-free `human_request_rate_limited` event; while it
  is refused, sign-in from the same shared login still works, and after
  exhausting the sign-in burst the Owner can still step up (separate buckets,
  Owner decision 2026-10-12); record that everyone behind the shared login
  shares the step-up bucket;
- [ ] on a disposable host running chrony (NTP reachable), record
  `chronyc tracking` and `maxslewrate`, step up, then make chrony slew the
  wall clock back by a few seconds (for example a local reference offset,
  never `makestep`) and repeat an Owner operation every few seconds for five
  minutes: record whether the session stayed fresh (expected: a slew moves
  `CLOCK_BOOTTIME` too) or turned stale early (`403 step_up_required`, fail
  closed, availability only); either way confirm a new step-up works and the
  window never exceeds five minutes.

### Issue #238 step-up follow-ups (pending, not executed)

Mock only: verified with the synthetic ASGI driver, software authenticators,
a synthetic boot clock and patched storage failures
(`server/tests/test_human_step_up.py` `FollowUpTests` and
`StepUpFindingStoreTests`); no browser, real authenticator, real storage
hard stop or real notification channel has exercised it, and the production launcher mounts the human routes only from an enabled
`human_access` deployment section (CP-1), not yet exercised on real hosts.
Once a deployment enables the routes, with a synthetic `*.invalid` Owner whose passkey is on a roaming
authenticator usable from two separate browser profiles (A and B), on a
disposable deployment:

- [ ] another session cannot spend a challenge: sign the Owner in from
  profile A and from profile B; wait more than five minutes so both are
  stale; in A request step-up options and copy the challenge from the
  developer tools before answering A's prompt; in B, with B's own cookie and
  `X-CSRF-Token`, obtain an assertion for A's challenge
  (`navigator.credentials.get` from the developer tools console with A's
  options) and submit it to `POST /api/auth/step-up`, once unchanged and
  once with the assertion's signature altered: each is the generic denial,
  B's next Owner operation still answers `403 {"detail":"step_up_required"}`,
  and the audit log has no new `verify_principal_step_up` record; then
  complete A's still-open step-up prompt with the same challenge: `204`, one
  `verify_principal_step_up` record, and A's retried Owner operation runs;
- [ ] a request without a current session spends nothing: repeat with B
  signed out (or idle past 30 minutes) before it submits A's challenge, and
  separately with B's request carrying another Tailscale login than B's
  session was bound to: each is the generic denial and A still completes its
  step-up with the same challenge (`204`); record that a challenge only one
  session can redeem stays pending until its normal expiry when that session
  never answers (availability only);
- [ ] a finding whose write fails is observable: in A request step-up
  options, then drive the Main state storage into `STORAGE_HARD_STOP` (fill
  its filesystem to the safety reserve), then answer with an assertion whose
  backup-eligibility flag differs from registration (the same method as in
  the WebAuthn credential checks above): the generic denial, no
  `mark_principal_credential_inconsistent` audit record, no Owner
  notification, and the application log (journald for the service) shows one
  WARNING `credential_finding_unrecorded` event carrying only the event name
  (no kind, principal, credential, challenge, token, identity or reason);
  repeat to a third and a fourth failure and confirm the event appears at
  the first, second and fourth failure only (1, 2, 4, 8, ...); release the
  space, sign in or step up again with the changed flag and confirm the
  finding is now recorded and notified (the stored credential was unchanged,
  so it is detected again); record that the in-process counter is not
  persisted across a restart;
- [ ] a racing finding is notified once: with the Owner signed in from A and
  B (both stale), request step-up options in both, then answer both prompts
  with a changed backup-eligibility assertion as close together as possible
  (and separately one step-up and one sign-in): both are the generic denial,
  both sessions end, the credential is shown inconsistent, the audit log has
  exactly one `mark_principal_credential_inconsistent` record and the Owner
  receives exactly one notification; record whether the two finishes
  actually overlapped (the dedup is exercised either way: the later finish
  finds the credential already marked).

### Issue #10 phase 2 S4b Owner access administration routes (pending)

Mock only: verified with the synthetic ASGI driver, software authenticators
and a synthetic boot clock (`server/tests/test_human_admin_routes.py`,
`server/tests/test_access_administration.py`,
`tests/e2e/test_access_matrix_scenarios.py`); no browser, Tailscale Serve,
real authenticator or real deployment has exercised them, the production launcher mounts the human routes only from an enabled
`human_access` deployment section (CP-1), not yet exercised on real hosts, and the Owner's Web screen is S6.
Once a deployment enables the routes, with a synthetic `*.invalid` Owner
and synthetic invitees, each with their own passkey:

- [ ] as the Owner (fresh), `POST /api/admin/principals` with a display name
  and `["live:view"]`: `200` with `principal_id`, `code`, `expires_at`;
  record that the code appears only in that response (not in the inventory,
  the application log, the audit log or the browser's URL bar or history);
- [ ] the invitee redeems the code at the plain redemption screen with their
  own passkey and signs in: `GET /api/session` lists exactly `live:view`;
- [ ] `GET /api/admin/principals` lists every principal with its permissions,
  pending-code summary and credential handles, and never a Tailscale login,
  credential id or public key (inspect the raw response);
- [ ] withdraw `live:view` (`POST .../permissions` with `granted: false`):
  the invitee's open session ends at its next request; repeat the request
  (nothing to change): `204`, the session of a re-signed-in invitee stays;
- [ ] re-issue the code (`POST .../invitation`) for an active invitee: the
  old code is refused, the new one registers a second passkey; revoke the
  first passkey by its handle (`POST .../credentials/<handle>/revoke`): only
  sessions of that passkey end, and a synced copy of it on another device of
  the invitee no longer signs in either (credential-scoped, all synced
  devices);
- [ ] revoke the invitee (`POST .../revoke`): every session of theirs ends and
  their pending code is refused;
- [ ] wait more than five minutes after the Owner's sign-in or step-up and
  repeat any change: `403 {"detail":"step_up_required"}`, nothing changed;
  step up and retry: it runs; record that the stale `403` did not extend
  the Owner session's idle expiry;
- [ ] as an invitee with `live:view`, `recordings:view` or both, call every
  route with the invitee's own session and CSRF token: the generic `404`;
  without `X-CSRF-Token`, without `Origin`, from another origin, or with the
  Owner as the target: the generic `404`, and nothing changed;
- [ ] send more than 20 changes within a few seconds from one Owner session
  (for example a repeated no-op grant): the excess gets the generic `404`
  and writes no audit record; after a few seconds changes run again, and
  another session's changes were never limited by it; repeated change
  requests from invitee sessions (each with its own CSRF token) beforehand
  never stop the Owner's change (they are refused before the limiter, PR
  #242 review);
- [ ] check the audit log: each change has its records with the principal's
  logical UUID only (no code, display name, handle, credential id or
  identity): an invitation (A2) has two, `invite_principal` and
  `issue_principal_invitation`, and every other change (A3-A6) has one.

### Issue #10 phase 2 S4c local emergency revocation over SSH (pending; requires the Owner)

Verified only with a temporary SQLite database, a pseudo-terminal and the
synthetic ASGI driver with software authenticators
(`server/tests/test_local_revocation_cli.py`); the command has not been run
on the real Main Server or against any deployment database. These steps
change real access state and need the Owner present; they were not executed
as part of the S4c change. Once a deployment enables the human routes, on
the Main Server, with synthetic `*.invalid` invitees and their own test
passkeys (never a real person's credential):

- [ ] over SSH, as the service account, run `list`
  (`server/docs/DEPLOYMENT.md`, "Emergency revocation over SSH"); confirm it
  shows each principal's logical UUID, role, status, grants and display name
  and each credential's handle, status and label, and no Tailscale login,
  credential id, key, code or session data; confirm the output with stdout
  redirected to a file holds nothing else, and that `list` adds no audit
  record;
- [ ] with two test invitees signed in from two browsers, make human access
  closed (stop the reservation check from passing), run `revoke-principal`
  for invitee A, type `REVOKE`, and confirm the stdout line holds A's logical
  UUID only and the audit log holds one `revoke_principal` record with that
  UUID; let the check pass again: A's next request (reload) is the generic
  denial without a service restart, A's pending code (if any) is refused,
  and invitee B still works;
- [ ] register a synced passkey for invitee B on two devices of the same
  sync account, sign in on both, run `revoke-credential` for that handle
  and confirm the prompt says it is revoked on all the devices it synced to:
  both devices' next requests are denied and neither can sign in with it
  again; record that the revocation is credential-scoped, not per device;
- [ ] run both commands with the Owner's UUID / handle: each refuses with
  `owner_target_use_recover` and points to `recover`; repeat a finished
  revocation: `principal_already_revoked` / `credential_already_revoked`;
  type anything but `REVOKE`: `owner_confirmation_declined`; run as root,
  without a controlling terminal (`systemd-run`, `cron`) and as another
  account: `run_as_service_account` / `controlling_terminal_required`, each
  changing nothing;
- [ ] run a revocation while the Owner's Web operation on the same invitee
  is in flight (for example a grant change submitted right after the
  command commits): the Web operation is refused and changes nothing.

### Issue #10 phase 2 S5a sign-in shell in real browsers (pending, not executed)

`web/src/signin/` is verified only in headless Chrome with intercepted
requests and a CDP virtual authenticator (`web/tests/signin_browser.mjs`) and
with Node unit tests; no real browser, passkey provider or security key has
used it. Since S5b the Main Server serves it at `/` (mock-verified with a
synthetic build), CI loads the real `npm run build` output through the
server's loader in `server/tests/test_web_build_contract.py`, and since S5c
the release ships that build. Once a deployment serves `/` at the reserved
`https` origin, run with synthetic `*.invalid` people on
each of **iOS Safari**, **macOS Safari** and **Android Chrome** (and record the
browser and OS versions used):

- [ ] `/` shows only 「サインイン」, the sign-in button, the invitation code
  field and the label field 「このパスキーの目印（任意）」, in Japanese, with no
  product name, camera wording, version or favicon; the page source and
  `/s.js`, `/s.css` carry none either;
- [ ] redeem a fresh invitation code typed by hand in lower case with spaces,
  and once with the Japanese IME on (full-width characters, 「ー」 as the
  separator): it registers, the page shows 「登録しました。サインインしてください。」
  and focus moves to the sign-in button; the code field is empty afterwards;
- [ ] on **iOS Safari** and **macOS Safari** (and Firefox if available), the
  registration and sign-in `POST`s reach the Main Server with the exact
  `Origin` of the reserved origin, never `Origin: null`, and no `Referer`
  (Web Inspector → Network → request headers, or the Main Server's ceremony
  outcome): registration and sign-in both succeed; the documents themselves
  still answer with `Referrer-Policy: no-referrer`;
- [ ] a label of 64 emoji registers and is shown whole in the Owner's
  credential list; a label of 65 characters shows the generic message and
  sends nothing;
- [ ] the OS / browser passkey sheet asks for user verification at
  registration and at sign-in; sign-in lands on `/app/`;
- [ ] sign in with a roaming **security key** (USB or NFC) registered
  through the shell as a discoverable credential: in the browser's developer
  tools, the sign-in `POST` body carries `response.userHandle` as a non-empty
  string (not `null`) and sign-in succeeds; record the key model. A key that
  returns `null` there is refused by the server (the shell sends the member,
  never omits it) and must be recorded as such;
- [ ] with a valid session, opening `/` goes straight to `/app/`;
- [ ] a wrong, expired or already used code, a cancelled passkey sheet and a
  refused sign-in each show only 「完了できませんでした。もう一度お試しください。」 and
  nothing from the server;
- [ ] on a deployment that requires device-bound credentials, registering a
  synced passkey (iCloud Keychain / Google Password Manager) shows the
  device-bound guidance, and a security key then registers;
- [ ] type a code (and a label), navigate to another page without
  registering, then press Back: both fields are empty (also after a
  back-forward cache restore);
- [ ] with the Main Server not answering `GET /api/session`, the form appears
  after about 5 s;
- [ ] after each attempt, the code appears nowhere in the address bar, the
  history list, the browser's saved form data / password manager prompts, or
  the Web Inspector's storage panes (local / session storage, IndexedDB,
  cookies other than `__Host-session`);
- [ ] the browser console reports no Content-Security-Policy violation on `/`
  other than, possibly, an `img-src` one for the browser's own automatic
  `/favicon.ico` request (expected: the shell has no favicon and its policy is
  `img-src 'none'`), and `/` opened over plain HTTP from another host shows only
  「このブラウザーまたは接続ではパスキーを使えません。」;
- [ ] the layout fits a phone screen without horizontal scrolling in portrait
  and landscape, in light and dark appearance.

### Issue #10 phase 2 S5b sign-in shell and application asset serving (pending)

Mock only: verified with a synthetic Web build, the synthetic ASGI driver and
software authenticators (`server/tests/test_human_web_assets.py`), and CI
loads the real S5a build through the same loader
(`server/tests/test_web_build_contract.py`); no browser has loaded, rendered
or enforced the response policies of the shell or the application, and no
Tailscale Serve or real deployment has served them. The release ships the
build since S5c (next section). Once a deployment enables the human
routes with that build, from a browser on the shared account at the reserved
name:

- [ ] open `https://<reserved name>/` without any session: the sign-in shell
  loads with its script and style; record the response headers in the
  browser's developer tools (exactly the fixed list of
  `server/app/auth/README.md`, "Web assets", `no-store`, no `Set-Cookie`,
  `ETag`, `Last-Modified`, `Server` or `Date`) and that the console shows no
  CSP violation other than, possibly, an `img-src` one for the browser's own
  automatic `/favicon.ico` request (the shell has no favicon and its policy is
  `img-src 'none'`; the request itself is the generic `404`);
- [ ] load `/`, `/s.js` and `/s.css` from two browsers (one signed in as the
  Owner, one never invited) and compare the bodies' SHA-256: identical; reload
  with the cache disabled and enabled: always `200`, never `304`;
- [ ] without a session, request `/app/`, `/app/app.js` and a missing
  `/app/<name>`: the generic `404` for each; sign in with a test invitee that
  holds no permission: `/app/` and its assets load; sign out: they are the
  generic `404` again;
- [ ] stay on `/app/` with only asset reloads for more than 30 minutes after
  the last other request: the next request is the generic `404` (assets do
  not extend the session);
- [ ] try to embed `/` and `/app/` in a frame from another origin: the browser
  refuses (`frame-ancestors 'none'`); confirm `HEAD /`, `/index.html`,
  `/s.js?x=1` and `/app/app.js.map` are the generic `404`;
- [ ] replace a file of the deployed build on disk while the service runs: the
  served bytes do not change; restart with the modified build: the human
  routes stay closed (the manifest no longer matches).

### Issue #10 phase 2 S5c Web build in the release (pending, not executed)

Mock only: the release build, the installer's placement and the rollback
check were exercised with a synthetic Web build in temporary directories
(`server/tests/test_release_web_assets.py`), as the test account standing
for root; no real artifact has been built with the real `npm ci && npm run
build` output, and no host has installed or rolled back one. On a build host
and then on the Main Server (Owner, synthetic data only):

- [ ] build the release as in `server/docs/DEPLOYMENT.md` ("Release
  artifact"): `node --version` is the major of `web/package.json` `engines`
  (24), `npm ci --ignore-scripts` then `npm run build` in `web/`; build again
  and compare: `diff -r` of the two `web/dist` reports nothing and the two
  release manifests (`tar -xOzf <artifact> manifest.json`) list the same
  `web/...` SHA-256 values; build the release artifact twice from the same
  checkout, wheelhouse and `web/dist` (two `--output` paths) and confirm
  `sha256sum` prints the same value for both `.tar.gz` files, equal to the
  `sha256=` each build printed;
- [ ] with the administrator umask at `0002` (`umask` prints `0002`), install
  or update with the installer: `stat -c '%U %a %h' ` on every entry of
  `<installation>/releases/<version>/web` prints `root 755` for directories
  and `root 444 1` for files; `find <release>/web -links +1` prints nothing;
- [ ] add `"web_assets_directory": "<installation>/current/web"` to the
  deployment configuration and run, as the service account,
  `<installation>/current/venv/bin/python -m app.deployment --config <config>
  --check`: it passes; with the key pointing at a missing directory it fails
  with `web assets refused (reason=path)` and names no path;
- [ ] on a disposable test installation only, change one byte of a file
  under `releases/<older version>/web/` as root and run `rollback`: it is
  refused before any change with the "differs from its release manifest"
  steps; `current`, `previous` and the unit are unchanged.

### Issue #10 S7 interim live (pending)

Mock only: the routes, authorization, limits, lease and retention are verified
with synthetic JPEG-shaped bytes, the synthetic ASGI driver and software
authenticators (`server/tests/test_live_frame_routes.py`). No browser has
decoded a real camera frame, no Web live screen exists yet (CP-5), and no real
deployment has served the routes. Once a deployment enables the human routes
with an approved `local_uvc` camera, from browsers on the shared account at
the reserved name:

- [ ] a test invitee with `live:view` only: the source list shows each
  approved camera's name and health only, a session opens and frames decode
  in Safari (iPhone), Safari (Mac) and Chrome/Firefox (desktop); record
  whether the camera's MJPG frames without a Huffman table (DHT) decode in
  each browser;
- [ ] a test invitee with `recordings:view` only: every live route is the
  generic `404`;
- [ ] copy the frame URL from the developer tools into another invitee's
  browser and into a second sign-in of the same invitee: the generic `404`;
  the original viewer keeps receiving frames;
- [ ] measured frame rate per viewer stays at or below 5 fps; record latency
  and the Main Server CPU with 1, 2 and 4 viewers;
- [ ] a third viewer on one camera, and a fifth in total, gets the generic
  `404`; a person's third session is refused too;
- [ ] close the viewer's tab: within about 15 seconds the preview reports no
  viewer (no retained frame); revoke the invitee (or withdraw `live:view`) in
  the Owner administration while watching: frames stop at once;
- [ ] unplug the camera while watching: the frame route answers `204` and the
  source list shows it offline; no pre-loss frame is shown as live; replug and
  re-approve: frames resume;
- [ ] watch for more than 30 minutes: the session does not idle out while
  frames are pulled; then stop pulling and do nothing else: the session ends
  at its idle limit;
- [ ] the frame response has `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff` and no `Content-Disposition`; the browser
  offers no download button in the application.

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
- [ ] once the runtime wires the entrance adapter: the historical timeline shows an `entrance_gate` `unknown` fact when the entrance gate stops being sufficient (and when its detector stops) and a `ready` fact when it recovers, so the dark period is distinguishable from a period without crossings; the fact never reads as `no person`;
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
- [ ] **Issue #130, pending real-disk verification**: repeat the near-reserve fill with at least two sources whose real segment sizes vary below the max bound (real segmenter output or generated variable sizes spanning many allocation units). Record per minute the status before the appends and whether every append succeeded. Expect: no refusal preceded by `healthy` or `degraded`; refusals preceded by `STORAGE_HARD_STOP / segment_write_refused_at_reserve`, except a batch above the recent-bitrate estimate (a spike or a size tail), which may follow `STORAGE_PRESSURE`; record whether the sources' segment intervals align (same cadence, overlapping intervals, so the measured batch-total charge applies once ten aligned segments exist); hard stop before accepted minutes no more frequent than with the pre-#130 recent-maximum charge (compare against the same run on the pre-#130 code if possible; the mock runs show only small reductions from the measured batch history, 47 → 45 with two and 26 → 23 with four independent synchronized sources). The Issue #130 numbers in `agent/docs/RING_BUFFER.md` come from a mock quota and seeded synthetic sizes only;
- [x] **Issue #130 / PR #272 real-disk run (2026-10-16, real disk, synthetic payload)**: capture host, disposable loop-mounted ext4 volume (4 GiB), real `MediaStore`/`DiskRing` (mount/UUID/free space/fsync), seeded synthetic segment bytes and an injected trusted clock. No camera, segmenter, transport or UI. Code: PR #272 head `40bbb36`, merge-base `213fb46` (pre-PR main) and, as a reference, the merge-base with the pre-#130 recent-maximum charge (test `legacy_charge` constants). `--check` passed on the approved mount for both codes. Profile: 2/3/4 sources, all 10 s segments (aligned), max 1 Mbit/s (305 allocation units), Gaussian sizes with mean 0.5×bound and sd 0.08×bound (independent, or a 0.8 common-factor correlation), seeds 130/131/132, duration 600 s, reserve 256 MiB, ledger cap 32 MiB; after 600 s of warm-up an external filler leaves 60×N units above reserve + ledger headroom; 720 steps per run, 54 runs. Results (3 seeds summed, base → PR): no refusal preceded by healthy/degraded in any run; every refused batch within its estimate was preceded by `STORAGE_HARD_STOP / segment_write_refused_at_reserve`; refusals preceded by PRESSURE (all `post_loss_headroom_reduced`, all batches above their estimate): 2 sources 9 %/5 % (independent/correlated), 3 sources 0 %/3 %, 4 sources 0 %/7.7 % → 6.8 %, never more than base; false hard stop (per accepted step): 2 sources 164 → 153 / 193 → 189, 3 sources 208 → 182 / 197 → 197, 4 sources 397 → 361 / 307 → 304 (pre-#130: 158/191, 198/197, 398/307); the measured charge applied on 65–84 % of steps (fallback after a refusal's gap until 10 aligned batches are rebuilt) and was below the pre-#130 cap on 22/46/62 % (independent 2/3/4) and 6–10 % (correlated) of steps; free space never went below the reserve (minimum free − reserve 64.2 MiB = ledger headroom); in every run, filling to half the ledger headroom gave `STORAGE_HARD_STOP / ledger_reserve_unavailable` and refused the append, and deleting the fill cleared it to `degraded / pre_loss_coverage_gap` and appends resumed. Owner decision 2026-10-19: merge PR #272 on this result. Still open: real segmenter VBR (temporal autocorrelation, spikes) and real camera input, which the pending item above still covers; the false hard-stop rate with 4 sources (about 17 %) is left to a later Owner decision on the deviation factor. Raw per-step data is kept in a local private record.
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
- [ ] record the content inventory with `python -m app.lifecycle_inventory record` from the installed release into an administrator-private directory outside the runtime root, installation tree and any checkout (see `server/docs/DEPLOYMENT.md`, "Preservation inventory across update and rollback"); the command must report every coverage item as `present` (exit 0), otherwise seed the missing items first. After update, after every successful rollback and after a refused rollback's documented recovery, run `python -m app.lifecycle_inventory verify` against the same baseline and record only its status line: `preserved` (exit 0) passes, `failed` (exit 1) fails, `empty` (exit 3) is not a pass, and `preserved_except_declared_rewrites` (exit 4) passes only once each declared recording has been re-verified manually. Do not star or unstar recordings between `record` and `verify`; a star change is reported as `changed` and remains a failure. The tool does not probe container duration or decode media; those remain the manual items below;
- [ ] record a pre-update inventory (version/commit, recording count and sizes, starred recordings, audit record count with oldest/newest timestamps, camera source registrations, Owner presence, and nonidentifying invitation logical IDs with their permission/revocation state, plus Owner-approved hardware baseline) in local sanitized notes only; never record principal identity values, credentials, invitation values, or permission-bearing URLs, and mark each inventory that is empty or not applicable as such instead of counting it as preserved;
- [ ] counts, sizes and boundary timestamps alone cannot detect replaced content, so also record content evidence for the same baseline: each seeded recording's stable logical ID with its locally computed file digest (recorded by the inventory tool), container duration and a decodable playback sample (both manual: probe and play each seeded recording with a local player and note PASS/FAIL per logical ID), and the audit rows' per-row digests or an equivalent chained digest over the whole retained set, not only the first and last rows; keep the digests and logical IDs deployment-local;
- [ ] update to a newer version through the documented lifecycle; the reported version changes and every item of the pre-update inventory survives except for intended, documented migrations;
- [ ] after the update, re-verify the content evidence, not just the counts: the same recording logical IDs are present with unchanged digests, durations and decodable playback, and the audit digests match row for row apart from rows the update itself legitimately appended, each of which is accounted for; a documented migration that intentionally rewrites stored bytes states in advance which logical IDs it rewrites and how the new content is re-verified, and any other digest change is a failure;
- [ ] when the previous version can safely read the retained state, roll back through the documented lifecycle; the service starts and the same inventory is still intact — no recording, starred recording, or audit record is deleted, truncated, or silently rewritten, proven by the same logical IDs, digests, durations, decodable playback samples and audit row digests rather than by matching counts and boundary timestamps;
- [ ] when rolled-back code cannot safely read forward-migrated state, startup refuses and reports the incompatibility truthfully instead of destructively downgrading or discarding data; follow and record the documented recovery path, then compare the same recorded inventory after it restores a startable version/state;
- [ ] socket-activation boundary (Issue #126): with `server-sentinel-upstream.socket` installed in `/etc/systemd/system` and enabled and `human_port` below 1024, roll back to a release from before socket activation; confirm the installer refuses before any change (same `current`/`previous`, unit and running service), prints the Owner steps (no `mask`), and only queried the socket unit (`systemctl show -p LoadState/ActiveState`). Follow the printed steps in order: restore the earlier `human_port`; `disable --now` the socket unit and confirm the dashboard still answers on the running service; rerun once before parking the file and confirm it still refuses (`LoadState=loaded`); move the unit file to `/etc/server-sentinel/disabled/`, rerun once more before `daemon-reload` and confirm it still refuses; `daemon-reload` and confirm `LoadState=not-found`, `ActiveState=inactive`; rerun the rollback and confirm the service now listens on the earlier port without a separate restart, that `systemctl show server-sentinel.service -p Wants -p After` no longer names the socket unit, and that a reboot leaves the socket unit unstarted; point Tailscale Serve at the earlier port. Then return in the printed order (update forward and confirm the parked socket unit stays not-found and the release binds the old port; set the privileged `human_port`; move the unit file back, `daemon-reload`, `enable --now` the socket unit and confirm the running service still listens on the old port; `systemctl restart server-sentinel.service`; point Serve back) and confirm the upstream is socket-activated again (one socket on the port, its inode in `/proc/<service pid>/fd`). Also make the `systemctl` query fail (for example a `PATH` without `systemctl` on a disposable host) and confirm the refusal still prints the steps;
- [ ] repeat update and rollback with an in-progress recording and with storage near the safety reserve; no partial media is left counted as healthy, and the reserve is still honored afterwards;
- [ ] on a disposable volume, safely simulate a missing/unmounted or substituted runtime mount and restart: install, update, and rollback refuse unsafe writes, report an explicit failed/degraded result, and never create or use a silent root-filesystem fallback directory;
- [ ] database volume maintenance (Issue #152): with the service running, confirm the database file's descriptor stays open in `/proc/<service pid>/fd` and that unmounting the `state` volume is refused (`EBUSY`) rather than forced; then stop the service (and confirm no pairing CLI command is running), remount or restore the volume/database file, start the service again, and confirm startup checks and migrations succeed on the restored file and the earlier inventory is intact. Never use a lazy unmount or swap the database file under a running service;
- [ ] clock synchronization before start (Issue #235 item 4, Owner decision 2026-10-14; not run, mock-verified only), on a disposable host or VM, never the production Main host: after `install`, confirm `systemctl show server-sentinel.service -p After` names `time-sync.target`, `-p Wants` does not, and `TimeoutStopSec=90` is unchanged; with neither `chrony-wait.service` nor `systemd-time-wait-sync.service` enabled (and once with one enabled only `--runtime`), confirm `install`/`update`/`rollback` complete with exit status 0, print the time-sync warning with the enabling steps on standard error, and changed no time configuration (same `timedatectl show` output and same `systemctl is-enabled` states before and after); enable the wait service of the host's time daemon, rerun an `update` and confirm no warning. Then, with the network to every time source blocked and the RTC set a few hours back while powered off (or a VM started with an earlier RTC), boot: confirm the service stays queued behind the wait (`systemctl list-jobs`, `systemd-analyze critical-chain server-sentinel.service`) and does not start before `timedatectl show -p NTPSynchronized` is `yes`; restore the network within the wait service's limit and confirm it starts once synchronized with the correct wall clock (journal timestamps of the startup records). Boot again with the network kept blocked: with `chrony-wait.service` as shipped (`TimeoutStartSec=180`), confirm the wait service fails after about 180 s, `time-sync.target` is reached and the service starts on the unsynchronized clock (record that clock; this is the documented residual case). Record how long each start waited and the wait service's start limit (`systemctl cat <wait service>`); with a drop-in that changes the bound, confirm the service starts after the new bound. During a boot that is still waiting, run an `update`: record whether the installer's restart times out, confirm the pointers and unit are restored and the installer reports failure, and that the queued `server-sentinel.service` start job (`systemctl list-jobs`) later starts the restored release once the wait ends; then confirm that waiting until `systemctl is-active time-sync.target` is `active` and no job is queued before running the installer avoids it. Finally roll back to a release installed before this change and confirm the installer warns that the active unit is not ordered after `time-sync.target`;
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
- [ ] collector: confirm the real Codex (and, if enabled, Claude) bot user ID/login/type on a synthetic test PR; confirm the configured pass/blocking/suggestion markers against real review bodies and inline comments; measure provider review duration against `max_review_runtime_seconds`; confirm review IDs increase over time;
- [ ] collector: a same-repository workflow posting a PR review with the identical body through `GITHUB_TOKEN` is ignored as untrusted; a base update after the request invalidates it; a review finished before the runtime bound after a base update is not counted;
- [ ] collector recovery: on a synthetic test PR, post a success then a superseding failure for the same check on the test-merge SHA and confirm `GET .../commits/{sha}/check-runs?check_name=...&app_id=...&filter=all` lists both, that the later run has the higher ID, and that a restarted publisher with a stale `success` ledger record posts a new success instead of reusing it;
- [ ] token exchange (only after the Owner RS256 decision): the exchanged token is limited to this repository and the four fixed permissions, refreshes before expiry, and never appears in the publisher's journal, process environment or process arguments (`/proc/<pid>/environ`, `/proc/<pid>/cmdline`);
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
- Hostname reservation check module (`server/app/auth/reservation.py`, Issue
  #10 slice S1): its tests use synthetic `/proc/net/{tcp,tcp6,udp,udp6}` text and
  synthetic Serve status JSON only. The real `tailscale serve status --json`
  output format is **unverified**; the parser assumes a `TCP` / `Web` /
  `AllowFunnel` shape and fails closed on anything else. On the installed
  Tailscale version, capture the sanitized output for: no Serve config, the
  single expected mapping, an extra path, an extra HTTPS port, a plain HTTP
  mapping, a raw TCP forward, Funnel, and a foreground `tailscale serve`
  session; confirm each is parsed as expected or fails closed rather than
  passing. Record whether empty config prints `{}`, nothing, or text, and
  whether reading status needs anything beyond local operator access (it must
  not need ACL/Grants changes or admin credentials).
- Production composition (`human_access` deployment key, Issue #10;
  `server/docs/DEPLOYMENT.md`, "Enabling human access through Tailscale
  Serve"): its tests use synthetic enumerators, a synthetic Web build and
  generated stand-in executables only; nothing below is verified yet. As the
  service account, run `env -i <tailscale_executable> serve status --json`
  and record whether it succeeds without any environment, how long it takes
  and its size (the runner allows 5 seconds and 1 MiB). With
  `"isolation": "dedicated_network_identity"`, run it inside the dedicated
  VM/container against that environment's own `tailscaled` and confirm the
  backend's `/proc/net` and sock_diag view is that environment's namespace.
  Restart the service with the key and confirm the startup check opens access
  only with the expected single Serve mapping, and that `"isolation": null`,
  a missing Serve mapping, an extra path or port, or a stopped `tailscaled`
  keeps it closed (generic denial on the shell `/`) and sends one
  `human_access_fault` notification, and that a missing or group-writable
  `tailscale_executable` (Issue #283) lets the release's check pass with the
  warning `human access stays closed (reason=executable)` on stderr, and the
  service start and keep recording with every human path closed, log
  `human_access_composition_failed`, send one `human_access_fault`
  notification and report `human_access_degraded`. Make the composition itself
  fail at start (for example a session-binding key that is not the service
  account's own) and confirm the service keeps running and recording with
  every human path closed, logs `human_access_composition_failed`, sends one
  `human_access_fault` notification and reports `human_access_degraded`
  until the cause is fixed and the service restarted.
- On the target host, compare the parsed `/proc/net/tcp` and `/proc/net/tcp6`
  listeners with `ss -ltnH`, and the parsed `/proc/net/udp` and
  `/proc/net/udp6` unconnected sockets with `ss -lunH`, for IPv4, IPv6,
  wildcard and IPv4-mapped binds,
  and record whether Tailscale Serve holds a visible socket on the Tailscale
  address (which decides the recorded proxy sockets). Run the check in the
  network namespace that holds the reserved address when the dedicated
  network identity isolation is used. A wildcard `sshd` or other system
  service on the node is reported as an unexpected listener unless the Owner
  adds a listener exception for that port. With a wildcard `sshd` on 22:
  confirm access closes with no exception; add `tcp/22` created by unit
  `ssh.socket` (or `ssh.service`) with uid 0 through the audited
  Owner path and confirm access opens and a `change_security_setting` audit
  record exists; bind a test listener to the Tailscale address on port 22
  (not wildcard) and confirm access still closes; start a wildcard listener
  on another port and confirm access closes; attempt the change as a non-Owner
  and confirm a `denied` record and no change; restart and confirm the
  persisted exception is loaded before the first check and access opens;
  corrupt the stored `application_metadata` value on a disposable copy and
  confirm startup uses no exceptions (access closed) and the Owner receives
  a `LISTENER_EXCEPTIONS_UNREADABLE` fault, also when no wildcard listener is
  present, and that access stays closed until the value is repaired. Start a
  second `SO_REUSEPORT` listener on the loopback human upstream port and
  confirm `ss -ltn` shows two rows and access closes with
  `UNEXPECTED_LISTENER`; likewise start a second `SO_REUSEPORT` wildcard
  listener on the excepted port 22 and confirm access closes. Record which wildcard UDP sockets
  the node holds (for example `tailscaled`'s WireGuard port): confirm each
  closes access until the Owner adds a `udp` exception for that port, that a
  `tcp` exception on the same port does not cover it, and that a UDP socket
  bound to the Tailscale address on 443 (for example a test QUIC server)
  closes access. Confirm on the host whether its `::` listeners are dual-stack
  (`net.ipv6.bindv6only`, per-socket `IPV6_V6ONLY`); the check assumes they
  are and needs an exception without a family for them.
- `tailscaled` peerAPI reserved-address exception (Owner decision D1,
  2026-10-16; ADR-0003; synthetic tests only so far, not run on any host).
  On the node whose Tailscale name is the reserved name:
  - [ ] list the TCP listeners on the Tailscale addresses (`sudo ss -ltnp
    --cgroup`) and confirm each row other than the Serve socket on the
    dashboard port is created in `/system.slice/tailscaled.service` by uid 0
    and is the peerAPI (`tailscaled` debug output or upstream documentation
    for the installed version), and record its port per address family;
  - [ ] from another Tailscale node, request `http://<address>:<port>/` and
    `https://<reserved name>:<port>/` and record that the port answers plain
    HTTP only (no TLS handshake);
  - [ ] with a dashboard session established in a browser, open
    `http://<reserved name>:<port>/` in the same browser and confirm in the
    browser's network panel that the request carries no `__Host-session`
    cookie (the cookie is `Secure`); record the browser and version;
  - [ ] record whether the IPv4 and IPv6 rows use the same port (one
    exception without a family) or different ports (one `ipv4` and one
    `ipv6` exception), and that each family has exactly one `tailscaled`
    port besides the Serve socket: the command refuses a second
    `reserved_address` exception for a family (Issue #278);
  - [ ] record the port per family before and after `sudo systemctl restart
    tailscaled`, after `tailscale down` followed by `tailscale up`, and after
    a reboot: whether it stays the same decides whether the recorded
    exception survives restarts or a follow-up Owner decision is needed (a
    port that changes every time would revoke every human session on every
    restart). The belief that the port is derived from a hash of the
    Tailscale address and moves to another candidate when that one is in use
    is unverified recollection, not a documented guarantee; record what the
    installed version actually does;
  - [ ] confirm the port serves no page or script whose content another
    node or a user chooses (ADR-0003 same-site assumption): record the
    response to `/` and an unknown path from another Tailscale node;
  - [ ] without the exception, confirm access closes with
    `UNEXPECTED_LISTENER`; record the `reserved_address` exception for the
    observed port(s) with `app.auth.reservation_cli set`, restart the
    service and confirm access opens;
    confirm a test TCP listener on the same address and another port, and
    one on the recorded port started by another unit after `tailscaled` is
    stopped, each close access; on a disposable node, add a Serve HTTPS
    listener on another port and confirm access closes with
    `UNEXPECTED_ROUTE`, plus `UNEXPECTED_LISTENER` when `ss` shows a socket
    for it (record which).
- Local listener-exception command (`app.auth.reservation_cli`, Owner
  decision D3, 2026-10-16; synthetic tests only so far, not run on any host):
  - [ ] as the service account over SSH, `show` prints the stored set (or
    `no listener exceptions`) and nothing else; `set` with the host's
    exceptions shows the stored and new sets, asks for `CHANGE`, and adds one
    `change_security_setting` audit record (actor `owner`) holding no port,
    unit or address;
  - [ ] the running service keeps its startup set until
    `systemctl restart server-sentinel.service`; after the restart the new
    set is in force (a removed exception closes access);
  - [ ] run as root, as another account, without a controlling terminal
    (`systemd-run`, `cron`), with a dashboard or upstream port, and with a
    `reserved_address` exception for another unit: each refuses and changes
    nothing;
  - [ ] with the deployment's real `human_access` section, an exception for
    its `port` or for `human_port` is refused; with the section removed
    from a copy of the configuration, `set` refuses with
    `human_access_not_configured` and no refusal prints a hostname,
    address, unit or port.
- Breach recovery (Owner decision 2026-09-30): with an Owner and an invited
  viewer signed in, bind a test listener to the Tailscale address on another
  port, wait for the check to close access, then stop it. Confirm access
  reopens only after a `system` `invalidate_human_sessions` audit record
  exists, that both earlier sessions are refused and each person must sign in
  again with their passkey, and that a pending invitation must be reissued.
  Repeat with the listener removed and the service restarted before the next
  check: startup must revoke before opening. Make the database read-only on a
  disposable copy and confirm access stays closed with a
  `SESSION_REVOCATION_FAILED` Owner fault. Stop `tailscaled` briefly and
  record that the enumeration failure also forces everyone to sign in again.
  Make only the marker write fail (for example a disposable copy whose
  `application_metadata` row is locked by another writer) while the test
  listener is up: confirm the `invalidate_human_sessions` record is committed
  at once, so a restart after removing the listener cannot reopen with an
  earlier session.
- Access-fault Owner notification (Issue #232 item 4; pending the production
  composition that passes `AccessFaultMonitor` to the check and ceremonies,
  so mock-verified only): with Slack configured to the Owner's own test
  channel, cause one breach close as above and confirm exactly one
  `ServerSentinel critical alert: human_access_fault` within one monitoring
  tick, none for the following retries with the same reason, and one
  `ServerSentinel recovery notice: human_access_recovered` after access
  reopens. Confirm neither message nor the `notification_events` row contains
  the hostname, an address, a viewer identity or a reason, and that the
  monitoring status shows `human_access_degraded` only during the fault.
  Hourly budget across a restart (Issue #281 item 2, Issue #287; mock-verified
  only), on a disposable copy of the database, never the production one:
  after the update, confirm with `sqlite3` that `notification_events` has the
  `accepted_at` column and that rows written before the update kept every
  value with `accepted_at` empty. Cause four access notifications within an
  hour, restart the service and cause a fifth: confirm it arrives only once
  the oldest of the four is an hour old (counted from each row's
  `accepted_at`), never earlier and not more than an hour after the restart.
  Repeat with the state mount unavailable at start (monitoring `failed`) and
  one notification sent before the mount returns: after it returns, the
  earlier rows of the hour still count and that notification counts once.
- Listener owners through sock_diag (Issue #126, Owner decision 2026-10-07;
  mock and unprivileged local experiments only so far, not yet run on the
  Main Server). Production check procedure, all as the ServerSentinel service
  account unless `sudo` is shown, with a console or second session open:
  1. Service requirements: `systemctl show server-sentinel.service -p
     RestrictAddressFamilies -p PrivateNetwork -p ProtectControlGroups -p
     NetworkNamespacePath` shows `AF_NETLINK` allowed, `PrivateNetwork=no`, no
     namespace path, and `ProtectControlGroups=yes` (not `private`/`strict`).
     `cat /proc/<service pid>/cgroup` is `0::/system.slice/server-sentinel.service`
     and `readlink /proc/<service pid>/ns/net` equals `readlink /proc/1/ns/net`
     (read as root).
  2. Unprivileged lookup, as the service account (`<root>` is the
     installation root):

     ```sh
     cd / && sudo -u <service account> <root>/current/venv/bin/python -I -c '
     import sys; sys.path.insert(0, "<root>/current")
     from app.auth.sock_diag import NetlinkSockDiag, cgroup_paths
     paths = cgroup_paths()
     for s in NetlinkSockDiag().dump():
         print(s.family, s.protocol, s.inode, s.uid, paths.get(s.cgroup_id))'
     ```

     Record that the tcp/22 sockets resolve to `/system.slice/ssh.socket` uid
     0, `tailscaled`'s sockets to `/system.slice/tailscaled.service` uid 0,
     and the upstream port to `/system.slice/server-sentinel-upstream.socket`
     uid 0; compare the inodes with `sudo ss -ltnpe` / `sudo ss -lunpe`.
     Record whether the UDP tables needed the `udp_diag` module and whether it
     was already loaded (`lsmod | grep diag`). This runs outside the unit
     sandbox; step 1 covers the unit's restrictions.
  3. Upstream activation: follow the `server/docs/DEPLOYMENT.md` socket
     activation steps; confirm `/proc/sys/net/ipv4/ip_unprivileged_port_start`
     is greater than the port, `ss -ltne 'sport = :<port>'` shows one row whose
     inode is in `/proc/<service pid>/fd`, the backend runs without
     capabilities (`grep Cap /proc/<service pid>/status` all zero), and access
     opens with the `tcp/22` `ssh.socket` (uid 0) exception entered with
     `app.auth.reservation_cli set` and a service restart.
  4. Mismatching listener → revoke: on a disposable node or during a
     maintenance window, with an Owner and an invited viewer signed in, stop
     `ssh.socket` and `ssh.service`, start a wildcard listener on 22 from a
     login session (for example `sudo python3 -m http.server 22`; it is
     created in the session's `user.slice` scope), and confirm the check
     closes access with `UNEXPECTED_LISTENER` (the second dump confirmed it),
     that reopening after restoring `ssh.socket` revokes every human session
     with a `system` `invalidate_human_sessions` audit record, and that a
     `user.slice` process whose cgroup ends in `ssh.socket` does not satisfy
     the exception. Repeat on the upstream port with the backend stopped
     (`sudo python3 -m http.server --bind 127.0.0.1 <port>`) only if a
     disposable node is available.
  5. Netlink denied → close only: with a drop-in that removes `AF_NETLINK`
     from `RestrictAddressFamilies=` (or `ProtectControlGroups=private` on
     systemd 257+), restart the service and confirm human access stays closed
     with `LISTENER_OWNER_UNVERIFIED` only, the Owner fault arrives, no
     `invalidate_human_sessions` record is written and existing sessions stay
     valid after the drop-in is removed and access reopens.
  6. Unprivileged port: on a disposable node lower
     `net.ipv4.ip_unprivileged_port_start` below the upstream port and confirm
     `LISTENER_OWNER_UNVERIFIED` without revocation; restore it.
  7. Outdated exceptions: on a disposable copy holding a version 1 (port-only)
     or version 2 (executable path, or unit without uid) stored exception,
     confirm startup reports `LISTENER_EXCEPTIONS_OUTDATED` and access stays
     closed until the Owner re-enters the exception with unit and uid.
  8. Residual risk (not detectable, record only): sock_diag reports the
     creator, not the holder; a socket passed to another process with
     `SCM_RIGHTS` outside the ServerSentinel unit keeps its creator's cgroup.
  9. cgroup-BPF prerequisite (Issue #157): record that
     `sudo ss -ltn --cgroup 'sport = :<upstream port>'` shows
     `cgroup:/system.slice/server-sentinel-upstream.socket` (not
     `/init.scope`). Only on a host or VM without cgroup-BPF support (never
     the production Main Server), confirm startup reports
     `UPSTREAM_CREATED_IN_INIT_SCOPE`, human access stays closed and no
     `invalidate_human_sessions` record is written (mock-only so far).
  10. Slow `exec` (Issue #160, mock and same-host loopback only so far): on a
      disposable node under heavy load, confirm that children the backend
      spawns never produce `UNEXPECTED_LISTENER` for the upstream; a child
      that has exec'd by the third scan (about 200 ms) stays unverified
      (closed without revocation) until the next check. Record any
      `UNEXPECTED_LISTENER` from a child that took longer, for the Owner.
- Kernel forwarding (not covered by the check): on the Main Server, run
  `sudo nft list ruleset` and `sudo iptables-save -t nat` (and `-t mangle`),
  and confirm no DNAT, REDIRECT or TPROXY rule targets the reserved addresses
  or their ports; record Docker's `userland-proxy` setting, any `sk_lookup`
  BPF programs (`sudo bpftool prog show`) and IPVS services
  (`sudo ipvsadm -Ln`, if installed). Any such forwarding is outside what the
  check can see and must be removed or excluded by the deployment isolation.
- Unit identity: confirm the tcp/22 sockets' sock_diag cgroup is exactly
  `/system.slice/ssh.socket` (step 2 above), and that a user-session process
  whose cgroup ends in `ssh.socket` under `user.slice` does not satisfy a unit
  exception.
- Human upstream ownership (mock-only so far): with the check composed in the
  running service and socket activation in place, confirm access opens and
  that the upstream's inode in `ss -ltne 'sport = :<port>'` appears in
  `/proc/<service pid>/fd` and nowhere else in the unit's processes
  (`cat /sys/fs/cgroup/system.slice/server-sentinel.service/cgroup.procs`).
  On a disposable node, stop the upstream only (keep the check running), bind
  another process to the same loopback address and port (one socket, no
  `SO_REUSEPORT`), and confirm `UNEXPECTED_LISTENER` closes access and that
  reopening revokes every human session. Start the backend without the
  socket unit on a port at or above `ip_unprivileged_port_start` and confirm
  `LISTENER_OWNER_UNVERIFIED` without revocation.
- Proxy socket ownership (mock-only so far): record whether `tailscaled`
  holds a visible socket on the Tailscale address at the origin port (`sudo ss
  -ltnp`); if it does, record its sock_diag cgroup and uid (step 2 above, for
  example `tailscaled.service` uid 0) as `proxy_owner`. Confirm access opens, then (on a disposable node) stop the proxy,
  bind another process to the same address and port while Serve status still
  lists the route, and confirm `UNEXPECTED_LISTENER` closes access and that
  reopening revokes every human session. Stop the proxy without a replacement
  and confirm `PROXY_LISTENER_MISSING` closes access and that it reopens
  without revocation once the proxy is back.
- Hostname resolution (mock-only so far): with the production
  `GetaddrinfoResolver` composed, confirm on the host that it returns exactly
  the reserved name's Tailscale IPv4 and IPv6 addresses (compare with
  `getent ahosts <reserved-host>`) and that access opens. Record whether
  MagicDNS answers both families. Stop `tailscaled` (or point the resolver at a
  non-answering server) and confirm access closes with
  `HOSTNAME_RESOLUTION_UNAVAILABLE`/`_TIMEOUT`, and that once resolution
  recovers access reopens with no `invalidate_human_sessions` record and
  existing sessions still accepted (Owner decision 2026-10-01: a resolution
  failure is not an exposure). If `tailscaled` stopping also makes the listener
  or route enumeration fail, that failure still revokes; record which reasons
  the host actually produced. Omit one configured address and confirm
  `RESERVED_ADDRESSES_CHANGED` closes access until the configuration matches
  and that reopening then revokes every human session;
  on a disposable node whose name gains an extra address (for example a test
  `/etc/hosts` entry when the resolver honors it), bind a listener to that
  address and confirm it is reported as `UNEXPECTED_LISTENER`.
- Once the check is composed into startup and the daily worker, confirm an
  enumeration failure or timeout (for example stopping `tailscaled`, or making
  `/proc/net` unreadable) keeps human access closed and notifies the Owner,
  and that a later violation closes access that was previously open.
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
