# 2026-10-22: Main の録画 codec / container / muxer / validator の調査（D13）

- Status: **Owner 判断を記録済み（2026-10-22）**。判断の内容は §0 にあります。§1〜§10 の比較は、判断の背景として残しています。実機で測る必要がある項目（同期 I/O、CPU / GPU、bitrate の上限、browser の挙動など）は、§0 と §13 に「実機で測る」と明記しており、その値はまだ決まっていません。
- Date: 2026-10-22
- Related: Issue #313（本調査の Issue）、#10 Phase 2 の D13 と S9、#17、#18、#19、#21、#23、#26、#47、#28、#15 / ADR-0007、#16
- Scope: 文書だけです。runtime の依存、lock、`license/components.json` / `license/owner-approvals.json` の記録、code は追加しません。
- 実測について: **この文書のために新しく測った値はありません**。数値は、既存の記録（`MANUAL_TEST.md`、`docs/decisions/2026-10-11-mjpg-decoder-survey.md`）から引用するか、明記した仮定から計算した **推定** です。Main host と capture host は本番環境なので、この調査ではカメラにも稼働中のサービスにも触れていません。Main host で行ったのは、読み取りだけの `gst-inspect-1.0` と `dpkg -l` による package の確認だけです。

## 0. Owner 判断（2026-10-22）

Owner は 2026-10-22 に、§12 の問いについて次のとおり決めました。

| 問い | 判断 |
| --- | --- |
| Q1 保存の codec | **H.264** で保存する。 |
| Q2（D13）container と再生 | **fragmented MP4** で保存し、**そのまま browser へ配る**（MSE / HLS(fMP4)。§6 の P3）。録画の一覧・再生・playlist・segment は、server 側で `recordings:view` を確認してから返す。download / export は提供しない。 |
| Q3 encoder | **GStreamer の nvcodec（NVENC）**。 |
| Q4 NVENC が無い・失敗したとき | **MJPEG の保存に fallback する**。そのとき録画を **degraded** にし、**Owner に通知する**。黙って fallback しない。segment は `codec` / `container` を持つので、形式の混在は manifest で区別できる。 |
| Q5 validator | **全 frame の decode による検証を必須**とする。録画の検証専用の子プロセスで行い、ROI 用の子プロセスとは分ける。CPU の割り当ては、実機で測ってから決める。 |
| Q6 self-test | **実 pipeline の sample** を使う（capture → packet adapter → muxer → validator）。既存の `.selftest` の契約に従って扱う。 |
| Q7 容量と上限 | recording root は **HDD**。segment の長さは、実機で同期 I/O の負荷を測ってから決める。§8.6 の上限は、H.264 と MJPEG の fallback のそれぞれについて、negotiated bound から計算し直す。 |
| Q8 AVC の特許 | 研究室内での使用として、**Owner の責任で受け入れる**。 |

**MEDIA-003 / SPEC §6.2 との関係**: MEDIA-003 は「source の codec / profile が suitable なら stream copy を優先し、そうでなければ（Otherwise）encode する」としています。MJPEG は browser の `<video>` で再生できないので（§4 A）、browser で再生するという用途には suitable ではありません。そのため H.264 への transcode は、MEDIA-003 の「Otherwise」に当たります。また、NVENC が無い・失敗したときは MJPEG の保存に fallback するので（Q4）、録画の correctness は GPU に依存しません（SPEC §6.2 の「Do not require a specific GPU vendor for correctness」）。

この判断により、§4 の B（software encode。x264 / OpenH264）、§7 の V3（FFmpeg の CLI）と V4（PyAV）、§6 の P1 / P2 を主な経路とする案は、採用しません。§11 の推奨（MJPEG で保存し、P1 で再生する案）は、判断の前の提案として残しています。

### 0.1 判断を受けて残る技術的な問い（実装の前に決める）

- **T1: H.264 の validator に使う decoder**。全 frame の decode を、閉じ込めた子プロセスで行う必要があります（Q5）。候補は次のとおりで、**まだ決まっていません**。
  - `nvh264dec`（gst-plugins-bad の nvcodec。encoder と同じ plugin です。gst-plugins-bad は LGPL です（採用のときに COPYING で確認します））。子プロセスに `/dev/nvidia*` と CUDA の library への access を許す必要があり、Landlock / seccomp の閉じ込めが ROI の子プロセスより広くなります。また、encode と同じ GPU と driver で decode するので、GPU や driver の不具合が encode 側と検証側の両方に同時に出ると、検証で見逃すおそれがあります。
  - `avdec_h264`（gst-libav。FFmpeg の H.264 decoder を CPU で使います）。FFmpeg は既定の build なら LGPL-2.1-or-later ですが、`--enable-gpl` で build すると GPL になります [FFmpeg-legal]。distribution package の build 構成を監査する必要があります。Main host には入っていません。GPU から独立して検証でき、閉じ込めの範囲も狭くできます。CPU 負荷は測っていません。
  - `openh264dec`（gst-plugins-bad）。OpenH264 の特許 license は、Cisco が配布する binary に限られます（§4 B）。Q8 で特許は Owner の責任で受け入れましたが、binary の入手方法と表示の条件は別に確認が要ります。
  - MJPEG の fallback の segment は、これまでどおり simplejpeg で検証します。
- **T2: fMP4 の muxer**。Main host には `mp4mux` / `qtmux`（gst-plugins-good。`fragment-duration` を持ちます）があります。`isofmp4mux`（gst-plugins-rs）はありません。GStreamer の muxer を使うか、自前の stdlib の ISO BMFF writer を使うかは、まだ決まっていません。どちらの場合も、segment ごとに init（`ftyp` + `moov`）を持たせて、単独で decode できるようにします。
  - そのような自己完結した segment file を HLS(fMP4) でそのまま配るには、playlist で同じ file の中の範囲を指す必要があります。init 部分は `EXT-X-MAP` の `BYTERANGE` で、media 部分（`moof` + `mdat`）は `EXT-X-BYTERANGE` で指します [RFC8216]。そのため、認可付きの再生 route は **HTTP の byte-range request（`Range` / `206 Partial Content`）に対応する**必要があります。iOS も、media の server に byte-range への対応を求めています [Apple-byterange]。認可は、range ごとの request にも同じように掛けます。
- **T3: MJPEG の fallback の segment の container と再生**。MJPEG は `<video>` で再生できません（§4 A）。fallback の区間をどの container（Matroska `V_MJPEG` など）で保存し、browser でどう見せるか（frame pull、または「この区間は再生できない」と表示するか）を決める必要があります。
- **T4: bitrate の上限の強制**。§8.6 の上限は、negotiated bound（`VideoFormat.maximum_bitrate`）が実際に守られることを前提にしています。ただし、`VideoFormat.maximum_bitrate`（`server/app/media/profiles/model.py`）は**宣言されているだけで、今はどこでも強制されていません**（読んでいるのは synthetic の harness の fixture だけです）。
  - そのため、**H.264 でも MJPEG の fallback でも、segment ごとに byte 数の上限を強制します**。muxer か validator が、segment の byte 数を `B_s` × segment の長さ ÷ 8 × (1 + o) + `V_s` + `H` と比べ、超えた segment は拒否して gap にし、録画を degraded にします。黙って保存することはしません。
  - H.264 では、これに加えて NVENC の rate control（最大 bitrate と VBV buffer）で、上限を超えないようにします。rate control だけに頼ることはしません。
  - MJPEG は camera が bitrate を制御しないので、fallback で使う上限を設定で決めます（§8.6）。
- **T5: GStreamer の導入**。Main の runtime に、operator が導入する GStreamer（core、base、good、bad の nvcodec）を入れることになります。`agent/docs/DEPENDENCIES.md` の前例（絶対 path、root 所有の確認、使う plugin を限る、Landlock）に合わせた閉じ込めと、package の inventory の review が要ります。NVENC は `/dev/nvidia*` への access を必要とします。

### 0.2 実機で測ってから決めるもの

- HDD 上での append の遅延、fsync と SQLite の commit の時間（§8.4）。これを測ってから segment の長さを決めます。
- NVENC の encode と validator の decode の CPU / GPU / VRAM、遅延（§8.5）。
- H.264 の実際の bitrate と画質。これをもとに、NVENC の最大 bitrate（negotiated bound）を決めます。
- iPhone Safari での HLS(fMP4) / ManagedMediaSource の再生と、cookie による認可（§6、§13）。
- Firefox on Linux で H.264 を再生できるか。

## 1. 問題（main `833c492` 時点）

Main の durable recording には、保存層（`server/app/media/recording/`、#18）しかありません。

- production code から `RecordingStore.append()` を呼ぶ箇所がありません。#17 の `PacketAdapter`（`server/app/media/profiles/pipeline.py`）を `Segment` に変える muxer もありません。
- segment validator が注入されないとき、`MonitoringRuntime` は `RefuseUnvalidatedSegments` を使い、すべての segment を `SEGMENT_VALIDATOR_UNAVAILABLE` で拒否します（`server/app/monitoring/runtime.py`）。`recorder_probe_factory` も無いので、日次の recording-health self-test は `UNAVAILABLE` を返します（`server/app/monitoring/runtime.py` の `MonitoringDependencies` の docstring、`server/app/monitoring/README.md` の `UNAVAILABLE` → `recording_health_warning`）。
- codec / container / muxer / validator は、まだ何も選ばれていません。#10 Phase 2 の Owner 判断 **D13（再生の container）** は「#19 / #17 で決めます」として未決です。
- #18 は primitive だけで close されています。recording README にも「No production validator is shipped here」とあります。

このため、次の作業が止まっています。

| 止まっているもの | 待っている内容 |
| --- | --- |
| #21 / #10 S9 録画の browser 再生 | 「#19 の packaging、#17 の codec、本番の segment validator」（#10 Phase 2 計画） |
| #23 日次 Recording Health | 実際の recording path での write → fsync → reopen → container / duration / size 検証 → decode（SPEC §10.3 の 5〜7） |
| #26 critical evidence | `server/app/presence/runtime.py` に「No evidence or notification port is configured here yet」とあります |
| #47 / #28 | recordings を保持したまま install / update / rollback できるかの確認と、実機での総合受入 |

## 2. 前提と制約（既存の要件から）

- **stream copy を優先する**: 「Prefer passthrough/stream-copy when source codec/profile is suitable」（REQUIREMENTS MEDIA-003）。SPEC §6.2 の優先順は 1. stream copy、2. hardware encode / decode、3. bounded な software encode です。「Do not require a specific GPU vendor for correctness. Hardware acceleration is optimization.」とも書かれています。
- **入力はすべて MJPG**:
  - `local_uvc`（Main の EMEET C960 × 2）は、Python の V4L2 MMAP で直接取り込み、transcode しません。
  - `remote_agent`（capture host の Yamaha CS-800）は `v4l2src ! image/jpeg ! fdsink` で取り込みます。capture host の GStreamer は base / good だけで、H.264 encoder がありません。
  - transport PoC（#15）が運ぶ unit も MJPEG frame です。
- **event 録画が中心**: 既定は 30 秒前 + 120 秒後、最大 20 分です。手動録画も最大 20 分です。pre-roll は compressed media で持ち、decoded frame の長い履歴は持ちません（MEDIA-008 / MEDIA-009、SPEC §6.7）。
- **保持と容量**: 録画の既定保持は 20 日です。hard safety reserve、`STORAGE_PRESSURE`、`STORAGE_HARD_STOP` があり、starred は自動削除しません（STORE-003〜006）。
- **再生**:
  - non-owner の録画アクセスは browser 再生だけです。download / export は提供しません（AUTH-007、SECURITY「Recording playback」）。
  - viewer は phone / Mac / desktop の browser で、iPhone Safari も含みます。
  - playback の segment / manifest にも認可が必要です。URL をコピーしただけでは再生できないようにします。
- **video だけ**: audio track を作らず、受け入れもしません（REQUIREMENTS 冒頭の video-only 要件）。
- **依存の license**: Apache-2.0 / MIT / BSD を推奨します。GPL（結合した成果物に義務が及ぶもの）や、ライセンスが曖昧なものは、Owner の承認がない限り使えません（`docs/THIRD_PARTY_POLICY.md`、AGENTS §13）。
- **保存層の契約**（recording README）:
  - `Segment` は「independently decodable」な、muxer 済みの video です。
  - `SegmentValidator` は、video だけであること、許可した形式と設定、decode する寸法の上限、単独で decode できることを、保存の前に確認します。
  - `codec` / `container` の識別子は `[a-z0-9][a-z0-9_.-]{0,31}` です。
  - 書き込みは `.part` → fsync → 名前の publish → directory fsync → ready の順に進む journal です。

### 2.1 保存層がすでに crash safety を持っていること

`RecordingStore` は、**segment 単位**で crash safety を持っています。segment は 1 file として丸ごと書き、fsync し、atomic に publish します。restart のときは、journal にある pending だけを片付けます。このため container には「途中まで追記した 1 本の長い file を crash 後も読めるようにする」性質（例: 非 fragment の MP4 で robust muxing を使う、など）は要りません。要るのは次の 2 点です。

1. 各 segment file が **単独で完結して decode できる**こと（container の header と codec の初期化情報を自分で持っていること）。
2. muxer が memory に持つ未完成の segment が、**`max_segment_ms` / `max_segment_bytes` で上限を持つ**こと（crash で失うのは、最大 1 segment 分の時間です）。

container の「crash-safe append」の比較（§5）は、この前提で評価しています。

## 3. 入力の実測値（既存記録からの引用）

| 出典 | profile | 平均 frame | 帯域 / source |
| --- | --- | --- | --- |
| `MANUAL_TEST.md`「Main Server 上の local UVC capture resource」2026-09-30 | C960 MJPG 1920x1080@30 | 150–166 KiB | 36.8–40.7 Mbps |
| 同上 | C960 MJPG 1280x720@30 | 100–103 KiB | 24.5–25.3 Mbps |
| 同上 | C960 MJPG 640x480@30 | 50–53 KiB | 12.3–13.0 Mbps |
| `MANUAL_TEST.md`「LAN baseline」2026-09-30 | 観測した camera の MJPEG | — | 約 60 Mbps（1080p30）、約 30 Mbps（720p30） |
| `MANUAL_TEST.md` 低照度の観測（lens を覆う） | C960 1080p、実配信 16〜17 fps | 約 150 → 220 KiB に増加 | 実測の条件（16〜17 fps × 約 220 KiB）では約 29〜31 Mbps |
| 2026-10-22 の capture host 計測（#305） | CS-800 MJPG 1280x720@30 | 約 125 KB | （計算すると約 30 Mbps） |

暗い場面や noise の多い場面では、MJPEG の frame は大きくなります。ただし C960 の低照度の観測では fps も 16〜17 に下がったので、帯域は実測の条件では約 30 Mbps でした。**仮定**として、220 KiB の frame のまま 30 fps を保つ camera があれば約 54 Mbps になります（この組み合わせは観測していません）。以下の見積もりでは、1080p30 の MJPEG を代表値 40.7 Mbps（Main の local capture の実測）、上振れ値 60 Mbps としました。60 Mbps の根拠は、LAN baseline の「約 60 Mbps（1080p30）」という観測だけです。

## 4. codec の選択肢

### A. MJPEG をそのまま stream copy する（transcode しない）

- 処理: camera の JPEG frame を、そのまま container に入れます。MJPEG では frame がそれぞれ独立に decode できるので、segment の境界はどの frame にも置けます。keyframe を待つ必要もありません。
- 新しい codec の依存: **ありません**。integrity の検証には、Owner が採用を承認した simplejpeg（libjpeg-turbo）を使えます。既存の ROI 用の分離子プロセス（Landlock + seccomp、#269）と同じ方式を基に、検証用の protocol を足す形になります（§7、§9）。
- 特許: AVC の pool（Via LA）の対象外です。
- GPU: 要りません。SPEC §6.2 の「特定の GPU vendor を correctness の条件にしない」に、そのまま合います。
- **欠点**:
  1. **browser の `<video>` で再生できません**。MDN の video codec guide の一覧（AV1、AVC、H.263、HEVC、MP4V-ES、MPEG-1、MPEG-2、Theora、VP8、VP9）に Motion JPEG は入っていません [MDN-codecs]。再生には、別の方式が要ります（§6 の P1 / P2）。
  2. **容量が大きくなります**。H.264 と比べて、桁が変わるほどの差です（§8）。
  3. pre-roll spool は disk 上に常に書き続けるので、SSD / NVMe の書き込み量も大きくなります（§8.3）。

### B. H.264 に software で encode する

- 処理: MJPEG を decode し、YUV に直して H.264 に encode します。decode した frame は encoder に渡すまでの短い間だけ持つので、MEDIA-009 の「decoded frame history を持たない」に反しません。
- 候補の encoder:
  - **x264**: GPL です（商用 license も別にあります）[x264]。FFmpeg も、libx264 を使うと「the GPL applies to all of FFmpeg」になります [FFmpeg-legal]。GStreamer の `x264enc` は gst-plugins-ugly にあります。ugly は、plug-in や支えとなる library の license、あるいは広く知られた特許の問題のために、配布に問題が生じうる module だと説明されています [GStreamer-modules]。**THIRD_PARTY_POLICY の「GPL where obligations may affect the combined distributed work」に当たり、Owner の承認が要ります**。
  - **OpenH264**: source は BSD-2-Clause です。ただし AVC の特許 license が及ぶのは、**Cisco が配布した binary** で、次の条件をすべて満たす場合だけです [OpenH264-binary]。
    - 第三者のソフトウェアと統合・結合する前の状態で、end user の端末へ別に download されること
    - user が有効・無効を切り替えられること
    - 「OpenH264 Video Codec provided by Cisco Systems, Inc.」と表示すること
    - EULA 等に条項を再掲すること
    - 対象は「PERSONAL USE OF A CONSUMER OR OTHER USES IN WHICH IT DOES NOT RECEIVE REMUNERATION」に限られ、「NO LICENSE IS GRANTED OR SHALL BE IMPLIED FOR ANY OTHER USE」とされています
    - この特許 license の対象は、Cisco が配布する binary だけです。source から build したもの、distribution の package、同梱したものは、この license の対象になりません。同じ文書は、AVC / H.264 の codec 全般について（「As with all AVC/H.264 codecs」）、「you may also obtain your own patent license from MPEG LA or from the individual patent owners, or proceed at your own risk」と一般的に述べています。
- 特許: H.264 は Via LA の AVC pool の対象です。encoder / decoder product は年 100,000 unit までが $0.00 で、12 分以下の title は content fee が $0.00 です。ただし「The actual License agreement provides the only definitive ... statement」とされています [ViaLA-AVC]。self-hosted で配布もしない研究室の deployment にこれがどう当てはまるかは、**この調査では判断できません**（法務判断が必要です）。
- CPU: **測っていません**。1080p30 を realtime で encode すると、MJPEG の decode（下の §8.5）に加えて、source ごとに数 core 規模を使う可能性があります。これは仮定であり、根拠はありません。Main host では別の session が GPU benchmark を回しているので、CPU 負荷の測定は CPU を制限した container で行う必要があります（運用上の制約）。
- 利点: 容量が小さく、H.264 + MP4 は「a broadly-supported combination—by every major browser」です [MDN-codecs]。ただし Firefox の H.264 は、OS 側にある codec に依存します [MDN-codecs]。Linux desktop の Firefox で再生できるかは、実機で確かめる必要があります。

### C. H.264 に NVENC（NVIDIA hardware）で encode する

- Main host の GPU は RTX PRO 6000 Blackwell Workstation Edition です。NVIDIA の support matrix によると、**NVENC は 4 基、同時 session 数は Unrestricted** で、H.264 / HEVC / AV1 の encode に対応します [NVIDIA-matrix]。GeForce の上限 12 session は当てはまりません。
- Main host の現状（2026-10-22、`dpkg -l` / `gst-inspect-1.0` で読み取りだけ確認）:
  - NVIDIA driver の `libnvidia-encode-595` は入っています。
  - GStreamer 1.28.2 は base / good だけで、**`nvh264enc`（gst-plugins-bad の nvcodec）、`x264enc`、`openh264enc`、`avdec_h264`、FFmpeg は入っていません**。
  - 採用するには、gst-plugins-bad（nvcodec）か、NVENC を有効にした FFmpeg を、operator が導入する必要があります。
- license:
  - gst-plugins-bad は LGPL です（upstream の COPYING。pinning のときに再確認します）。
  - NVENC の runtime は NVIDIA の proprietary driver library です。onnxruntime-gpu を評価したときの扱い（`docs/decisions/2026-09-30-yolox-person-evaluation.md`）と同じく、repository の lock や allowlist には入れず、operator が導入する前提になります。
  - AVC の特許については B と同じです。
- 相反する点: SPEC §6.2 は GPU を correctness の条件にしません。C だけを採用すると、GPU や driver が無い、または失敗したときに録画が `adapter_unavailable` になります。software の fallback（B）を持つか、A に fallback するかを決める必要があります。`AdapterSelector` の `prefer_hardware` / `require_hardware` は、どちらの方針も表せます。
- GPU の共有: 同じ GPU で、別の session の benchmark や推論（#20）が動きます。NVENC は専用の回路ですが、MJPEG の decode（CPU、または `nvjpegdec`）、色変換、upload には、CPU や GPU の資源を使います。**測っていません**。

### D. VA-API

NVIDIA で VA-API を使う `nvidia-vaapi-driver` は「Hardware decoding only, encoding is not supported」です [nvidia-vaapi]。Main host には Intel / AMD の GPU が無いので、**この host では encode の候補になりません**。別の host に deploy するときの、汎用の hardware 経路としてだけ残ります。

### E. その他（HEVC / AV1）

MDN によると、HEVC は browser と OS によって対応がまちまちです。Chrome は hardware がある場合に限られ、Firefox は platform ごとに異なります [MDN-codecs]。AV1 は「supported in all browsers」ですが、Safari では hardware decoder がある端末（M3 以降、iPhone 15 Pro、iPhone 16 以降など）に限られます [MDN-codecs]。viewer の iPhone は機種を選べないので、**主な形式の候補には入れません**。NVENC は両方とも encode できるので、将来の容量削減の選択肢として残します。

### F. 混合: 保存は MJPEG（A）、再生のときに変換する

A で保存し、再生の要求が来たときだけ H.264 に変換します（§6 P2）。viewer がいないときは処理を止めるので、MEDIA-005 / SPEC §6.5 の demand-driven の考え方に合います。保存には新しい依存が要りませんが、再生には B か C の依存が要ります。

## 5. container の選択肢

§2.1 のとおり、segment を 1 file に閉じるので、「単独で decode できること」「parser を小さく保ち、検証できること」「再生への packaging のしやすさ」を重視して比べます。

| container | MJPEG を入れられるか | H.264 を入れられるか | browser 再生 | segment の自己完結性 | Main host の muxer | 備考 |
| --- | --- | --- | --- | --- | --- | --- |
| **fragmented MP4（ISO BMFF、init + `moof`/`mdat`）** | ISO BMFF に MJPEG を入れる一般的な方法は QuickTime の `jpeg` sample entry で、browser では再生できない | ○ | H.264 なら MSE / HLS（EXT-X-MAP）にそのまま使える。init segment は `ftyp`+`moov`（sample なし）、media segment は `moof`+`mdat` [W3C-MSE-ISOBMFF][RFC8216] | segment ごとに init を持たせれば完結する | `mp4mux` / `qtmux`（good）あり。`isofmp4mux`（gst-plugins-rs の fmp4）は無い | iPhone は native HLS か ManagedMediaSource（Safari 17.1 で iPhone に対応）[WebKit-17.1][MDN-MMS]。Safari の ManagedMediaSource は、AirPlay の代替 source（例: HLS の `<source>`）があるか、`disableRemotePlayback` を `true` にした場合にだけ有効になる [MDN-MMS] |
| 非 fragment の MP4 | 同上 | ○ | `<video src>` で progressive 再生（iOS は byte-range が必須 [Apple-byterange]） | `moov` が末尾に来るので、file を閉じるまで読めない。短い segment なら §2.1 で吸収できる | `mp4mux`。robust muxing（`reserved-moov-update-period`）で crash 後も読めるが、seekable な出力が必要 [GStreamer-qtmux] | 長い 1 file の追記には向かない |
| **Matroska（MKV）** | ○（`V_MJPEG`、初期化データなし）[Matroska-codecs] | ○（`V_MPEG4/ISO/AVC`） | MDN の web 向け container 一覧には WebM（Matroska の subset）しかなく、MKV は載っていない [MDN-containers]。browser 再生の前提にはできない | Cluster 単位で完結する。MJPEG なら header と frame だけで済む | `matroskamux` / `matroskademux`（good）あり | Owner が VLC / mpv などで local に確認するのに向く |
| MPEG-TS | 実質的に不可 | ○ | MDN の一覧に無い [MDN-containers]。Safari の HLS 以外では transmux（hls.js 等）が要る | packet 単位で頑丈 | `mpegtsmux`（bad）は無い | 188 byte の packet と PES の parser が増え、検証の面が大きくなる |
| 自前の frame index 形式（JPEG の連結 + timestamp 表） | ○ | — | 不可（再生は §6 P1 を使う） | 完結する | 不要（stdlib で書ける） | 外部の tool では読めない。形式の文書化と versioning が自前の責任になる |

**整理**: H.264 で保存し、**保存した segment をそのまま配る（§6 P3）場合は**、fragmented MP4 がほぼ唯一の選択肢です（D13 = fMP4、再生は HLS(fMP4) または MSE）。再生のときに packaging し直す前提なら、H.264 を Matroska 等で保存する余地もあります。ただしその場合は、再生のたびに remux が要ります。MJPEG で保存するなら、browser が読める container はありません。Matroska（`V_MJPEG`）か自前の形式になり、D13 は「保存の container」と「再生の packaging」に分かれます。

## 6. 再生の方式（S9、non-owner は browser 再生だけ）

- **P1: 保存した JPEG を、認可付きで frame ごとに取りに行く**（S7 の暫定 live と同じ方式。D10）
  - 新しい依存はなく、すべての browser で動きます。
  - 帯域は、そのまま MJPEG の bitrate です（1080p で 40〜60 Mbps / stream）。Tailscale 経由の phone では重くなります。間引き（低 fps での再生）で下げられます。
  - `<video>` の controls や seek はありません。seek は server 側の index で作ります。
  - download の button は作りませんが、frame は browser に届きます。これは AUTH-007 の「screen recording は防げない」と同じ扱いです。
- **P2: 要求が来たときに H.264 fMP4 へ変換する**（F）
  - HLS(fMP4) または MSE で `<video>` を使えます。
  - viewer の数に比例して、encoder の資源を使います（上限は #19 の viewer 制限に合わせます）。
  - 依存は B / C と同じです。開始までに変換の遅延があります（**測っていません**）。
- **P3: 保存している H.264 fMP4 をそのまま配る**（B / C で保存した場合）
  - 変換はいりません。認可付きの playlist / segment route と、iOS 向けの byte-range 対応が必要です [Apple-byterange]。
  - 認可済みの URL が漏れても再生できないこと（SECURITY）は、cookie による session 認可で守ります。native HLS player がすべての request に cookie を付けるかどうかは、**実機の Safari で確かめる必要があります**。

どの方式でも、次の 2 点は共通です。

- 録画の一覧、再生（P1 の frame、P2 / P3 の playlist と segment を含む）、録画に結び付いた historical timeline / event は、**server 側で `recordings:view` を確認して**から返します。`live:view` だけの principal には返しません（REQUIREMENTS の `recordings:view` の定義、AGENTS §9）。P1 は S7 の live と同じ取り出し方をしますが、認可は live の validator ではなく、録画の permission で行います。
- manifest の clip 区間（README「Whole compressed segments may overlap window boundaries」）を守るのは再生側の責任です。

## 7. muxer / demuxer / validator の実装と依存

| 案 | 内容 | license | sandbox / 分離 | 所見 |
| --- | --- | --- | --- | --- |
| **V1: 自前の stdlib muxer / parser + 既存の simplejpeg 分離子プロセス**（A 向け） | Matroska（`V_MJPEG`）の EBML writer と、**自分が書く subset だけ**を受け付ける parser を Python stdlib で書きます。JPEG の構造の pre-check は、既存の `server/app/detection/roi/mjpg.py`（SOF の寸法検査など）の規則を基にします。decode の確認は、ROI 用の simplejpeg 子プロセスと同じ方式で行います。ただし、検証用の protocol を足す必要があります（§9）。 | 自前のコードは Apache-2.0。simplejpeg は Owner 承認済み（`pypi:simplejpeg@1.9.0`、IJG を個別承認） | decode は Landlock + seccomp で閉じ込めた子プロセスで行います（#269 と同じ方式）。parser は Main 内の pure Python です。 | 新しい依存がありません。parser の範囲を狭くできます。ただし、EBML の writer / parser を保守する必要があります。 |
| V2: operator が導入する GStreamer の subprocess（`matroskamux` / `mp4mux` / `qtdemux` / `jpegdec`、C なら `nvh264enc`） | Agent の capture と同じく、絶対 path、root 所有の確認、使う plugin を限る、Landlock で閉じ込める、という形で実行します。 | `agent/docs/DEPENDENCIES.md` が LGPL-2.1-or-later と記録しているのは core と good だけ。base と bad も upstream では LGPL のはずだが、採用のときに COPYING で確認する。ugly の `x264enc` は x264 の GPL が掛かる | Agent の `uvc_sandbox.py` と同じ手法を、Main にも適用する必要があります。GPU を使うなら `/dev/nvidia*` への access が要るので、閉じ込めの範囲が広がります。 | Main の capture は今は GStreamer を使っていないので、Main への新しい runtime の導入になります。Owner の承認が要ります（DEPENDENCIES.md の「Adopting GStreamer as the production capture runtime ... requires the Owner decision」に準じます）。 |
| V3: FFmpeg の CLI を subprocess で使う | `ffmpeg` / `ffprobe` を operator が導入します。 | 既定の build は LGPL-2.1-or-later。`--enable-gpl` や libx264 を使うと全体が GPL になります [FFmpeg-legal]。distribution の package がどう configure されているか、監査が要ります | subprocess + Landlock で閉じ込めます。demuxer と decoder の攻撃面が非常に広くなります。 | Main host には入っていません。 |
| V4: PyAV（in-process） | FFmpeg の Python binding です。wheel に FFmpeg が同梱されています。 | PyAV 自体は BSD-3-Clause です。PyPI の page には、同梱した FFmpeg の build 構成（GPL か LGPL か、libx264 を含むか）が**書かれていません** [PyPI-av]。旧版の文書では、wheel に libx264 / libx265 が入っていると書かれていました [PyAV-install-old] | native の decoder が Main の process 内で動くので、simplejpeg のときに Owner が決めた「native decode は分離子プロセスで行う」方針と合いません。採用するなら、分離子プロセスの中で動かす必要があります。 | wheel の監査（native library と license file の一覧）が重くなります。 |

H.264 を採用する場合は、validator にも H.264 の decoder が要ります（`nvh264dec`、`avdec_h264`、`openh264dec` など）。encoder と同じ依存の review をもう一度行う必要があります。

## 8. 資源と容量の見積もり（すべて推定。測っていません）

前提:

- MJPEG の bitrate は §3 の実測値です（1080p30 = 40.7 Mbps を代表値、60 Mbps を上振れ値、720p30 = 25 Mbps）。
- H.264 の bitrate は **仮定**です。1080p30 で 4〜8 Mbps（代表値 6 Mbps）、720p30 で 2〜4 Mbps としました。室内の固定 camera を想定した値で、根拠となる測定はありません。NVENC は x264 と同じ画質を得るのに、より高い bitrate が要る場合があります（これも測っていません）。
- container の overhead は無視しています（MJPEG の frame あたり数十 byte 程度の見込みです）。1 GB = 10^9 byte です。

### 8.1 1 source あたり

| 形式 | 30 秒の pre-roll | 150 秒の既定 event | 20 分（上限） | 1 時間 | 24 時間 |
| --- | --- | --- | --- | --- | --- |
| MJPEG 1080p30 @40.7 Mbps | 153 MB | 763 MB | 6.1 GB | 18.3 GB | 440 GB |
| MJPEG 1080p30 @60 Mbps | 225 MB | 1.13 GB | 9.0 GB | 27 GB | 648 GB |
| MJPEG 720p30 @25 Mbps | 94 MB | 469 MB | 3.75 GB | 11.3 GB | 270 GB |
| H.264 1080p30 @6 Mbps（仮定） | 22.5 MB | 113 MB | 0.9 GB | 2.7 GB | 65 GB |
| H.264 720p30 @3 Mbps（仮定） | 11 MB | 56 MB | 0.45 GB | 1.35 GB | 32 GB |

### 8.2 1〜4 source で 20 日保持した場合（例）

例として、1 source あたり 1 日 50 件の既定 event（150 秒）が起き、それを 20 日保持するとします。件数は仮定です。

| source 数 | MJPEG 1080p @40.7 | MJPEG 1080p @60 | H.264 1080p @6（仮定） |
| --- | --- | --- | --- |
| 1 | 0.76 TB | 1.13 TB | 0.11 TB |
| 2 | 1.53 TB | 2.25 TB | 0.23 TB |
| 4 | 3.05 TB | 4.5 TB | 0.45 TB |

event が続いて 20 分の上限まで伸びる場合や、手動録画が多い場合は、これよりも大きくなります。仮に常時録画をすると、MJPEG 1080p では 4 source × 20 日で 35〜52 TB になり、現実的ではありません（常時録画は要件にはありません）。

**retention との関係**: MJPEG の場合、20 日の既定保持より先に `STORAGE_PRESSURE` に達して、古い録画が回収される可能性が高くなります。STORE-004 / 006 の順序（期限切れ → 古い unstarred → 新規の抑制）は保たれますが、Owner が見る「保持できている日数」は短くなります。これは表示（#21）に出す必要があります。

### 8.3 pre-roll spool の書き込み量

保存層の pre-roll spool は disk 上の file なので、source が有効な間はずっと書き換わり続けます（README「compressed pre-roll spool」）。4 source の場合で計算します。

- MJPEG 1080p @40.7 Mbps: 約 20 MB/s で、**1 日に約 1.76 TB** を書きます。
- H.264 @6 Mbps（仮定）: 約 3 MB/s で、1 日に約 0.26 TB です。

recording root が SSD / NVMe の場合、MJPEG の pre-roll は耐久性（TBW）にかなり効きます。HDD なら、帯域は問題にならない見込みです。代わりの方法として、pre-roll を memory 上の compressed ring に置く方法があります（4 × 225 MB ≈ 0.9 GB。decoded frame ではないので MEDIA-009 に反しません）。ただしこれは保存層の設計変更になり、crash のときに pre-roll を失います。

### 8.4 segment の長さと、同期 I/O・行数への影響

`RecordingStore.append()` は、1 segment ごとに次の同期処理を、1 つの owning worker thread の上で順番に行います（`store.py`）。

1. pending 行を入れる SQLite transaction の commit（`synchronous=FULL` 以上）
2. `.part` の `fsync`
3. link と unlink のあとの directory `fsync`
4. ready にして recording に link する SQLite transaction の commit（`_publish()`）
5. **`_trim()` の transaction の commit。これは append のたびに毎回実行されます**（spool の印を更新する transaction で、追い出すものが無くても commit します）
6. spool から外れて、どの recording にも link されていない segment ごとに、unlink、directory `fsync`、`DELETE` の transaction の commit

event が無い定常状態では、新しい segment が 1 つ入るたびに、pre-roll の窓（`pre_roll_ms`）から古い segment が 1 つ外れ、link されていないので 6 で削除されます。つまり**定常状態では、append のたびに追い出しが起きます**。

| 状態 | 1 append あたりの commit | 1 append あたりの file・dir の fsync |
| --- | --- | --- |
| 定常状態（event 無し、追い出し 1 件を含む） | 4（1、4、5、6） | 3（2、3、6） |
| その source が event で録画されている間（外れた segment は link されているので削除されない） | 3（1、4、5） | 2（2、3） |

event は 1〜4 source の任意の部分集合に掛かります。spool の追い出しは source ごとに起きるので、active な source が N 台、そのうち録画中の source が k 台のとき、同期処理（commit + fsync）の回数は 1 秒あたり **(k × 5 + (N − k) × 7) ÷ segment の秒数** です。録画していない source は、event 中でも定常状態と同じく追い出しを続けます。最も多くなるのは、event が無い（k = 0）ときです。

| segment の長さ | 4 source での append / 秒 | 定常状態: commit / 秒 | 定常状態: fsync / 秒 | 同期処理の合計 / 秒（N = 4、録画中 k = 0 / 1 / 2 / 3 / 4） | 20 分の録画の segment 数（`max_segments_per_recording` の下限の目安） |
| --- | --- | --- | --- | --- | --- |
| 1 秒 | 4 | 16 | 12 | 28 / 26 / 24 / 22 / 20 | 約 1,200（境界の分を足す） |
| 2 秒 | 2 | 8 | 6 | 14 / 13 / 12 / 11 / 10 | 約 600 |
| 4 秒 | 1 | 4 | 3 | 7 / 6.5 / 6 / 5.5 / 5 | 約 300 |

pre-roll に関わる上限（`pre_roll_bytes`、`max_spool_segments`、`max_segment_bytes`）は §8.6 にまとめました。

この数え方は、上の file / directory の fsync と、SQLite の commit の回数です。SQLite の commit は、journal mode によっては、内部でさらに fsync を伴います（rollback journal なら journal と database の両方。WAL なら WAL の fsync）。

- SSD / NVMe なら、この回数は問題にならない見込みです（**測っていません**）。
- HDD では、1 回の fsync に数 ms〜十数 ms かかることがあります。仮に同期処理 1 回を 10 ms とすると、1 秒の segment × 4 source の定常状態（28 回 / 秒）では、worker の時間の**約 3 割以上**を同期 I/O が占めます。SQLite 内部の fsync を足すと、journal mode によってはさらに増えます。これは**仮定にもとづく推定**です。

segment の長さを決めるときの trade-off は次のとおりです。

- **短くする利点**: crash で失う量（最大 1 segment）、gap の粒度、再生の seek の粒度、muxer が memory に持つ量（`max_segment_bytes`。MJPEG 1080p の 2 秒で約 10〜15 MB）が小さくなります。
- **長くする利点**: 同期 I/O の回数と、SQLite の行数（`recording_segments` / `recording_links`）が減ります。

推奨案（§11）の「1〜2 秒」は、MJPEG では segment の境界をどの frame にも置けることと、上の同期 I/O の回数とのあいだの仮の値です。recording root の媒体（Q7）に対して、実機で append の遅延と fsync の回数を測ってから決めます（§13）。`Limits` の値は caller が与えるもので、この調査は既定値を決めません。

### 8.5 CPU / GPU

| 形式 | 処理 | 見積もり |
| --- | --- | --- |
| A（MJPEG copy） | mux | 無視できる程度（frame の copy と header を書くだけ） |
| A の validator | 全 frame を decode する | 合成 frame の 1080p 4:2:2 で full decode が 3.4〜4.1 ms / frame（decoder 調査の値で、合成の noise を含む上限）。30 fps なら約 0.12 core / source、4 source で約 0.5 core。実 frame（約 166 KiB）は合成（約 425 KB）より小さいので、実際はこれより軽いと考えられる（**確認していません**） |
| （不採用）A の validator で、構造は全 frame、decode は一部の frame だけ | 上記の数 % | 不採用。§9 の 4 を参照 |
| B（x264 / OpenH264） | decode + 色変換 + encode | **測っていません**。1080p30 では source ごとに数 core 規模の可能性がある（仮定） |
| C（NVENC） | decode（CPU か `nvjpegdec`）+ upload + encode | CPU は decode の分（約 0.12 core / source）+ α。NVENC は 4 基あり、session の上限はありません [NVIDIA-matrix]。throughput と VRAM は**測っていません** |

### 8.6 30 秒の pre-roll に必要な運用上限（negotiated bound から計算する）

`Limits` の `pre_roll_bytes`、`max_spool_segments`、`max_segment_bytes` は、**source ごとではなく、store 全体で共有される上限**です（`store.py` の `_trim()` は、全 source の spool の合計 byte 数と合計 segment 数を比べます）。`_trim()` は、各 source の最新の `end_ms` から `pre_roll_ms` より前に終わった segment を spool から外します。このため、spool には source ごとに 30 秒分と、境界の 1 segment が残ります。合計がどちらかの上限を超えると、`_trim()` は古い segment から spool の印を外します。そのため、上限が足りないと、**30 秒より新しい segment まで追い出され、pre-roll が短くなります**。

`server/docs/DEPLOYMENT.md` の例の値は、`pre_roll_bytes` = 67,108,864（64 MiB）、`max_spool_segments` = 64、`max_segment_bytes` = 8,388,608（8 MiB）、`max_segment_ms` = 10,000 です。また、`max_segment_bytes` は storage の `max_request_bytes`（例では 16 MiB）以下でなければ、設定が拒否されます（`server/app/monitoring/config.py`）。

#### 計算の式

観測した平均の bitrate（§3）では、30 秒を保証できません。上限は、**source ごとの negotiated bound** から計算します。

- 記号:
  - `P` = `pre_roll_ms`（30 秒）
  - `B_s` = source s の `VideoFormat.maximum_bitrate`（bit/s）。H.264 では NVENC の rate control で守らせる最大 bitrate です。
  - `V_s` = encoder の VBV buffer の大きさ（byte）。rate control が許す一時的な超過の上限です。MJPEG では 0 とし、`B_s` を超える segment は拒否します（T4）。
  - `o` = mux の overhead の割合（`moof` / sample table など）
  - `H` = segment ごとの固定の overhead（自己完結させるための init segment など）
  - `D_s` = 通常の segment の長さ。`Dmax_s` = その最大値（`max_segment_ms` 以下）
  - `R_s` = 1 つの pre-roll の窓の中で許す、reset / discontinuity による早い区切りの回数。区切りが起きると、短い segment ができます。
- 式:
  - `pre_roll_bytes` ≥ Σ_s [ (P + Dmax_s) × B_s ÷ 8 × (1 + o) + V_s + n_s × H ]
  - `max_spool_segments` ≥ Σ_s n_s。ここで n_s = ⌈P ÷ D_s⌉ + 1 + R_s
  - `max_segment_bytes` ≥ max_s [ Dmax_s × B_s ÷ 8 × (1 + o) + V_s + H ]。また、`max_request_bytes` ≥ `max_segment_bytes`
- reset / discontinuity が窓の中で `R_s` 回を超えると、segment の数が上限を超えて、pre-roll が短くなります。これは manifest で short buffer として報告され（recording README）、録画の health では degraded として扱う必要があります。`R_s` の値は、muxer の区切りの規則と合わせて実装のときに決めます。

#### 例（値はすべて仮定。実機で決め直します）

`P` = 30 秒、4 source、`D_s` = `Dmax_s` = 2 秒、`R_s` = 2、`o` = 2 %、`H` = 2 KB としました。

| 条件 | `B_s` | `V_s` | `pre_roll_bytes` | `max_spool_segments` | `max_segment_bytes` |
| --- | --- | --- | --- | --- | --- |
| H.264（NVENC、決定済みの形式） | 8 Mbps（仮定） | 1 MB（仮定） | 約 0.14 GB | 72 以上 | 約 3.0 MB |
| MJPEG の fallback（上限を設定で強制） | 60 Mbps（仮定） | 0 | 約 0.98 GB | 72 以上 | 約 15.3 MB（16 MiB 以上を推奨） |
| MJPEG の fallback（上限を強制しない場合） | 約 995 Mbps（1 frame の上限を V4L2 の MJPG buffer の大きさ 1920×1080×2 byte とし、30 fps とした場合） | 0 | 約 16 GB | 72 以上 | 約 254 MB（`max_request_bytes` を大きく超える） |
| DEPLOYMENT.md の例 | — | — | 64 MiB（約 0.067 GB） | 64 | 8 MiB |

このことから、次の点が分かります。

- H.264 でも、例の `pre_roll_bytes`（64 MiB）と `max_spool_segments`（64）では、4 source で 30 秒の pre-roll を保証できません。例の値を、上の式で計算した値に更新する必要があります。
- **MJPEG の fallback は、上限を強制しないと、現実的な値で 30 秒を保証できません。** camera が bitrate を制御しないためです。fallback 用の最大 bitrate を設定し、それを超える segment は拒否して gap にし、degraded にする必要があります（T4）。fallback に切り替わったときは、`pre_roll_bytes` が fallback の bound でも足りるように、最初から大きい方の値で設定します。
- `max_segments_per_recording`（例では 8,640）は、20 分の録画を 1 秒 segment で記録する場合でも足ります（約 1,200 + R）。

上限値と segment の長さは、実機で同期 I/O（§8.4、HDD）と bitrate を測ってから決め、`server/docs/DEPLOYMENT.md` の例の値も更新します（Q7）。

## 9. segment の integrity 検証

`SegmentValidator` は、保存の前に次のことを確認する必要があります（README / `model.py` の docstring の契約）。

1. **container の構造**: 自分が書いた subset 以外は拒否します（未知の element / box、track が複数、audio track があるもの、codec ID が allowlist に無いもの）。container の寸法が、source が negotiate した profile と一致することも確認します。
2. **codec の構造**:
   - MJPEG: frame ごとに SOI / EOI と SOF の寸法を確認し、SOF0 / SOF1 の 8-bit baseline 以外を拒否します（decoder 調査の規則 2 と、#233 の lossless SOF 拒否を流用します）。
   - H.264: SPS の寸法と profile の allowlist を確認し、segment の先頭が IDR であることを確認します。
3. **timestamp**: segment の中で単調に増えること。`Segment.start_ms` / `end_ms` と container の duration が一致すること。frame 数が fps × duration の許容範囲内に収まること。
4. **decode**: 分離子プロセスで、**segment の全 frame を decode します（必須）**。失敗はすべて拒否にして、録画の health を degraded にします。黙って保存することはしません。
   - 一部の frame だけを decode する案は採りません。SOI / EOI / SOF などの構造検査を通っても、Huffman 表、量子化表、entropy-coded data が壊れていて decode できない frame があり得ます。decode しなかった frame にそれがあると、そのまま保存されます。`RecordingStore` は validator が成功した segment を `integrity='verified'` として記録するので、壊れた frame は再生するまで見つからず、録画の health も正常のままになります。これは、保存の前に「independent decodability」を確かめるという保存層の契約（`SegmentValidator`）に反します。
   - CPU は 4 source で約 0.5 core と推定しています（§8.5。合成 frame による上限）。実機で測って、資源の上限を決めます。
   - 既存の ROI 用の子プロセス（`server/app/detection/roi/mjpg_worker.py` / `mjpg_child.py`）は、ROI 用に作られています。1 source に 1 つ、低い優先度（nice 10）、1 frame あたり 500 ms の deadline で動き、luma の画素を返します。そのまま録画の検証に使うことはできません。
   - そのため、同じ方式（fork+exec、rlimit、Landlock + seccomp、deadline）を基にして、**検証専用の request を足す**必要があります。
     - 画素を返さず、decode できたかどうかと寸法だけを返します。
     - segment 単位で、複数の frame をまとめて送ります。
   - 子プロセスの数と優先度も決める必要があります。ROI と共有するか、録画の検証専用にするかです。
   - 検証が録画の速さに追いつかないときは、queue を有界に保ちます。あふれた segment は拒否して gap にし、録画を degraded にします。検証を飛ばして保存することはしません。
5. byte の integrity（SHA-256、長さ、hard link や symlink の拒否、再検証）は、保存層がすでに行っています。

**Recording Health の self-test（#23、SPEC §10.3）**: 既存の self-test の契約は、**実際の pipeline から取った、上限のある sample** を使うことを求めています（`server/app/media/health/README.md`「obtains a bounded sample from the actual pipeline」、`RecordingStore.self_test_probe()` の docstring「bounded actual-pipeline sample provider」）。そのため self-test の segment は、**直近の実 pipeline の出力（capture → packet adapter → muxer）**を取り、それを recording root に write → fsync → reopen → 構造 / duration / size の検証 → validator による全 frame の decode、の順で確認します。

- 合成の frame を self-test に使うことはしません。合成の入力を mux して検証するだけでは、実際の capture → packet adapter → muxer の経路が壊れていても self-test が成功してしまうからです。合成の media は、validator や muxer の単体テストにだけ使います（README「Generated test bytes do not constitute a production codec」）。
- **privacy**: self-test の segment には、実際の部屋の映像が入ります。既存の契約どおりに扱います。
  - file は journal に記録した `.selftest` の 1 つだけで、名前は生成した UUID です。
  - 成功・失敗・中断のどの場合も、検証のあとに削除し、削除も fsync します。強制終了などで残ったものは、次の起動時に、新しい test segment を書く前に回収します。cleanup に失敗した場合は、次の self-test media を書きません。
  - 結果には media、path、例外の文字列を含めません（health README）。
  - self-test の segment は録画として登録しないので、一覧・再生・retention の対象にはなりません。
- H.264 を選んだ場合、self-test は encoder（GPU）の health も確かめる必要があります。

## 10. Agent の MJPEG 入力との関係

- capture host には H.264 encoder がありません（base / good だけ）。Agent が H.264 を作るには、capture host にも codec の依存と CPU / GPU が要ります。そうすると、`media-capture-agent` の「最小の plugin（`coreelements` + `video4linux2`）」という sandbox の前提が崩れます。**MJPEG のまま転送し、Main で処理する**のが、現在の Agent の設計に合います。
- Agent の ring buffer（#16）が保護する incident は、Main の録画とは別の二次証拠です。ring に入れる segment の codec と container は、まだ決まっていません。capture adapter の責任とされています（`agent/docs/RING_BUFFER.md`「Inputs and control boundary」）。また、Agent の runtime は stdlib だけを使う方針です（`agent/docs/DEPENDENCIES.md`。`node_tls` の cryptography を除く）。
  - **Agent の segmenter も Matroska `V_MJPEG` を選べば**、Agent の incident 証拠と Main の録画の形式をそろえられます。その場合、stdlib の EBML writer / parser は共有できる余地があります。
  - simplejpeg による decode の検証は、Main 側だけで行います。Agent には simplejpeg を入れないので、Agent 側の検証は構造の検査までです。
  - Main が H.264 で保存する場合は、Agent の証拠（MJPEG を前提とする）と形式が分かれます。
- LAN の帯域は、MJPEG 1080p × 4 source で約 160〜240 Mbps です。これに対し、TCP の実測は 940 Mbps です（`MANUAL_TEST.md` の LAN baseline）。

## 11. 判断の前の推奨（背景として残す。§0 の Owner 判断が優先します）

**段階的に進める案を推奨します。**

1. **今（#23 / #26 / S9 の解除）**: **A（MJPEG stream copy）+ Matroska（`V_MJPEG`）を 1〜2 秒の自己完結した segment にする + V1（stdlib の muxer / parser + 既存の simplejpeg 分離子プロセスで validator）**。再生は **P1（認可付きの frame pull。S7 と同じ方式）**。
   - 理由:
     - 新しい codec の依存、GPL、AVC の特許、GPU が要りません。
     - MEDIA-003 / SPEC §6.2 の優先順位 1 位（stream copy）に当たります。
     - Agent から届く入力（MJPEG）を transcode せずに保存できます。Agent の ring の形式も `V_MJPEG` にそろえる余地があります（§10。Agent 側はまだ決まっていません）。
     - validator には、Owner が承認済みの decoder を、既存と同じ閉じ込めの方式で使えます（検証用の protocol を足します。§9）。
     - これで #23 の self-test を、実際の pipeline の sample（capture → packet adapter → muxer → validator）で実装でき、`RefuseUnvalidatedSegments` を外せます。
   - 前提: validator は全 frame を decode します（§9）。`pre_roll_bytes`、`max_spool_segments`、`max_segment_bytes`、`max_request_bytes` を §8.6 の値に合わせて決め、`server/docs/DEPLOYMENT.md` の例も更新します。
   - 代償:
     - 容量が H.264 の約 7 倍です（推定。§8）。retention は保持日数より容量で決まりやすくなります。
     - pre-roll spool の書き込み量が大きくなります（SSD の場合）。
     - 再生には `<video>` の controls が無く、帯域も大きくなります。
2. **#19（live transport）で H.264 の encoder を採用する場合**: 同じ encoder（C の NVENC を優先し、B を software fallback にするか、A に戻すかは Owner が決めます）を使って、**P2（再生のときに H.264 fMP4 / HLS へ変換する）**を加えます。そのうえで、保存形式を H.264 fMP4 に移すかどうかを、実測（CPU / GPU / 容量 / 画質）にもとづいて改めて判断します。保存層は segment ごとに `codec` / `container` を記録しているので、形式が混在しても manifest で区別できます。

推奨しない案:

- x264（GPL）を Main の既定にすること
- PyAV を in-process で使うこと
- MPEG-TS
- NVENC だけ（fallback 無し）で correctness を成り立たせること（SPEC §6.2 と相反します）

## 12. Owner に尋ねた問い（2026-10-22 に判断済み。判断は §0）

- **Q1（codec）**: MJPEG の stream copy にするか、H.264 にするか。→ **H.264**
- **Q2（D13: container / 再生）**: MJPEG なら Matroska / 自前の形式 / MP4 のどれか、P1 でよいか。H.264 なら fragmented MP4 + HLS(fMP4) / MSE でよいか。→ **fragmented MP4 をそのまま browser へ配る（P3）。server 側で `recordings:view` を確認し、download / export は提供しない**
- **Q3（依存）**: 自前の stdlib 実装 / GStreamer / FFmpeg の CLI / PyAV のどれを認めるか。x264 と OpenH264 を外してよいか。→ **encoder は GStreamer の nvcodec（NVENC）**。muxer と validator の decoder は、T1 / T2 で決めます。
- **Q4（hardware と fallback）**: NVENC が無い・失敗したときの動作。→ **MJPEG の保存に fallback し、degraded にして Owner に通知する（黙って fallback しない）**
- **Q5（validator）**: 全 frame の decode に必要な CPU と、子プロセスを共有するか専用にするか。→ **全 frame の decode は必須。録画の検証専用の子プロセスで行う。CPU は実機で測る**
- **Q6（self-test の sample）**: 実 pipeline の sample を `.selftest` の契約で扱うこと。→ **実 pipeline の sample を使い、`.selftest` の契約に従う**
- **Q7（容量と上限）**: recording root の容量と媒体、pre-roll の置き場所、上限値と segment の長さ。→ **HDD。segment の長さは実機で同期 I/O を測ってから決める。§8.6 の上限は negotiated bound から計算し直す**
- **Q8（AVC の特許）**: → **研究室内での使用として、Owner の責任で受け入れる**

## 13. 未検証のこと

- 実 camera、実 encoder、実 browser での測定は、一切行っていません（CPU / GPU / VRAM、encode の遅延、画質、bitrate、Safari / iPhone の HLS と cookie、Firefox on Linux の H.264）。
- H.264 の bitrate、software encode の CPU、NVENC の throughput は仮定です。
- distribution package の GStreamer bad / FFmpeg の build 構成と license、gst-plugins-rs の fmp4 の正確な license（distribution の metadata には MPL-2.0 とある）、PyAV の wheel に同梱された FFmpeg の構成は、pinning のときに一次資料で確認する必要があります。
- 法務の判断（AVC の特許、OpenH264 の binary license の適用範囲）は、この調査の範囲外です。AVC の特許は、Owner が研究室内での使用として自身の責任で受け入れました（§0 Q8）。
- recording root の実際の媒体（HDD / SSD）での append の遅延、fsync と SQLite の commit の回数・時間（§8.4）は測っていません。segment の長さ（1〜2 秒）は、この実機の測定を経てから決めます。
- iPhone Safari の ManagedMediaSource が、AirPlay の代替 source を置いたとき、または `disableRemotePlayback` を `true` にしたときにだけ開くこと（[MDN-MMS] の条件）を、実機で確かめていません。
- 検証用の decode の子プロセスが、ROI 用と並んで動いたときの CPU と遅延（§9）は測っていません。H.264 の validator に使う decoder（T1）はまだ決まっておらず、その license（gst-libav / FFmpeg の build 構成など）と閉じ込めの方式も確認していません。
- NVENC の最大 bitrate と VBV を設定したときの、実際の segment の大きさ（§8.6 の bound が守られるか）は測っていません。

## 14. 出典（2026-10-22 に参照）

- [MDN-codecs] MDN, Web video codec guide — https://developer.mozilla.org/en-US/docs/Web/Media/Guides/Formats/Video_codecs
- [MDN-containers] MDN, Media container formats — https://developer.mozilla.org/en-US/docs/Web/Media/Guides/Formats/Containers
- [MDN-MMS] MDN, ManagedMediaSource — https://developer.mozilla.org/en-US/docs/Web/API/ManagedMediaSource
- [WebKit-17.1] WebKit, WebKit Features in Safari 17.1 — https://webkit.org/blog/14735/
- [W3C-MSE-ISOBMFF] W3C, ISO BMFF Byte Stream Format — https://www.w3.org/TR/mse-byte-stream-format-isobmff/
- [RFC8216] IETF RFC 8216, HTTP Live Streaming（§3.3 fMP4、§4.3.2.5 EXT-X-MAP）— https://datatracker.ietf.org/doc/html/rfc8216
- [Apple-byterange] Apple, Safari Web Content Guide: Creating Video for Safari on iPhone（Configuring Your Server）— https://developer.apple.com/library/archive/documentation/AppleApplications/Reference/SafariWebContent/CreatingVideoforSafarioniPhone/CreatingVideoforSafarioniPhone.html
- [Matroska-codecs] Matroska Codec Mappings — https://www.matroska.org/technical/codec_specs.html
- [GStreamer-qtmux] GStreamer, qtmux（robust muxing、fragment-duration）— https://gstreamer.freedesktop.org/documentation/isomp4/qtmux.html
- [GStreamer-modules] GStreamer の module 説明（gst-plugins-ugly / bad）。distribution の packaging（例: BLFS gst-plugins-ugly）でも同じ文言 — https://rivendell.linuxfromscratch.org/blfs/view/12.1/multimedia/gst10-plugins-ugly.html
- [x264] VideoLAN, x264 — https://www.videolan.org/developers/x264.html
- [OpenH264-binary] Cisco OpenH264 Binary License — https://www.openh264.org/BINARY_LICENSE.txt
- [FFmpeg-legal] FFmpeg License and Legal Considerations — https://ffmpeg.org/legal.html
- [PyPI-av] PyPI, av（PyAV）— https://pypi.org/project/av/
- [PyAV-install-old] PyAV documentation, Installation（旧版。wheel の FFmpeg 構成の記載）— https://pyav.org/docs/stable/overview/installation.html
- [ViaLA-AVC] Via LA, AVC/H.264 License Program — https://www.via-la.com/licensing-programs/avc-h-264/
- [NVIDIA-matrix] NVIDIA, Video Encode and Decode GPU Support Matrix — https://developer.nvidia.com/video-encode-decode-support-matrix
- [nvidia-vaapi] elFarto/nvidia-vaapi-driver — https://github.com/elFarto/nvidia-vaapi-driver
- repository の内部資料: `REQUIREMENTS.md`（MEDIA-003/005/007〜010、STORE-003〜006、AUTH-007）、`SPECIFICATION.md`（§6.2、§6.5〜6.7、§9、§10.3）、`server/app/media/recording/README.md`、`server/app/media/profiles/README.md`、`agent/docs/DEPENDENCIES.md`、`agent/capture/README.md`、`docs/decisions/2026-10-11-mjpg-decoder-survey.md`、`MANUAL_TEST.md`（local UVC capture resource、LAN baseline）
