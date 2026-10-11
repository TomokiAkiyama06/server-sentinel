# Issue #15 Agent–Main media transport PoC 計測ハーネス（手動試験専用）

このディレクトリは Issue #15 / ADR-0007 の transport 比較を **同じ決定的 impairment
matrix と同じ Main 側判定** で測るためのハーネスです。製品ではありません。
`server/` と `agent/` の package はここを import せず、release artifact にも含めません。
**本 README の実機手順はまだ一度も実行していません**（PR 時点の確認は loopback の
synthetic 実行のみ）。実機の結果は `MANUAL_TEST.md` §G の記録テンプレートと
ADR-0007 Validation 表へ記入し、未実施の構成を検証済みと書かないでください。

## 何を使い、何を測るか

- 製品コードをそのまま使う: Main 側は `IngestListenerConfig` / `build_ingest_server_context` /
  `CaptureIngestAcceptor`（TLS 1.3 mTLS、ledger の現在の activation）、
  `ContinuityTracker` + `AgentIngestQueue`。Agent 側は `node_tls.build_capture_client_context` /
  `connect_to_main`（deployment CA pin、server name 検証、Tailscale endpoint 拒否）、
  実カメラは `UvcCapture` + sandbox 付き `GStreamerLauncher`（video node のみ、`/dev/snd` 不使用）。
- 鍵・CA・ledger はすべて使い捨ての試験専用（`materials`）。本番 deployment の CA / ledger は使わない。
- 受信 payload は SHA-256 を計算して即破棄。Main 側に残るのは source ごとの数値 watermark
  （private SQLite、`--state` 配下）だけ。映像は 1 frame も disk に書かない。
- 測定出力は数値 JSONL のみ（`records.py` が値を数値 / 真偽 / null / 固定語彙に制限し、
  文字列・path・IP・UUID・hostname を拒否）。

候補（今回の範囲、新規 package なし）:

| candidate | 内容 |
| --- | --- |
| `a_framed` | TLS 1.3 mTLS 上の length-prefixed frame stream。source ごと stop-and-wait、1 s heartbeat |
| `b_chunked` | 同じ frame を HTTP/1.1 chunked の長寿命 `POST /poc15/v1/stream` で送受信 |
| `b_segment` | 1 s ごとの `PUT /poc15/v1/segment`（body = frame 列、response = ack 列、keep-alive） |

QUIC / WebRTC は今回対象外です。SRT は passphrase 方式で ADR-0006 の相互証明書認証を
満たせず G1 を通らないため、Owner 判断（2026-10-11）で候補から外しました。TCP の packet loss / jitter は root の `netem` が必要なため
測定せず、summary は常に `unmeasured` と出します。

## ポートと bind（試験専用。`0.0.0.0` は使わない）

| 用途 | 既定 |
| --- | --- |
| Main receiver `a_framed` | `<MAIN_LAN_IP>:47200/tcp` |
| Main receiver `b_chunked` / `b_segment` | `<MAIN_LAN_IP>:47201/tcp` |
| capture host の impairment proxy | `127.0.0.1:47210`（A）/ `47211`（B chunked）/ `47212`（B segment）。47213–47214 は予備 |

`<MAIN_LAN_IP>` は private LAN の IP literal（Tailscale 範囲は product validation が拒否）。
実 IP / hostname / 経路は repository・Issue・PR に書かず、私的な手元記録にのみ残します。
receiver は product の bind 検証を通した上で `SO_REUSEADDR` 付きで bind します（product の
`open_ingest_listener` には無く、TIME_WAIT 中の Main 再起動で再 bind できないため。product 側の対応は
Issue #223 で追跡）。

## 安全規則

- Main host は production（GPU benchmark が同居）。Main 側は必ず
  `CUDA_VISIBLE_DEVICES=` と `systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=1G`
  + `nice -n 10 ionice -c 3` + `timeout -k 30 <上限>` の下で動かす。scope 名は `ss-poc15-*`。
- sudo / root / `tc` / firewall 変更 / Tailscale 設定変更はしない。Main から capture host へ SSH しない。
- 1 日の合計実行は **3 時間まで**（scenario 長の合計 + 起動・停止の余裕。`timeout` は暴走時の
  上限）。soak は下の「soak の上限」の通り、上限値の 1 run 45 分で数える。
- `--materials` / `--state` / `--out` / holder の state・socket は repository の外の 0700 directory
  （ハーネスは repository 内の path を拒否）。
- 実カメラ frame は holder → sender の unix socket（0700 directory 内）経由で memory 上のみ。
  映像を見る・保存する操作はしない。実在人物が映る場合は撮影範囲に人がいない時間に行う。
- 緊急停止（kill switch）: 両 host で `systemctl --user stop 'ss-poc15-*'`。
  `timeout -k` は二重の上限です。

## Step 0: read-only inventory（変更なし）

両 host で、値は手元記録にだけ残し、repository には粗い値（版数、core 数など）だけ書く。

```sh
uname -r; nproc; free -m; python3 --version
systemd-run --version | head -1; systemctl --user is-system-running
ss -ltnu '( sport >= :47200 and sport <= :47214 )'   # 何も表示されないこと
command -v ss gst-launch-1.0
cat /sys/fs/cgroup/user.slice/cpu.max 2>/dev/null
```

capture host のみ（実カメラ時）: `id -nG` に `video` があること、`ls /dev/video* | wc -l`
（件数だけ）、Landlock 有無（MANUAL_TEST §B の記録と同じ方法）。

## Step 1: 使い捨て materials

Main（`R=~/poc15/materials` など repository 外）:

```sh
python3 scripts/manual/transport_poc/poc15.py materials init --root "$R" --negatives-only
```

capture host（正規 node の鍵は capture host から出さない）:

```sh
python3 scripts/manual/transport_poc/poc15.py materials node-key --root ~/poc15/nodes/good
python3 scripts/manual/transport_poc/poc15.py materials node-key --root ~/poc15/nodes/revoked_live
```

`csr.pem`（公開情報）を Owner の既存の信頼できる経路で Main へ渡し、Main で発行:

```sh
python3 scripts/manual/transport_poc/poc15.py materials issue --root "$R" --csr good.csr.pem --label good
python3 scripts/manual/transport_poc/poc15.py materials issue --root "$R" --csr live.csr.pem --label revoked_live
```

`$R/nodes/good/{ca.pem,cert.pem,node.json}` と同 `revoked_live` を capture host の同名
directory へ戻す。否定試験用 `$R/nodes/{unpaired,other_ca,revoked}`（鍵を含むが失効済み /
未 activation / 別 CA で何の権限もない使い捨て）も capture host の `~/poc15/nodes/` へ渡す。
`auth_revoked_live` は実行のたびに Main 側 ledger で revoke されるので、候補ごと（同じ候補の
再実行も含む）に capture host で `revoked_live` の `node-key` をやり直し、Main で `issue` して
新しい `cert.pem` / `node.json` を capture host へ戻してから実行する（revoke 済みの bundle の
ままだと接続前に拒否され、接続中失効を測れない）。

loopback（1 host）は `materials init --root "$R"` だけで全 bundle を作ります。

## Step 2: 実行

### loopback synthetic（1 host、CI と同じ形）

```sh
CUDA_VISIBLE_DEVICES= timeout -k 30 90m systemd-run --user --scope --unit=ss-poc15-loop \
  -p CPUQuota=200% -p MemoryMax=1G nice -n 10 ionice -c 3 \
  python3 scripts/manual/transport_poc/poc15.py matrix --materials "$R" --state ~/poc15/state \
  --out ~/poc15/out --summarize            # --fast で短縮版
```

### 実機 2 host（1 scenario ずつ、同じ `--run-id`）

両 orchestrator は自 host の action だけを自 host の開始時刻基準で実行します。Main を先に
起動し、Main の orchestrator が標準出力に `ready <scenario> <candidate>` を出したら 10 秒以内に
capture host を起動します（Main は scenario 長 + 20 s 待つ）。

`<RUN_ID>` は両 host で同じ値を使い、形式は `r` + UTC の `YYYYMMDD` + `t` + `HHMMSS` + 任意の
16 進 0〜8 桁（例: `r20261011t093000a1`、`RUN_ID=r$(date -u +%Y%m%dt%H%M%S)`）。形式外の値は
記録時に拒否されます。

Main:

```sh
CUDA_VISIBLE_DEVICES= timeout -k 30 15m systemd-run --user --scope --unit=ss-poc15-main \
  -p CPUQuota=200% -p MemoryMax=1G nice -n 10 ionice -c 3 \
  python3 scripts/manual/transport_poc/poc15.py matrix --role main --bind <MAIN_LAN_IP> \
  --materials "$R" --state ~/poc15/state --out ~/poc15/out --real-inputs \
  --candidates a_framed --scenarios outage_5s --run-id <RUN_ID>
```

`--real-inputs` は capture host が holder（実カメラ）を使う run では Main 側にも必ず付け、
synthetic（`--source-kind gst` / `builtin`）の run では両側とも付けない。集計は片側でも
`real` と記録されていれば real として判定し（`ss` 必須、holder の Agent CPU を加算）、
両側の申告が食い違う run は `unmeasured` にします。

capture host（実カメラ。holder は 1 process で全カメラを保持）。holder の `--out` の親 directory
は holder 起動前に作る（holder は作らない）:

```sh
install -d -m 700 ~/poc15/out
timeout -k 30 20m systemd-run --user --scope --unit=ss-poc15-holder -p CPUQuota=100% -p MemoryMax=512M \
  python3 scripts/manual/transport_poc/poc15.py holder --state-dir ~/poc15/holder-state \
  --socket-dir ~/poc15/holder-sock --sources 1 --profile 1280x720@30 --approve \
  --seconds 1100 --out ~/poc15/out/holder.jsonl --run-id <RUN_ID>
timeout -k 30 15m systemd-run --user --scope --unit=ss-poc15-agent -p CPUQuota=100% -p MemoryMax=512M \
  python3 scripts/manual/transport_poc/poc15.py matrix --role agent --upstream-host <MAIN_LAN_IP> \
  --node-root ~/poc15/nodes --materials ~/poc15/nodes --state ~/poc15/state --out ~/poc15/out \
  --source-kind holder --holder-socket ~/poc15/holder-sock/frames.sock --real-inputs \
  --candidates a_framed --scenarios outage_5s --run-id <RUN_ID>
```

開発 checkout の sandbox helper は root 所有ではないため、MANUAL_TEST §B の前例と同じく
`--dev-checkout-helper`（helper ファイルだけ「本人所有かつ他者書込不可」を要求し、
GStreamer 本体と plugin は root 管理を要求）を付けたときだけ holder が起動します。
synthetic MJPEG は `--source-kind gst`（`videotestsrc is-live=true ! video/x-raw,width=1280,height=720,framerate=30/1 ! jpegenc`）、
または `builtin`（生成バイト列）です。`--real-inputs` は holder 使用時だけ付け、1〜4 source の
real / synthetic の内訳を記録に明記します。

`--role agent` の `--materials` は capture host 側では使われない（node bundle は `--node-root`）。

#### soak の上限

上の `timeout -k 30 15m` と holder の `--seconds 1100` は soak 以外の 1 scenario（最長
`normal` 300 s。Main は scenario 長 + 20 s 待ち、子 process の停止に各最大 15 s）用で、
soak（1800 s）には短すぎて途中で kill され、integrity `fail` になる。soak は 1 run ごとに
次の値にする（scenario 1800 s + Main 待ち 20 s + 起動・停止の余裕で 45 分）:

- Main: `timeout -k 30 45m ... matrix --role main ... --scenarios soak`
- capture host の agent: `timeout -k 30 45m ... matrix --role agent ... --scenarios soak`
- holder（実カメラ時）: `timeout -k 30 50m ... holder ... --seconds 2700`（agent より先に
  終わらないように agent の上限より長くする）

3 時間上限には 1 soak run を 45 分（実行は約 31 分、`timeout` 上限の値）で数える。soak 以外の full matrix は
scenario 長の合計が 1 候補あたり約 36 分だが、2 host では scenario ごとの起動・停止と Main の
grace を含めて 1 候補あたり約 42 分、3 候補で約 2 時間 7 分かかる。soak 1 run（45 分）を足すと
約 2 時間 52 分で 3 時間上限に余裕が無いため、**soak は full matrix と別の日に行う**。soak の日は
1 日最大 3 run（3 × 45 分 = 2 時間 15 分）。
loopback の `timeout -k 30 90m` も soak を含めない既定の matrix 用で、`--scenarios soak` を
加えるときは soak 1 run につき 45 分を足す。

`sources_2` / `sources_3` / `capacity_4` / `fifth_refused` は 2 / 3 / 4 / 5 source を必要とし、
holder は接続済みの実カメラ数しか供給しないため（現状 1 台）、これらの scenario は
`--source-kind gst`（synthetic）で実行し、記録の real camera 数は 0 とする。実カメラ 1 台 + synthetic 3 本の混在はこのハーネスでは
作れない（sender の media source は 1 種類）。

### scenario（決定的、full / `--fast`）

| scenario | 内容（full） |
| --- | --- |
| `normal` | 5 分無障害（1 source） |
| `sources_2` / `sources_3` | 2 / 3 source で 2 分無障害（1〜4 source の各構成を測るため。1 は `normal`、4 は `capacity_4`） |
| `outage_1s` / `outage_5s` / `outage_120s` | proxy blackhole（無音の読み停止）1 s×3 / 5 s×3 / 120 s×1 |
| `rst` | 全接続を RST ×3 |
| `bandwidth_cap` | 公称 bitrate の 50 % へ 180 s 制限 |
| `slow_stop_10s` / `slow_stop_60s` | Main receiver を SIGSTOP 10 s / 60 s |
| `slow_drain` | durable stand-in の消費を公称の 50 % に制限 |
| `main_restart` / `capture_restart` | receiver の異常停止（SIGUSR1: 未永続の queue を破棄）→ 再起動（durable watermark から再開）/ sender 再起動（epoch 前進）。通常終了（SIGTERM）の receiver は受理済み queue を永続化してから終了 |
| `capacity_4` / `fifth_refused` | 4 source 無 backpressure / 5 source 目の拒否 |
| `auth_unpaired` / `auth_other_ca` / `auth_revoked` / `auth_revoked_live` | 否定認証（受理 media 0）/ 接続中 revoke |
| `route_probe` | ハーネスの ingest receiver が human route（`GET /api/...`）を返さないこと。製品の human/admin API や capture credential の権限は確かめない（製品側は MANUAL_TEST §G の該当項目で確認） |
| `soak` | 30 分（`--scenarios soak` で明示時のみ） |

## Step 3: 集計と判定

```sh
python3 scripts/manual/transport_poc/poc15.py summarize --two-host MAIN_OUT/<RUN_ID> AGENT_OUT/<RUN_ID> \
  --holder AGENT_OUT/holder.jsonl --json ~/poc15/summary.json
```

（両 host の `out/<RUN_ID>` は数値 JSONL だけなので 1 か所に集めてよい。`--role main` /
`--role agent` の記録が含まれていれば `--two-host` を付けなくても 2 host として扱い、host 間の
時計比較は行いません。）

2 host の制約（時計比較をしない代償）: Main 側の停止・再起動（G5 の Agent 検知）と Main の
stale 閾値以上の blackhole（G5 の Main `interrupted`）は、各 window と検知記録を時刻で対応付け
られないため、**件数だけ**を `min(検知 episode 数, window 数)`（blackhole は source ごと）で
照合します。どの検知がどの window のものかは確かめず、余分な検知（例: 別の切断で出た episode）が
検知されなかった window の分を埋めうる。遅延の上限は各 episode の自 host 時計内の値
（Agent の `idle_ns`、Main の `since_last_rx_ns`）≤ 15 s だけで確かめます。window ごとの
対応は 1 host（loopback）の run でだけ確かめられ、2 host の結果を転記するときはこの制約を
併記してください。

summary の各 run 行と候補行には `fast`（CI 用の短縮 timing で実行したか）が出ます。候補行の
`fast` は 1 run でも短縮 timing なら `true`、全 run が full timing のときだけ `false`
（`fast_runs` は短縮 timing の run 数）。ADR-0007 へ転記する結果は全 run が `fast: false`
（`--fast` なし）でなければならない。

候補ごとの G1〜G6 は、その gate に必要な scenario（G1: `auth_*` 4 種 + `route_probe`、
G2: `normal` / `capture_restart` / 通信断 7 種、G3: `normal` / `slow_drain` / `bandwidth_cap` /
`outage_120s` / `slow_stop_60s` / `capacity_4`、G4: 切断 6 種、G5: 通信断 7 種、G6:
`capacity_4` / `fifth_refused`）が全部そろって初めて `pass` になり、欠けていれば `unmeasured`
（どれかが `fail` なら `fail`）です。さらに G2 / G3 / G6 は、1 / 2 / 3 / 4 source の各構成が
少なくとも 1 run ずつ完全な実行として記録されていること（orchestrator と sender の申告 source 数が
一致し、その数の source が durable stand-in に到達）が必要で、欠けた構成があれば `unmeasured`
（summary の `<gate>_missing_source_counts`）です。既定の matrix（`--sources 1`）は `normal`（1）/
`sources_2` / `sources_3` / `capacity_4` で 4 構成を測ります。`--sources` を変えると `normal` 等の
source 数も変わるので、既定のまま実行してください。

各 run は、1 回の実行の完全な記録でなければ判定に使いません（`integrity`）。merge した全記録の
`run_id` が 1 種類、side（`both`、または `main` と `agent`）ごとに orchestrator の `start` と `end`
が 1 つずつ、起動した子 process（`spawn`）ごとに exit code 0 の `exit`、process ごとに開始と完了の
記録（receiver / proxy は `ready` と `end`、sender は `start` と `metric`）が起動数と同数であること。
違反（別実行の記録の混入、同じ `run_id` での再実行の追記、子 process の異常終了、orchestrator の
途中終了）は全 gate `fail`、片側の記録や process file の欠落、両側の入力申告の不一致、orchestrator
`start` の source 数・`fast`・`duration_ns`・scenario・candidate のどれかの不一致は `unmeasured`
になります。

media を流す scenario（否定認証と `route_probe` 以外）では、各 source が run の間ずっと生成し続けた
ことも `integrity` の条件です（`production`）。durable unit が 1 つ届いただけでは source を
「exercised」とは数えません。sender は producer（`gst-launch` の EOF、holder socket の EOF、
producer thread の例外）が run 途中で終わると `producer_failed` を記録して停止し、非 0 で終了します。
summarizer は `producer_failed` があれば `fail`、さらに sender の `end`（source・epoch ごと、sender
時計）で、`generated` ≥ 0.8 × 申告 fps ×（生成時間 − 3 s）、最初の unit が生成開始から 3 s 以内、
unit 間の最長空白と最後の unit から生成終了までが 2 s 以内、source ごとの生成時間の合計が予定
duration −（epoch 数 × 2 s）以上であることを要求し、満たさなければ `fail`（記録が無ければ
`unmeasured`）です。実 camera では申告 fps（`--fps`）を camera profile と一致させてください。
低照度で camera の frame rate が下がった run は、連続生成として扱われず `fail` になります。
`--holder` を渡すと holder の `queue_drops` = 0 と
`forward_drops` ≤ sender process 数（real 入力の run 数 + `restart_sender` 数）も判定します。

| gate | 判定 |
| --- | --- |
| G1 | mTLS 相互認証。否定試験（未 activation / 別 CA / 失効 / 接続中失効）で受理 media 0、`route_probe` は 404 か切断。未 activation / 別 CA / 失効は sender の接続試行 ≥ 1 と Main 側の認証拒否記録（`auth_refused`、`connection_limit` を除く）が両方必要で、sender 記録が無ければ `unmeasured`、試行か拒否記録が無ければ `fail`。接続中失効は Main 側 orchestrator の `revoke` 記録（無ければ `unmeasured`）、receiver の `revoked`、その後の receiver sample ≥ 1（無ければ `unmeasured`）がすべて `revoked` 時点の受理数と一致、`revoked` 後の再接続拒否（Main の `auth_refused`、1 host では sender の `connect` も可）が必要 |
| G2 | sender の `start` と `end` 記録が必要（否定認証と `route_probe` 以外。無ければ `unmeasured`）。epoch 内の報告 gap = durable stand-in から算出した実欠落（完全一致）。実欠落は epoch の起点（sequence 0）から数え、最初の durable unit より前の欠落も含む（capture 再起動後の epoch の先頭は範囲不明 gap）。Agent が受理を得た epoch に durable 記録が無ければ不一致。capture 再起動は範囲不明 gap、重複 commit 0。さらに sender の `end`（source・epoch ごとに `generated` / `drops` / `drops_sent` / `residual` / `residual_sent` / `unit_ranges`）と `unit_range` 記録（drop / 拒否 / 終了時保持の sequence 範囲）で Agent 側の unit 収支を照合する: 最後の durable sequence より後の unit（backpressure で末尾が落ちると Main には gap が出ない）は、その sequence より**後**の drop / 拒否 / 保持中（`residual`）の unit と 1 対 1 で一致しなければ `fail`（記録の無い消失。例: Main が ack した後に失った末尾。epoch 途中の drop・拒否は Main の gap として報告済みなので末尾の説明に使わない）、それ以前の `drops` は Main がその epoch で報告した gap（送信後未 ack の unit は Main が持ちうるので余裕に含める）に収まらなければ `fail`（説明のつかない drop）、範囲と件数が食い違えば `fail`、`end` に収支や範囲が無い・durable 記録のある epoch に `end` が無いなら `unmeasured`。最後の receiver が停止時に受理済み unit を破棄した（`end` の `discarded_at_stop` > 0。後続の receiver が gap を報告できない）場合も `fail`。末尾の drop 数は `agent_accounted_tail_units`（Agent 側で計上した欠落） |
| G3 | receiver と sender の両方の sample が必要（片方でも無ければ `unmeasured`）。receiver queue ≤ 設定上限、sender pending ≤ 上限、kernel send queue の滞留 byte（`TIOCOUTQ`、`ss -tmi` があれば skmem `w`）≤ 2×SO_SNDBUF + 64 KiB、VmHWM ≤ 上限、warmup 後の RSS 増加 ≤ max(16 MiB, 10 %)（sample < 4 なら `unmeasured`）。skmem `tb` は送信 buffer の上限値で、SO_SNDBUF 設定前に kernel が拡大しうるため記録のみ。実入力の run で `ss` が無い（socket を 1 つも報告した sample が無い）なら `unmeasured`。proxy 保持量は 1 回の `recv()` buffer で構造的に有界なので記録のみ |
| G4 | 切断を伴う impairment から手動操作なしで再接続、p95 ≤ 10 s（2 host で Main 側 action の場合は Agent 時計で切断→初回受理。初回受理を挟まない連続した切断は 1 episode）。切断と初回受理は impairment ごとに 1 組ずつ対応させ（同じ記録を複数回使わない）、必要な再接続数は予定された reset / Main 再起動と、Agent loss timeout + 1 s 以上の blackhole / SIGSTOP の数だけで決まる（scenario 名による追加要求はない） |
| G5 | 無音断の検知 ≤ 15 s（Agent / Main とも）、Main の未 commit 区間（Agent capture 時刻）⊆ Agent 保護区間 [T−600 s, T+600 s]。proxy blackhole は予定数の `impairment_start` 記録が必要（`proxy.jsonl` が無ければ `unmeasured`、不足は `fail`）、Main の stale 閾値以上の blackhole には source ごとに Main の `interrupted`（最後の受信から ≤ 15 s）が必要。Main 側停止（`slow_stop_10s` / `slow_stop_60s` / `main_restart`）は停止ごとに Agent の loss 検知が必要で、遅延は Agent 時計で最後の受信からの経過（`idle_ns`）≤ 15 s。Main 側 orchestrator 記録が無ければ `unmeasured`。予定された proxy reset はそれぞれ Agent 時計で 15 s 以内の `loss_detected` が必要（`proxy.jsonl` が無ければ `unmeasured`）。`loss_detected` は source ごとに出るが connection 単位で 1 episode とし、reset / 長い blackhole ごとに別の episode を 1 つずつ消費する（1 回の検知を 2 つの reset に使わない）。対応づけの範囲は [impairment 開始, min(開始 + 15 s, 次に予定された impairment の開始)) で、後の impairment の後に出た検知は前の impairment の検知として数えない（最後の impairment は開始 + 15 s まで）。1 host の Main 側停止と Main の `interrupted` の照合も同様に次の window の開始で打ち切る。Main の `interrupted` は最後の `session_close` 以前のものだけを数える（sender 終了後の stale 判定は障害検知ではない） |
| G6 | 4 source で backpressure / rate limit / sender drop 0（4 source すべての sender `end` 記録が必要、1 つも無ければ `unmeasured`）、かつ Main / Agent とも cgroup v2 `cpu.max` の CPU 上限下で実行（`capacity_4`、上限が無ければ `fail`）。5 source 目は active-source 上限（`source_capacity`）で拒否 |
| 副次 | soak 30 分で予期しない切断 0、overhead ≤ 10 %（proxy の上り byte / payload）、実カメラ passthrough 1 台あたり Agent CPU ≤ 1 core の 50 %（最初の sample からの差分で算出）、latency p95 ≤ 1 s（参考） |

すべての比較は 1 host の時計内、または envelope の Agent capture 時刻と Agent 自身の
loss 時刻の比較だけで行い、host 間の時計差を使いません。

## Cleanup checklist（毎日の終了時と PoC 終了時）

- [ ] `systemctl --user stop 'ss-poc15-*'`、`systemctl --user list-units 'ss-poc15-*'` が空
- [ ] `ss -ltnup '( sport >= :47200 and sport <= :47214 )'` が空（両 host）
- [ ] Main: `$R`（使い捨て CA 秘密鍵・ledger）と `--state` を削除
- [ ] capture host: `~/poc15/nodes`（node 鍵）、holder の state・socket directory を削除（holder の camera 承認も消える）
- [ ] 残すのは数値 JSONL / summary だけ。private な値（IP、hostname、serial、path）が無いことを確認
- [ ] `git status` に PoC 出力が無い（ハーネスは repository 内 path を拒否する）
- [ ] system 設定・firewall・Tailscale・udev は一切変更していないことを確認
