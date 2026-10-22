# Issue #15 Agent–Main media transport PoC 計測ハーネス（手動試験専用）

このディレクトリは Issue #15 / ADR-0007 の transport 比較を **同じ決定的 impairment
matrix と同じ Main 側判定** で測るためのハーネスです。製品ではありません。
`server/` と `agent/` の package はここを import せず、release artifact にも含めません。
**本 README の実機手順は測定として一度も完了していません**（PR 時点の確認は loopback の
synthetic 実行のみ。2026-10-20 に 2 host の smoke 1 run を手動 hand-off で行ったが、同じ run id で
agent 側を 2 回起動したため integrity `fail` で、測定には数えない。MANUAL_TEST §G 参照）。
`schedule`（下記）は 2026-10-20 に実機で 1 日目を実行したが、real camera の slot は holder の起動拒否で
未実行（MANUAL_TEST §G）。holder の信頼検査の preflight は mock でのみ試験済みです。
実機の結果は `MANUAL_TEST.md` §G の記録テンプレートと
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
**Main host の firewall（Owner の root 作業）**: Main host の firewall（例: ufw の default deny）は
PoC の期間だけ、capture host からの receiver port 47200–47201/tcp **だけ**を許可する必要があります。
ハーネス自身は firewall を一切変更しません。規則の追加と削除は Owner が root で行い（例:
`sudo ufw allow proto tcp from <CAPTURE_LAN_IP> to <MAIN_LAN_IP> port 47200:47201` と、終了時の
`sudo ufw delete allow proto tcp from <CAPTURE_LAN_IP> to <MAIN_LAN_IP> port 47200:47201`）、
送信元を capture host の IP literal に限定します（範囲や `any` にしない）。削除は下の cleanup
checklist に含まれます。

receiver は product の bind 検証を通した上で `SO_REUSEADDR` 付きで bind します（product の
`open_ingest_listener` には無く、TIME_WAIT 中の Main 再起動で再 bind できないため。product 側の対応は
Issue #223 で追跡）。

## 安全規則

- Main host は production（GPU benchmark が同居）。Main 側は必ず
  `CUDA_VISIBLE_DEVICES=` と `systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=1G`
  + `nice -n 10 ionice -c 3` + `timeout -k 30 <上限>` の下で動かす。scope 名は `ss-poc15-*`。
- ハーネスと PoC の実行手順は sudo / root / `tc` / firewall 変更 / Tailscale 設定変更をしない（上の
  firewall 許可規則は Owner が PoC の前後に別途 root で追加・削除する）。Main から capture host へ
  SSH しない（`schedule` も host 間通信をしない）。
- 1 日の合計実行は **3 時間まで**（scenario 長の合計 + 起動・停止の余裕。`timeout` は暴走時の
  上限）。soak は下の「soak の上限」の通り、上限値の 1 run 45 分で数える。
- `--materials` / `--state` / `--out` / holder の state・socket は repository の外の 0700 directory
  （ハーネスは repository 内の path を拒否）。
- 実カメラ frame は holder → sender の unix socket（0700 directory 内）経由で memory 上のみ。
  映像を見る・保存する操作はしない。実在人物が映る場合は撮影範囲に人がいない時間に行う。
- 緊急停止（kill switch）: 両 host で `systemctl --user stop 'ss-poc15-*'`（`schedule` を
  `ss-poc15-schedule` scope で動かしていれば scheduler 自身も止まり、以後の slot は起動しない）。
  `timeout -k` は二重の上限です。

## Step 0: read-only inventory（変更なし）

両 host で、値は手元記録にだけ残し、repository には粗い値（版数、core 数など）だけ書く。

```sh
uname -r; nproc; free -m; python3 --version
systemd-run --version | head -1; systemctl --user is-system-running
ss -ltnu '( sport >= :47200 and sport <= :47214 )'   # 何も表示されないこと
command -v ss gst-launch-1.0
cat /sys/fs/cgroup/user.slice/cpu.max 2>/dev/null
timedatectl show -p NTPSynchronized --value   # schedule を使う場合は両 host で yes
```

capture host のみ（実カメラ時）: `id -nG` に `video` があること、`ls /dev/video* | wc -l`
（件数だけ）、Landlock 有無（MANUAL_TEST §B の記録と同じ方法）。

capture host へハーネスの source（この checkout の export。例 `~/poc15/src`）を渡すときは、group /
other が書き込めない mode にします。holder は sandbox helper（`--dev-checkout-helper` の場合も
「本人所有かつ他者書込不可」）とその親 directory に group / other の書込権限があると起動を拒否します
（2026-10-20: `git archive` の既定 `tar.umask` 002 で 664 / 775 になった tarball を umask 002 の
一般ユーザーで展開し、real slot の holder がすべて `sandbox helper is writable by others` で終了）。

```sh
git -c tar.umask=022 archive --format=tar.gz -o poc15-src.tar.gz HEAD   # Main（export 側）
chmod -R go-w ~/poc15/src                 # capture host（展開後。umask に依らず必ず実行）
find ~/poc15/src -perm /022 | wc -l       # 0 であること
```

`schedule --role agent` は real slot がある時刻表なら slot 0 の前に holder と同じ起動時の信頼検査
（`GStreamerLauncher` の構築: interpreter・sandbox helper・GStreamer 本体と plugin・Landlock。
カメラは開かず GStreamer も起動しない）を行い、失敗すれば理由を表示して slot を 1 つも起動せず
非 0（1）で終了します。

## Step 1: 使い捨て materials

Main（`R=~/poc15/materials` など repository 外。ハーネスは親 directory を作らないので先に作る）:

```sh
install -d -m 700 ~/poc15
python3 scripts/manual/transport_poc/poc15.py materials init --root "$R" --negatives-only
```

capture host（正規 node の鍵は capture host から出さない。`node-key` は `--root` の親 directory を
作らないので、先に private な親 directory を作る。無いと `FileNotFoundError`）:

```sh
install -d -m 700 ~/poc15 ~/poc15/nodes
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

両 host で、無ければ先に state / out の private directory を作る（`--state` / `--out` の親は
ハーネスが作らない）:

```sh
install -d -m 700 ~/poc15 ~/poc15/state ~/poc15/out
```

### loopback synthetic（1 host、CI と同じ形）

```sh
CUDA_VISIBLE_DEVICES= timeout -k 30 90m systemd-run --user --scope --unit=ss-poc15-loop \
  -p CPUQuota=200% -p MemoryMax=1G nice -n 10 ionice -c 3 \
  python3 scripts/manual/transport_poc/poc15.py matrix --materials "$R" --state ~/poc15/state \
  --out ~/poc15/out --summarize            # --fast で短縮版
```

### 実機 2 host（1 scenario ずつ、同じ `--run-id`）

`--role main` / `--role agent` は 1 回の起動で scenario 1 つ・候補 1 つだけを受け付け、複数を指定すると起動時に拒否します（複数 run を続けると capture 側が前の run の receiver へ接続しうるため）。

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
  --candidates a_framed --scenarios outage_8s --run-id <RUN_ID>
```

`--real-inputs` は capture host が holder（実カメラ）を使う run では Main 側にも必ず付け、
synthetic（`--source-kind gst` / `builtin`）の run では両側とも付けない。集計は片側でも
`real` と記録されていれば real として判定し（`ss` 必須、holder の Agent CPU を加算）、
両側の申告が食い違う run は `unmeasured` にします。sender と `matrix`（agent / both 側）は
`--real-inputs` を `--source-kind holder` 以外と組み合わせると起動時に拒否します。集計でも、
real と申告された run は全 sender `start` が `source_kind` = `holder`・`inputs` = `real`・
holder session nonce（sender 起動ごとに異なる乱数）を持たなければ `integrity` = `fail`
（申告だけで real にはならない）です。

capture host（実カメラ。holder は 1 process で全カメラを保持）。holder の `--out` の親 directory
は holder 起動前に作る（holder は作らない）。holder は run ごとに 1 つ起動し、記録は run ごとの
別ファイル（`holder-<RUN_ID>.jsonl`、agent と同じ `--run-id`）にする（記録は追記されるので、
同じファイルを別の run で再利用すると集計で `fail`）:

```sh
install -d -m 700 ~/poc15/out
timeout -k 30 20m systemd-run --user --scope --unit=ss-poc15-holder -p CPUQuota=100% -p MemoryMax=512M \
  python3 scripts/manual/transport_poc/poc15.py holder --state-dir ~/poc15/holder-state \
  --socket-dir ~/poc15/holder-sock --sources 1 --profile 1280x720@30 --approve \
  --seconds 1100 --out ~/poc15/out/holder-<RUN_ID>.jsonl --run-id <RUN_ID>
timeout -k 30 15m systemd-run --user --scope --unit=ss-poc15-agent -p CPUQuota=100% -p MemoryMax=512M \
  python3 scripts/manual/transport_poc/poc15.py matrix --role agent --upstream-host <MAIN_LAN_IP> \
  --node-root ~/poc15/nodes --materials ~/poc15/nodes --state ~/poc15/state --out ~/poc15/out \
  --source-kind holder --holder-socket ~/poc15/holder-sock/frames.sock --real-inputs \
  --candidates a_framed --scenarios outage_8s --run-id <RUN_ID>
```

開発 checkout の sandbox helper は root 所有ではないため、MANUAL_TEST §B の前例と同じく
`--dev-checkout-helper`（helper ファイルだけ「本人所有かつ他者書込不可」を要求し、
GStreamer 本体と plugin は root 管理を要求）を付けたときだけ holder が起動します。
synthetic MJPEG は `--source-kind gst`（`videotestsrc is-live=true ! video/x-raw,width=1280,height=720,framerate=30/1 ! jpegenc`）、
または `builtin`（生成バイト列）です。`--real-inputs` は holder 使用時だけ付け、1〜4 source の
real / synthetic の内訳を記録に明記します。

`--role agent` の `--materials` は capture host 側では使われない（node bundle は `--node-root`）。

### 実機 2 host の時刻指定実行（`schedule`、手動 hand-off なし）

1 scenario ずつの手動 hand-off（Main の `ready` を見て 10 秒以内に capture host を起動）を
約 60 回繰り返すと起動の重複や取り違えが起きやすいため（2026-10-20 の smoke run は同じ run id で
agent 側を 2 回起動して integrity `fail`）、`poc15.py schedule` で両 host が同じ時刻表に従って
自動で起動します。1 slot の中身は上の手動手順と同じ単一 scenario・単一候補の `matrix --role`
（同じ scope 名 `ss-poc15-main` / `ss-poc15-holder` / `ss-poc15-agent`、同じ CPU / memory 上限、
Main は `nice` / `ionice` と `CUDA_VISIBLE_DEVICES=` 空）で、run 自体の動作は変わりません。
scheduler は `systemd-run` に `--collect` を付けます（OOM などで failed になった scope を残さず、
次の slot が同じ scope 名を使えるようにする。前の scope が動作中なら同名の scope は作れないので、
slot の重複起動は従来どおり拒否される）。

- 両 host で `--role` 以外を同じにする: `--start`（UTC、例 `2026-10-21T01:00:00Z`。過去と
  24 時間より先は拒否）、`--candidates`、`--scenarios`（既定は soak と `auth_revoked_live` を除く
  既定 matrix の 19 scenario）、`--real-camera`。各 host はこの引数だけから同じ時刻表を計算し、
  host 間で通信しない（SSH なし）。
- 時刻表: slot 0 は `--start`、slot i+1 は slot i の開始 + scenario の full 長 + 90 s。順序は
  `matrix` と同じ（候補ごとに scenario 順）。各 slot の run id は slot の開始時刻
  （`r` + UTC `YYYYMMDD` + `t` + `HHMMSS`）で、両 host で一致する。開始時刻の比較に両 host の
  wall clock を使うので、両 host とも NTP 同期済み（Step 0 の `timedatectl`）であること。測定値は
  従来どおり 1 host の時計内だけで比較します。
- 余裕 90 s の理由: Main の orchestrator は scenario 長 + receiver 起動 + `--main-grace` 20 s +
  receiver 停止（最大 15 s）で約 scenario 長 + 37 s かかる。各起動は slot 開始から scenario 長 +
  55 s の `timeout -k 30` で上限を付けるので、暴走して SIGKILL が要る run も slot 開始 + scenario 長
  + 85 s までに必ず終わり、次の slot の receiver の bind・Agent の接続と重ならない（60 s では通常の
  run の余裕とこの上限を両立できない）。
- 入力: `--real-camera` を付けると、1 source で media を流す scenario（`normal`、通信断・停止・
  再起動・`bandwidth_cap`・`slow_drain`、`soak`）は capture host が slot 開始時に holder（上と同じ
  scope・上限、`--approve`、run ごとの `holder-<RUN_ID>.jsonl`）を起動し、両側に `--real-inputs` を
  付けます。2〜5 source の scenario、否定認証、`route_probe` は `--source-kind gst`（synthetic）で
  `--real-inputs` なし。`--real-camera` なしでは全 slot が `gst`。
- capture host は slot 開始 + 5 s に agent を起動する（Main はそれまでに `ready`）。real の slot で
  その時点に holder が終了している、または holder socket（slot ごとの
`<--holder-socket-dir>/<RUN_ID>/frames.sock`。SIGKILL / OOM で終わった holder の socket が後の slot の
bind を妨げないよう slot ごとに別 directory にし、空になった directory だけ消す）が無ければ、agent を
  起動せずその slot を失敗として記録する（sender は holder socket に再接続しないため）。agent の
  終了後に holder を SIGTERM で止め（15 s で終わらなければ SIGKILL）、holder の終了コードも slot の
  結果に含める。
- fail-closed: slot は重ならない（各 slot は自分の process の終了を待つ）。前の slot が延びて次の
  slot の開始を 5 s より過ぎた場合は schedule 全体を非 0（3）で止め、以後の slot は起動しない
  （相手 host の run は接続できずに失敗し、記録に残る）。この場合は両 host で kill switch を
  使って止める。slot の失敗（非 0 終了）では時刻表はずれず、次の slot は予定どおり起動する
  （schedule の終了コードは 1）。SIGINT / SIGTERM では実行中の slot の process を止め、以後の slot は
  起動しない（終了コード 130）。
- 既存の記録を上書きしない: 時刻表のどれかの run id の `--out/<RUN_ID>` または
  `holder-<RUN_ID>.jsonl` が既にあれば起動しない（同じ `--start` の再実行は記録が追記されて
  integrity `fail` になるため、新しい `--start` を選ぶ）。
- 1 日 3 時間上限: 時刻表の合計（最後の slot の終わりまで）が 3 時間を超える schedule は拒否します
  （既定 matrix は 1 候補 1 時間 3 分 30 秒、2 候補 2 時間 7 分、3 候補 3 時間 10 分 30 秒で拒否）。
  scheduler が数えるのは自分の時刻表だけなので、同じ日の手動 run（`auth_revoked_live` など）も
  合わせて 3 時間以内に収める。

日程の分け方（例）:

| 日 | 内容 | 合計 |
| --- | --- | --- |
| 1 日目 | `schedule --candidates a_framed,b_chunked` | 2 時間 7 分 |
| 2 日目 | `schedule --candidates b_segment` + 3 候補の `auth_revoked_live`（候補ごとに新しい `revoked_live` bundle で手動実行） | 約 1 時間 20 分 |
| 別の日 | soak: `schedule --candidates a_framed,b_chunked,b_segment --scenarios soak` | 1 時間 34 分 30 秒 |

`auth_revoked_live` は実行のたびに `revoked_live` の bundle を作り直す必要があるため（Step 1）、
`schedule` は指定を拒否します。上の手動 2 host 手順で 1 run ずつ実行してください。

まず両 host で `--print`（時刻表を表示して終了。何も起動しない）を実行し、時刻表が一致することを
確かめます（1 行目は role を含むので 2 行目以降を比べる。例:
`... --print | tail -n +2 | sha256sum` が両 host で同じ）。

Main:

```sh
S=2026-10-21T01:00:00Z   # 両 host で同じ値
systemd-run --user --scope --unit=ss-poc15-schedule -p CPUQuota=20% -p MemoryMax=256M \
  python3 scripts/manual/transport_poc/poc15.py schedule --role main --start "$S" \
  --candidates a_framed,b_chunked --real-camera \
  --bind <MAIN_LAN_IP> --materials "$R" --state ~/poc15/state --out ~/poc15/out
```

capture host:

```sh
S=2026-10-21T01:00:00Z
systemd-run --user --scope --unit=ss-poc15-schedule -p CPUQuota=20% -p MemoryMax=256M \
  python3 scripts/manual/transport_poc/poc15.py schedule --role agent --start "$S" \
  --candidates a_framed,b_chunked --real-camera \
  --upstream-host <MAIN_LAN_IP> --node-root ~/poc15/nodes --state ~/poc15/state --out ~/poc15/out \
  --holder-state-dir ~/poc15/holder-state --holder-socket-dir ~/poc15/holder-sock \
  --dev-checkout-helper
```

scheduler は開始前に時刻表を表示し、slot ごとに 1 行（slot 番号、run id、scenario、候補、
real / synthetic、終了コード。capture host の real slot は holder の終了コードも）を出します。
scheduler 自身は待機が主で、各 slot の process は上の scope に移るので、`ss-poc15-schedule` の
上限は scheduler だけに掛かります。`--dev-checkout-helper` は holder へそのまま渡します（下記）。
終了後の集計は両 host の `~/poc15/out` を 1 か所に集め、Step 3 の `summarize --two-host` に全 run
directory と全 `holder-<RUN_ID>.jsonl` を渡します。

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
`schedule` では各 slot の `timeout` 上限と holder の `--seconds` を scenario 長から自動で決める
（slot 開始から scenario 長 + 55 s、holder は scenario 長 + 45 s）ので、上の 45 分 / 2700 s の値は
手動実行用です。schedule の 3 時間上限は時刻表の合計（soak 1 run = 31 分 30 秒）で数えます。
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
| `outage_1s` / `outage_8s` / `outage_120s` | proxy blackhole（無音の読み停止）1 s×3 / 8 s×3 / 120 s×1（`--fast` の `outage_8s` は 4 s×1。`outage_8s` は Agent loss timeout + 2.5 s 以上で、どの候補も loss を検知する長さ。旧 `outage_5s` は timeout と同じ 5 s で、検知が偶然に左右された。#308） |
| `rst` | 全接続を RST ×3 |
| `bandwidth_cap` | 公称 bitrate の 50 % へ 180 s 制限 |
| `slow_stop_10s` / `slow_stop_60s` | Main receiver を SIGSTOP 10 s / 60 s（`--fast` は 4 s / 5 s。どの停止も Agent loss timeout + 2.5 s 以上で、b_segment でも Agent が loss を検知する長さ。#237） |
| `slow_drain` | durable stand-in の消費を公称の 50 % に制限 |
| `main_restart` / `capture_restart` | receiver の異常停止（SIGUSR1: 未永続の queue を破棄）→ 再起動（durable watermark から再開）/ sender 再起動（epoch 前進）。通常終了（SIGTERM）の receiver は受理済み queue を永続化してから終了 |
| `capacity_4` / `fifth_refused` | 4 source 無 backpressure / 5 source 目の拒否 |
| `auth_unpaired` / `auth_other_ca` / `auth_revoked` / `auth_revoked_live` | 否定認証（受理 media 0）/ 接続中 revoke |
| `route_probe` | ハーネスの ingest receiver が human route（`GET /api/...`）を返さないこと（この run の receiver が probe の session nonce を記録していること）。製品の human/admin API や capture credential の権限は確かめない（製品側は MANUAL_TEST §G の該当項目で確認） |
| `soak` | 30 分（`--scenarios soak` で明示時のみ） |

## Step 3: 集計と判定

```sh
python3 scripts/manual/transport_poc/poc15.py summarize --two-host MAIN_OUT/<RUN_ID> AGENT_OUT/<RUN_ID> \
  --holder AGENT_OUT/holder-<RUN_ID>.jsonl --json ~/poc15/summary.json
```

（両 host の `out/<RUN_ID>` は数値 JSONL だけなので 1 か所に集めてよい。`--role main` /
`--role agent` の記録が含まれていれば `--two-host` を付けなくても 2 host として扱い、host 間の
時計比較は行いません。）

接続ごとの session nonce: sender は接続ごとに乱数の session nonce（63 bit、0 以外）を作り、
接続の最初の frame（`HELLO`。`b_chunked` は最初の chunk、`b_segment` は最初の segment の先頭）で
送ります。receiver はそれを `session_hello`（と `session_close` の `session`）に、sender は
`connect` / `connected` / `closed` / `loss_detected` / `first_accept` / `route_probe` に記録します。これで
時計を比べずに Agent 側の接続と Main 側の session を対応付けます。

- `route_probe`: probe も自分の nonce を運び（`a_framed` は `HELLO` の後に HTTP request、
  `b_*` は `X-Poc15-Session` header）、この run の receiver がその nonce の `route_probe` 拒否
  記録を残していなければ G1 は `fail`（同じ address の古い・無関係な listener が 404 や切断を
  返しても pass しない）。nonce の無い古い probe 記録は `unmeasured`。
- 2 host の Main 側停止・再起動（G5 の Agent 検知と G4 の再接続）: Main 時計で各 window の開始
  （orchestrator の `sigstop` / `restart_receiver`）に live だった session（`session_hello` が
  開始以前、`session_close` と receiver の `end` が開始以後）を求め、各 window にそのうち 1 つの
  session の Agent `loss_detected` episode を 1 対 1 で割り当てます（同じ episode を 2 つの window
  に使わない）。window の前に閉じた別接続の偶発的な切断は割り当てられません。停止・再起動を
  生き延びた接続の後の無関係な切断も割り当てられません: 候補 session は Main 時計で window 終了
  + 15 s + 5 s（`SESSION_CLOSE_GRACE_NS`）以内に終わっていること（`session_close`、receiver の `end`、または orchestrator の
  receiver `exit`）、かつ Agent がその接続で最後に受け取った heartbeat echo（`loss_detected` /
  `closed` の `last_echo_ns`）が、receiver が window の cutoff（window 開始、または下記の
  `stopped` / `stopping` で示せる Main の応答停止時刻）以後にその session で返した echo
  （`heartbeat_ack` の `echo_ns`、Main 時計の `sent_ns` 付き。receiver は応答を socket に書き終えた後に
  記録し、送信に失敗した応答は記録しない）のどれよりも古いこと（= 停止後の Main の
  応答を Agent が受け取っていない）。echo 値は Agent 時計の値で echo 同士でしか比べず、
  `heartbeat_ack` の時刻は Main の window とだけ比べます。SIGCONT 後に receiver が読み出す
  kernel buffer 上の滞留分（Agent が切断前に送ったもの）は証拠に使いません。`last_echo_ns` の無い
  古い記録、または Agent がある session で最後に受けた echo がその session の `heartbeat_ack` に
  無ければ `unmeasured`。
  生き延びて除外された session 数は `main_outage_survivors`。遅延は割り当てた
  episode の `idle_ns`（Agent 時計）≤ 15 s。session nonce や echo 番号の記録が無く対応付けられなければ
  `unmeasured` ですが、対応付けなしでも記録から失敗と分かる場合は先に `fail` にします（#237）:
  G5 は Agent の loss episode が Main の window より少ない、または `idle_ns` が 15 s を超える episode が
  ある場合、G4 は再接続が必要な window（予定の再起動、または loss timeout + 1 s 以上の SIGSTOP）の
  終了以後に Main が `session_hello` を 1 つも受けていない場合（window ごとに別の HELLO を数える）。
  `session_hello` を 1 つも記録していない古い receiver 記録は `unmeasured` のままです。
- 2 host の G4 再接続時間（#237）: 1 host と同じく window 終了からの時間で、Main の停止時間は
  含めません（以前は Agent 時計の `closed` → 後続接続の初回受理を測っていたため、`slow_stop_60s`
  では 60 s の停止がほぼ丸ごと入り、p95 ≈ 55 s の false FAIL になる。この値は #237 の記録解析によるもので、
  2 host の実測ではない）。時計を比べずに、
  後続接続 s について (Main 時計: window 終了 → s の `session_hello`) + (Agent 時計: s の
  `connected`（TLS handshake 完了、HELLO 送信前）→ s の `first_accept`) を求めます。`connected` は
  HELLO の送信より前、送信は Main の受信（`session_hello`）より前なので、和は真の「window 終了 →
  初回受理」より HELLO の片道遅延の分だけ大きく、小さくはなりません（false PASS にならない）。
  s は window 終了以後に Main が HELLO を受けた、受理のある後続接続のうち最も早いもの（それより
  後の接続を選んでも値は大きくなるだけ）で、各接続は 1 回だけ使います。Main が window 終了前に
  受けた HELLO は再接続に数えません。SIGSTOP では、orchestrator が SIGCONT を送ってから `sigcont` を
  記録するまでの間に receiver が HELLO を受けることがあり、その接続も除外されて、より後の接続で
  測ります（値は大きくなる側で、受理のある後続接続が他に無ければ `fail`）。`connected` の無い古い
  記録は `unmeasured`。
- heartbeat 応答の記録と停止の協調（#237）: receiver は応答の書き込みと `heartbeat_ack` の記録を
  1 つの lock の下で行い、SIGUSR1 / SIGTERM の停止要求も同じ lock を取ってから `stop` を立てます。
  これで「`stop` の確認後に停止が来て応答が出る」「`sendall()` が戻った後、記録の前に停止が来る」の
  どちらの競合も無くなりました。`heartbeat_ack` は `sendall()` が戻った Main 時刻 `sent_ns` を持ち、
  summarizer はこれを使います（古い記録は記録時刻 `t_ns`。どちらも Agent が受け取りうる時刻より
  早くはならない）。receiver は終了時に `stopping`（`stop_ns`、`abrupt`、`coordinated`）を記録し、
  orchestrator は SIGSTOP の後に `/proc/<pid>/stat` で停止状態を確認できたら `stopped` を記録します。
  orchestrator は action を記録してから signal を送るので、その間に書かれた応答は window 開始後でも
  生存の証拠になりません。そのため「Main が応答をやめた時刻」（cutoff）は、window 内の `stopped`
  （SIGSTOP）または再起動で止まった receiver の協調済み `stopping` の `stop_ns`（`abrupt` かつ
  `coordinated`）があればその時刻、無ければ window 開始のままです（証明が無ければ従来どおり保守的）。
  lock を 2 s 以内に取れなかった停止は `coordinated: false` で、その後に完了した応答も後の `sent_ns`
  で記録されるため、生存判定は保守側に倒れます。
- 応答に echo を必ず含める（#237）: Agent の送信 backlog が 256 KiB 以上だと heartbeat が backlog の
  後ろに並び、SIGCONT 後の Main の返信が media ACK だけになりえます（Agent はそれで受信ありとして
  生き延びるのに、最後の echo は停止前のまま）。receiver は、その session で heartbeat を受けたことが
  あり、0.5 s（`ECHO_REPEAT_S`）以上 echo を書いていない返信に、最新の echo を付け直して記録します。
  付け直した echo は返信の先頭に置きます（heartbeat 応答も各返信の先頭）。`a_framed` / `b_chunked` では、
  Agent が返信の一部でも受け取れば、その frame も受け取っています（stream は順序どおりで、TLS record
  は丸ごと届く）。`b_segment` の sender は response body を全部読んでから frame を解釈するので、一部だけ
  読んだ response は数えません（その byte でも Agent の read timeout は延びます）。そのため `b_segment`
  の数は、全部読んだ response の分だけです。
  これで停止後の最初の返信は必ず echo を運び、生き延びた session は `answered` として除外されます。
  ただし付け直した echo は古い値なので、値だけでは Agent が受け取ったかどうかが分かりません。たとえば
  SIGCONT 後に、Agent が切断前に送った kernel buffer 上のデータへ返信した場合、Agent はもう読んでいない
  のに、Agent の最後の echo と同じ値が記録されます。そこで receiver は各 session の `heartbeat_ack`
  frame に書き込み順の番号 `index`（1 から）を付け、sender は接続ごとに受け取った frame 数
  `echo_frames` を `loss_detected` / `closed` に記録します。Agent が受け取ったのは frame 1..k
  （k = `echo_frames`）ちょうどなので、そのどれかが cutoff 以後に書かれていれば `answered` です。
  次のどれかに当たる場合は `unmeasured` です。
  - 1..k のどれかが Main の記録に無い
  - `echo_frames` が無い、整数でない、または負
  - Main の応答に `index` が無い
  - frame 1..k の echo の最大値が Agent の `last_echo_ns` と一致しない

  `echo_frames` は loss 記録ごとに出るので、その最大値を使います。この照合は、sender が受け取った
  `heartbeat_ack` frame を付け直しの古い echo も含めて 1 つ残らず数えることを前提にしています。
  付け直しの frame は古い値しか持たないので、数え損ねても最大 echo の照合では気づけません。現在の
  sender は `_inbound`（`a_framed` / `b_chunked`）と `_apply_segment_acks`（`b_segment`）が全 frame を
  `_echo` に渡し、これを `test_echo_frames_count_reset_and_record` で固定しています。sender の受信処理を
  変えるときはこの前提を保ってください。番号の無い #222 時代の 2 host 記録も
  `unmeasured` です。echo の値だけで判定すると、SIGCONT 後に media ACK だけで生き延びた session
  （heartbeat が backlog の後ろに並び、当時の receiver は echo を付け直さない）を検知と誤認しうる
  ためです（false PASS 側）。
  `sendall()` が戻ってから `sent_ns` を取るまでの数 µs に SIGSTOP が入った場合、その応答は cutoff 後に
  書かれたように見えます。これは稀な false FAIL で、false PASS にはなりません。

2 host の残る制約（時計比較をしない代償）: Main の stale 閾値以上の proxy blackhole（G5 の Main
`interrupted`）は、Agent 時計の blackhole window と Main の検知記録を対応付けられないため、
source ごとに**件数だけ**を `min(検知数, window 数)` で照合します。余分な `interrupted`
（例: 別の原因で出た flag）が検知されなかった window の分を埋めうるので、遅延の上限は
`since_last_rx_ns` ≤ 15 s だけで確かめます。この照合の window ごとの対応は 1 host（loopback）の
run でだけ確かめられ、2 host の結果を転記するときはこの制約を併記してください。

summary の各 run 行と候補行には `fast`（CI 用の短縮 timing で実行したか）が出ます。候補行の
`fast` は 1 run でも短縮 timing なら `true`、全 run が full timing のときだけ `false`
（`fast_runs` は短縮 timing の run 数）。ADR-0007 へ転記する結果は全 run が `fast: false`
（`--fast` なし）でなければならない。

**転記前の生記録レビュー（必須）**: 実 LAN の結果を ADR-0007 へ転記する前に、Claude と Owner が
全 run の生 JSONL 記録（各 run directory の orchestrator / receiver / sender / proxy と holder の
記録。summary だけではない）を確認し、summary の判定が記録と食い違わないこと（想定外の `fail` /
`unmeasured`、記録の欠落・混在、不自然な時刻や件数が無いこと）を確かめ、確認した run id と確認者を
MANUAL_TEST §G の記録へ残す。summarizer の `pass` だけを根拠に転記しない。

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
途中終了、sender の `end` が受理済み unit を持つのにこの run の receiver に `session_open` が無いか
`end` の `accepted` 合計が 0、つまり ack が別の receiver から来た）は全 gate `fail`、片側の記録や process file の欠落、両側の入力申告の不一致、orchestrator
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
`unmeasured`。`first_offer_delay_ns` / `last_offer_age_ns` / `max_offer_gap_ns` が無い、または
unit を生成した source で `null` の場合も `unmeasured`）です。申告 fps は sender の `start` と全 `end`、
Agent 側 orchestrator の `start`（`--fps`）で 1 つの値に一致しなければ `fail`（sender `start` に無ければ
`unmeasured`）。実 camera では申告 fps（`--fps`）を camera profile と一致させてください（`--holder` を
渡すと holder の profile fps と sender の申告 fps が食い違う run は holder 判定が `fail`）。
低照度で camera の frame rate が下がった run は、連続生成として扱われず `fail` になります。
`--holder`（real 入力の run ごとに 1 ファイル、複数回指定可）を渡すと holder の `queue_drops` = 0 と
`forward_drops` ≤ その run の sender process 数（1 + `restart_sender` 数）も run ごとに判定します。
holder ファイルは 1 回の holder 実行の完全な記録でなければ使いません: 全記録の `run_id` が 1 種類で
集計対象の real 入力 run の `run_id` と一致し、`start` と `end` が 1 つずつ、capture host の時計で
その run の最初の sender 記録より前に開始し最後の sender 記録より後に終了していること。別実行の
記録の混在・`start` / `end` の欠落（holder の異常終了や実行中のファイル）・同じ run の holder
ファイルの重複・run を覆っていない holder は `fail`、どの real 入力 run とも `run_id` が一致しない
（古い・別 run の）ファイル、sample の無いファイル、holder ファイルの無い real 入力 run は
`unmeasured` です。holder の CPU は検証済みの同じ run の holder 記録からだけ Agent CPU に加算します。
secondary の `agent_cpu` は real 入力の run が 1 つでも holder CPU を含まなければ `unmeasured` です。

real 入力の run は holder 側の記録との対応（`holder_linkage`）も必要です。sender は holder socket に
接続すると最初に自分の start nonce（8 byte）を送り、holder はその nonce で `session_open` /
`session_close` と source ごとの `forwarded`（その session で送信完了した frame 数）を記録します。
集計は sender の各 `start`（= 1 epoch）について、同じ `run_id` の holder ファイルにその nonce の
session が 1 回だけ開閉され、宣言した全 source で `forwarded` ≥ sender `end` の `generated`、かつ
超過分の合計が `HOLDER_INFLIGHT_SLACK`（64 frame。sender 停止時に socket に残った分）以下であることを
要求します。満たさなければその run の全 gate が `fail`（同時に動いていた別 sender 用の holder の記録では
満たせない）、holder ファイルが無ければ `pass` は `unmeasured` になります。

| gate | 判定 |
| --- | --- |
| G1 | mTLS 相互認証。否定試験（未 activation / 別 CA / 失効 / 接続中失効）で受理 media 0、`route_probe` は 404 か切断で、この run の receiver がその probe の session nonce の拒否記録（`route_probe`）を残していること（無ければ `fail`、nonce の無い古い記録は `unmeasured`）。未 activation / 別 CA / 失効は sender の接続試行 ≥ 1 と Main 側の認証拒否記録（`auth_refused`、`connection_limit` を除く）が両方必要で、sender 記録が無ければ `unmeasured`、試行か拒否記録が無ければ `fail`。接続中失効は Main 側 orchestrator の `revoke` 記録（無ければ `unmeasured`）、receiver の `revoked`、その後の receiver sample ≥ 1（無ければ `unmeasured`）がすべて `revoked` 時点の受理数と一致、`revoked` 後の再接続拒否として、`revoked` より後の Main の `auth_refused`（認証理由。`connection_limit` を除く）が 1 host・2 host とも必要で、無ければ `fail`（Main の記録が無ければ `unmeasured`）。sender の `connect` は TLS 試行の前に書かれるので拒否の証拠にしない |
| G2 | sender の `start` と `end` 記録が必要（否定認証と `route_probe` 以外。無ければ `unmeasured`）。epoch 内の報告 gap = durable stand-in から算出した実欠落（sequence 集合として完全一致）。durable stand-in は永続化した sequence 自体を `[first, last]` の run として SQLite に保持し、receiver 終了時に `durable_run` 記録（と `durable` の `runs` 件数）を出す。集計は run から epoch の欠落集合を独立に導出し（run の件数・境界・unit 数・順序・重複が `durable` 行と食い違えば `fail`、`runs` の無い古い記録は `unmeasured`）、continuity tracker が報告した厳密な gap（`sequence_skip` / `ingest_refused`）の範囲 `[after_sequence + 1, before_sequence)` の和集合と比較する。範囲同士の重複（二重報告）、`missing_units` と自分の範囲の不一致、durable unit 上や capture 再起動後の範囲不明区間内への誤配置は件数が合っていても `fail`。実欠落は epoch の起点（sequence 0）から数え、最初の durable unit より前の欠落も含む（capture 再起動後の epoch の先頭は範囲不明 gap）。Agent が受理を得た epoch に durable 記録が無ければ不一致。capture 再起動は範囲不明 gap、重複 commit 0。範囲不明 `capture_restart` gap が epoch の起点を動かせるのは、source の最初の durable epoch より後の各 durable epoch にちょうど 1 つあり（`after_sequence` / `missing_units` は無し、`before_sequence` はその epoch の最初の durable unit 以下で、それが起点になる）、sender 記録が epoch の前進を裏付ける場合だけ: sender の `start` は全て epoch を持ち記録順に厳密増加、再起動した source の各 epoch に `start` と `end`（`epoch_start` を記録していればそれも）がちょうど 1 つ、前の epoch の `end` が次の epoch の `start` より前。最初の durable epoch（起点は常に 0）以前への restart gap、同じ epoch への重複、sender が実行していない epoch への restart gap、これらの裏付けの欠落は `fail`。再起動後 epoch の起点より前 `[0, origin)` の unit は `unknown_extent_units` として出し（0 でなければ `lossless` は false）、その全 sequence が sender のその epoch の drop / 拒否 / residual の `unit_range` に含まれなければ `fail`（`unexplained_unknown_extent_units`）。さらに sender の `end`（source・epoch ごとに `generated` / `drops` / `drops_sent` / `residual` / `residual_sent` / `unit_ranges`）と `unit_range` 記録（drop / 拒否 / 終了時保持の sequence 範囲）で Agent 側の unit 収支を照合する: 最後の durable sequence より後の unit（backpressure で末尾が落ちると Main には gap が出ない）は、その sequence より**後**の drop / 拒否 / 保持中（`residual`）の unit と件数が一致しなければ `fail`（`unit_range` は sequence の集合として扱い、各範囲は [0, `generated`) 内、範囲同士は重複しないこと（同じ範囲の二重記録や drop と residual の重複で欠落を二重に説明しない）、drop / residual の sequence が Main の durable sequence（報告 gap の外）と重なるのは送信済み未 ack の `drops_sent` + `residual_sent` 件まで、拒否 unit は durable と重ならないこと。違反は `fail`）（記録の無い消失。例: Main が ack した後に失った末尾。epoch 途中の drop・拒否は Main の gap として報告済みなので末尾の説明に使わない）、それ以前の `drops` は Main がその epoch で報告した gap（送信後未 ack の unit は Main が持ちうるので余裕に含める）に収まらなければ `fail`（説明のつかない drop）、範囲と件数が食い違えば `fail`、`end` に収支や範囲が無い・durable 記録のある epoch に `end` が無いなら `unmeasured`。最後の receiver が停止時に受理済み unit を破棄した（`end` の `discarded_at_stop` > 0。後続の receiver が gap を報告できない）場合も `fail`。末尾の drop 数は `agent_accounted_tail_units`（Agent 側で計上した欠落） |
| G3 | receiver と sender の両方の sample が必要（片方でも無ければ `unmeasured`）。receiver queue ≤ 設定上限、sender pending ≤ 上限、kernel send queue の滞留 byte（`TIOCOUTQ`、`ss -tmi` があれば skmem `w`）≤ 2×SO_SNDBUF + 64 KiB、VmHWM ≤ 上限、warmup 後の RSS 増加 ≤ max(16 MiB, 10 %)（sample < 4 なら `unmeasured`）。skmem `tb` は送信 buffer の上限値で、SO_SNDBUF 設定前に kernel が拡大しうるため記録のみ。実入力の run で `ss` が無い（socket を 1 つも報告した sample が無い）なら `unmeasured`。proxy 保持量は 1 回の `recv()` buffer で構造的に有界なので記録のみ |
| G4 | 切断を伴う impairment から手動操作なしで再接続、p95 ≤ 10 s（再接続時間は impairment の終了から測り、Main の停止時間そのものは含めない。2 host で Main 側 action の場合は、window 開始時に live だった session（session nonce で対応付け）が切れた window について、Main 時計の「window 終了（SIGCONT / 再起動後の `ready`）→ 後続接続の `session_hello`」と Agent 時計の「その接続の `connected` → `first_accept`」の和で測る（真の値より小さくならない。#237）。対応する session が無い window は再接続 0 として数え、nonce や `connected` の記録が無ければ `unmeasured`。ただし対応付けができなくても、再接続が必要な window の終了以後に Main が `session_hello` を 1 つも受けていなければ `fail`）。切断と初回受理は impairment ごとに 1 組ずつ対応させ（同じ記録を複数回使わない）、各 impairment の対応範囲は次に予定された impairment の開始で打ち切る（切断は [開始, min(終了 + 30 s, 次の開始))、初回受理は次の開始より前。後の impairment の後に起きた切断・受理を前の impairment の再接続として数えない）、必要な再接続数は予定された reset / Main 再起動と、Agent loss timeout + 1 s 以上の blackhole / SIGSTOP の数だけで決まる（scenario 名による追加要求はない） |
| G5 | 無音断の検知 ≤ 15 s（Agent / Main とも）、Main の未 commit 区間（Agent capture 時刻）⊆ Agent 保護区間 [T−600 s, T+600 s]。proxy blackhole は予定数の `impairment_start` 記録が必要（`proxy.jsonl` が無ければ `unmeasured`、不足は `fail`）、Main の stale 閾値以上の blackhole には source ごとに Main の `interrupted`（最後の受信から ≤ 15 s）が必要。Main 側停止（`slow_stop_10s` / `slow_stop_60s` / `main_restart`）は停止ごとに Agent の loss 検知が必要で、遅延は Agent 時計で最後の受信からの経過（`idle_ns`）≤ 15 s（2 host では停止開始時に live だった session のうち、停止を生き延びていない（Main 時計で window 終了 + 15 s + 5 s（`SESSION_CLOSE_GRACE_NS`）以内に終わり、停止開始後（Main が応答をやめたことを記録で示せる場合はその時刻以後）の Main の heartbeat 応答を Agent が受けていない）session の loss episode だけを数える）。Main 側 orchestrator 記録が無ければ `unmeasured`。予定された proxy reset はそれぞれ Agent 時計で 15 s 以内の `loss_detected` が必要（`proxy.jsonl` が無ければ `unmeasured`）。`loss_detected` は source ごとに出るが connection 単位で 1 episode とし、reset / Agent loss timeout + 1 s 以上の blackhole（G4 の再接続要求と同じ規則。timeout と同じ長さの窓は検知が保証されないので求めない。#308）ごとに別の episode を 1 つずつ消費する（1 回の検知を 2 つの reset に使わない）。対応づけの範囲は [impairment 開始, min(開始 + 15 s, 次に予定された impairment の開始)) で、後の impairment の後に出た検知は前の impairment の検知として数えない（最後の impairment は開始 + 15 s まで）。1 host の Main 側停止と Main の `interrupted` の照合も同様に次の window の開始で打ち切る。Main の `interrupted` は最後の `session_close` 以前のものだけを数える（sender 終了後の stale 判定は障害検知ではない） |
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
- [ ] PoC 終了時: Owner が Main host の firewall に追加した PoC 用の許可規則（capture host →
  47200–47201/tcp）を root で削除し、他に PoC 用の規則が残っていないことを確認（Owner の作業）
- [ ] それ以外の system 設定・firewall・Tailscale・udev は一切変更していないことを確認
