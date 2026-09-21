# AGENTS.md — Coding Agent 向け必須ルール

このファイルは規範文書です。このリポジトリで作業する agent は、リポジトリ所有者が特定のタスクについて明示的に上書きしない限り、本書に従わなければなりません。

## 1. Mission

ServerSentinel を、無償・self-hosted・privacy-first の物理セキュリティ監視として構築します。構成は次のとおりです。

- main Ubuntu backend;
- React web dashboard;
- 汎用の Camera Source layer;
- local UVC capture;
- private LAN 経由のリモート Linux `media-capture-agent` capture;
- 明示的に招待された利用者による private な phone / Mac / desktop からの live 閲覧。

MVP は 1〜4 の active video source を扱います。iPhone / browser を camera source にすること、native iOS app、Apple Developer Program 加入、App Store 配布は必要としません。

## 2. 権威ある文書

優先順位:

1. 現在のタスク / Issue に対するリポジトリ所有者の明示的な指示;
2. `REQUIREMENTS.md`;
3. `SPECIFICATION.md`;
4. 承認済み ADR;
5. 本ファイル;
6. 既存実装。

security / privacy / biometric / access-control に関する製品判断を独断で作らず、所有者に確認してください。

## 3. 作業・マージ方針

軽微でない変更では次の順序を守ります。

1. 作業を Issue に対応付ける;
2. 意図した base から branch を切る;
3. 実装・テスト・文書化を行う;
4. PR を作成・更新する;
5. CI を待つ;
6. **current HEAD を current base / diff context に対して** レビューした Codex と Claude の結果を待つ;
7. blocking finding を修正し、スレッドに応答・解決する;
8. HEAD / base が実質的に変わったらレビューを再実行する;
9. すべての gate を通過した場合にのみマージする。

`main` へ直接コミットしないでください。

Issue #4 によるリポジトリレベルの強制が整うまでは、同一リポジトリへの write 権限は trusted maintainer の能力として扱い、マージ実行者がレビューの出所と current HEAD + base context を手動で確認します。

## 4. 実機が使えない場合の方針

mock、synthetic / 生成した fixture、dependency injection、仮想 source、transport mock を使ってください。検証していない hardware / network / browser の挙動を「確認済み」と記載してはいけません。実機での確認手順は `MANUAL_TEST.md` に置きます。

## 5. Privacy / security の不変条件

既定の不変条件:

- 開発者が運用する account / video service を持たない;
- telemetry / analytics / 広告 / tracking を行わない;
- Slack 用の開発者 relay を持たない;
- 隠れたデータ送信を行わない;
- MVP は video のみの監視;
- owner の face verification は任意かつ local;
- non-owner の名前付き顔データベースを作らない;
- camera 横断の biometric re-identification を行わない;
- 犯人性・有責性の自動推論を行わない;
- 既定で dashboard を public Internet に公開しない;
- Tailnet membership だけでは ServerSentinel を認可しない;
- Tailscale account を共有する deployment では Tailscale login も人を特定しないため、application 認可は ServerSentinel が発行する個人単位の credential に依存させる;
- viewer の authenticator での user verification は viewer の端末内で完結させ、指紋 / 顔の template を ServerSentinel へ送らせない・保存しない;
- ServerSentinel は Tailscale ACL / Grants を変更せず、Tailscale の管理 credential を保持しない。既存の Tailnet policy は変更せずに使える;
- Tailnet の Owner / Admin やインフラ管理者からの秘匿を約束しない。

## 6. Secret / 機微データの扱い

実物を commit / log してはいけません。

- `.env` の secret;
- Slack の webhook / token;
- Tailscale の auth / admin key;
- private key / 証明書;
- private な deployment の IP / hostname / SSID / Tailnet 値;
- owner の biometric template / embedding;
- 録画、実在の人物・実際の部屋を写した監視 media。

リポジトリ / CI の media fixture は synthetic / 生成物のみとします。公開ライセンスの実在人物画像であってもリポジトリ fixture にはしません。外部 benchmark dataset は各ライセンスの条件下で手元利用のみとし、GitHub の PR / Issue / Actions artifact へ添付しません。

## 7. Camera Source の不変条件

MVP の source type:

- `local_uvc`;
- `remote_agent`。

ルール:

- active source が 1 台でも動作する;
- 既定の active 上限は 4;
- `front` / `rear` のような固定 schema を持たない;
- source type と role は別概念として保つ;
- profile は source ごとに設定する;
- `/dev/videoN` だけでは durable identity にならない;
- reconnect 後、serial を持たない同型 UVC の曖昧な候補を自動 bind しない;
- 曖昧な reconnect は、owner の明示的な再承認まで `manual_intervention_required` とする;
- MVP では audio を取得しない;
- browser / iPhone camera capture は現在の product scope 外。phone / Mac / desktop browser は viewer とする。

## 8. `media-capture-agent` の不変条件

- service / process 名は `media-capture-agent`;
- 無関係なシステム / ベンダーソフトウェアを騙らない;
- desktop UI / tray を必須にしない;
- 通常時は専用の非 root account で動作する;
- MVP では video のみを capture する;
- 接続は agent から main host へ開始する;
- 一度きりの owner 承認による pairing の後、失効可能な相互認証付き暗号化 identity を用いる;
- capture node の credential は human / admin API の権限を与えない;
- private LAN で到達できるなら agent に Tailscale は不要;
- agent health と camera health は別に扱う;
- capture ingest listener と human dashboard listener を分離する;
- 映像を受け取るためだけに main host から capture machine へ SSH / 管理接続しない;
- agent は compressed video の disk ring buffer を持つ。owner が duration または capacity mode を選択し、Main Server との予期しない通信断では T-10 分 / T+10 分を保護する。保護した incident は既定 60 日で agent から失効する。

## 9. Human access の不変条件

human remote access には独立した 2 つの gate があります。

1. network レベルの private / Tailscale 許可;
2. ServerSentinel application の invitation / permission。

初期の non-owner permission:

```text
live:view
recordings:view
```

これらは独立しています。

MVP の non-owner recording access は browser playback のみです。所有者が要件を明示的に変更しない限り、download / export の route / button を追加しないでください。browser playback が画面録画や client 側の capture を防ぐとは説明しないでください。

historical timeline / event へのアクセスは `recordings:view` に含めます。`live:view` だけの相手へは決して公開しません。

trusted proxy / Tailscale の identity header を使う場合、その listener への backend アクセスは通常の LAN client から迂回できないようにしてください。

対象 deployment では研究室で 1 つの Tailscale account を共有するため、Tailscale login は account を示すだけで人を特定しません。application 認可は、ServerSentinel が発行する個人単位かつ個別に失効できる credential（ADR-0004 が WebAuthn / passkey を提案、Owner 承認待ち）に依存させてください。Tailscale の identity / device 情報は補助的な扱いに留めます。proxy identity header だけで human route を認可しないこと、device の承認を人物の特定であるかのように説明しないことを守ってください。

credential を人に紐づけるための条件も守ってください。登録時と毎回の認証で authenticator の user verification を必須にし、authenticator は招待された本人が管理するものとします。OS account や端末の unlock を共有する機器では、その共有 profile に置かれた platform authenticator は共有 credential であり条件を満たしません。session は生成元 credential に紐づけ、idle / 絶対時間両方の上限で終了させます。意図的に貸し与えられた credential や、放置された unlock 済み session を application が検知できるとは説明しないでください。

credential がまだ存在しない request の例外は、local の owner bootstrap（console にだけ表示する使い捨て authorization を発行し、予約済み origin の browser から通常の redemption 経路で 1 回だけ使う）、短命・使い捨て enrollment code による招待 redemption、認証 route 自体の 3 つだけです。これらは application data を返さず、無効 / 期限切れ / 使用済み code には未招待と同じ汎用応答を返します。AUTH-008 の owner 操作には fresh な user verification を要求し、step-up 失敗 / キャンセル時は何も実行しないでください。

dashboard は ServerSentinel 専用に予約した origin で、かつ secure context（HTTPS、または厳密に local な browser の `http://localhost`）で提供してください。browser はそれ以外で WebAuthn を提供しません。origin の予約自体は deployment 側の責任（専用 host / VM / namespace、または OS / service policy）で、application が startup と daily に行うのは実 listener と全 scheme・全 port の proxy route を列挙する「検出」です。防止ではなく、検査間に bind された process は次の検査まで cookie を受け取りうることを必ず明記してください。

2 つの gate 自体は弱めません。共有 account で変わるのは、network gate が個人を区別しなくなる点だけです。

## 10. Detection の不変条件

- person detection は server movement の証明ではない;
- 必要な場面では camera 全体の動きを補正する;
- occlusion と時間方向の持続性を扱う;
- confidence は確実性ではない;
- image-quality gating は detector ごとに定める;
- person detection を信頼できる形で実行できない場合の結果は `unknown` / 利用不可であり、信頼できる `no person` にしてはならない;
- 品質の低い owner verification は `unknown` とする;
- non-owner に名前付き identity を与えない;
- timeline は観測を報告するものであり、有責性や因果を述べない。

## 11. Presence の不変条件

状態: `PRESENT`、`PROBABLY_PRESENT`、`ABSENT`、`UNKNOWN`。

manual override が優先されます。既定で通常の occupancy automation を抑制するのは、明示的または高信頼の `PRESENT` だけです。server movement / camera tamper の検知はすべての状態で動作し続けます。

## 12. Media / storage の不変条件

- capture / recording / inference / viewer の profile は互いに独立;
- 不要な transcode より、互換性のある stream copy を優先する;
- subscriber が 0 のとき viewer 専用処理は停止・縮小する;
- remote viewer は main host へ接続し、capture agent へ直接接続しない;
- event の既定目標は前 30 秒 + 後 120 秒、最大 20 分;
- manual recording の最大は 20 分;
- 長時間の decoded frame history ではなく、実務上可能な範囲で bounded な compressed pre-roll を使う;
- recording retention の既定は 20 日;
- audit retention の既定は 90 日;
- starred recording を自動削除しない;
- filesystem の hard safety reserve を守る;
- `STORAGE_PRESSURE` / `STORAGE_HARD_STOP` を明示する;
- 既知の loss / overload の最中に healthy 状態を黙って表示しない;
- Agent media root はリポジトリ外の deployment 設定で受け取る。想定 mount の消失・置換時は unsafe write を拒否し、root filesystem 上の代替を黙って作らない;
- Main Server は owner 承認済みの hardware baseline を startup 時と最低 1 日 1 回比較する;
- Main Server は最低 1 日 1 回 recording-health の self-test を行う。承認済み hardware の変更・欠落や self-test の失敗は、即時の Owner 通知を発生させる。

## 13. 依存・model の license

upstream、正確な license、実質的な transitive 義務、pinning を確認してください。ML では実装コードと model / weights を別々にレビューします。

推奨: Apache-2.0、MIT、BSD-2/3-Clause、レビュー後に同等とみなせる permissive license。

所有者の明示的な承認なしには既定で不可: AGPL、両立しない GPL 義務、SSPL、BSL / source-available / 非 OSI、ライセンスが曖昧なもの。

YOLOX は person detector の初期評価候補に過ぎません。owner face verification の model / weights は別途レビューが必要です。

## 14. 破壊的操作の方針

所有者の明示的な承認なしに次を行わないでください。

- disk の消去 / format;
- すべての録画 / データベース / テーブルの削除;
- データを保持する volume の破棄;
- firewall の全面無効化やサービスの公開;
- 管理 credential を用いた Tailscale Grants / ACL の変更;
- 無関係な credential の rotate;
- 所有者を締め出しうる SSH 設定の変更;
- 保護された / 共有された履歴への force-push。

## 15. Logging / API のルール

raw な pairing credential、human の enrollment code、agent の key / 証明書、Tailscale / Slack の secret、biometric template、機微な header、media の内容を log に出さないでください。

すべての media / API route は server 側で認可を強制します。capture ingest は agent protocol の action だけを受け付けます。human UI の route は ingest listener から到達できません。

## 16. テスト

該当する範囲で次を扱います。

- 1〜4 source の topology;
- local UVC の安定した identity と reconnect;
- serial を持たない同型 camera の曖昧な reconnect;
- agent の pairing / 失効 / mTLS;
- agent online と camera offline の分離;
- clock skew;
- LAN の中断と backpressure;
- phone / Mac からの live 閲覧;
- Tailscale / private 到達性と ServerSentinel application 認可;
- 個人単位 credential の検証と、bootstrap / enrollment / 認証だけが credential なしで到達できること（無効 / 期限切れ / 使用済み code は未招待と同一応答）;
- owner 操作の fresh user verification（stale session の拒否、step-up 失敗 / キャンセル時に状態が変わらないこと）;
- `live:view` と `recordings:view` の分離（historical timeline が `recordings:view` でのみ見えることを含む）;
- duration / capacity の ring-buffer mode、T-10 / T+10 の保護、既定 60 日の失効、agent の disk pressure;
- detector ごとの quality gate（person の false negative 防止を含む）;
- owner verification / anonymous tracking / presence;
- storage pressure;
- migration と mock E2E。

## 17. 文書の更新規律

挙動が変わったら次を更新します。

- `REQUIREMENTS.md` — 製品判断;
- `SPECIFICATION.md` — 技術契約;
- ADR — アーキテクチャ上の決定;
- `MANUAL_TEST.md` — 実機 / network / browser の確認;
- `SECURITY.md` / `PRIVACY.md` — security / データの挙動;
- `docs/INITIAL_ISSUES.md` / `ROADMAP.md` — 実装順序。

## 18. 停止条件

次を行う前に作業を止め、所有者の明示的な判断を求めてください。

- 開発者が hosting する cloud の導入;
- analytics / 広告 / 決済の導入;
- プロジェクト license の変更;
- 両立しない、または不確かな依存 / model license の採用;
- 既定での public Internet 公開;
- 2 段階の access control や capture node 認証の弱体化;
- 強力な Tailscale admin credential の自動保存;
- audio の収集;
- non-owner の顔の登録・命名;
- camera 横断の biometric re-identification;
- 犯人性・有責性の自動推論;
- 新たな明示的 product decision / ADR なしの browser / iPhone camera capture の導入;
- non-owner 向け録画 download / export 機能の追加;
- 確立した `recordings:view` → historical timeline の permission 対応を所有者承認なしに変更すること;
- agent の 前 10 分 / 後 10 分 保護や既定 60 日失効を所有者承認なしに弱めること。
