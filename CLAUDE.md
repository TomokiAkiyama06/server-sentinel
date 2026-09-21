# Claude Code Instructions

ServerSentinel の開発・レビューでは、まず `AGENTS.md` を最上位の実行ルールとして読み、その後に変更対象に応じて `REQUIREMENTS.md`、`SPECIFICATION.md`、`SECURITY.md`、`PRIVACY.md`、`MANUAL_TEST.md` を確認してください。

## 言語

GitHub上でリポジトリ所有者が確認する Issue / PR / レビュー回答 / マージ要約は原則日本語で記載してください。コード、識別子、API名、ライブラリ名、コマンドは英語のままで構いません。

## 現在の製品前提

旧iOS-first / browser-camera-first仕様を前提にしないでください。

MVPの基本構成:

- Main Ubuntu ServerSentinel backend
- React Web UI
- 1〜4 Camera Sources
- `local_uvc` USB/UVC camera
- `remote_agent` Linux `media-capture-agent`
- capture agentはprivate LANでmainへ接続できればTailscale不要
- phone / Mac / desktopは主にhuman viewer
- browser/iPhone camera captureは現在のproduct scope外。phone/Mac/desktopはviewer
- `media-capture-agent`はvideo-only、非root常駐、capture credentialはadmin権限を持たない
- agentは圧縮disk ring bufferを持ち、Ownerが時間/容量モードを選択。通信断時は10分pre-loss + 10分post-lossを保護し、incidentは60日後をdefaultとしてagentから自動削除
- Tailnet membershipだけではServerSentinelへアクセス不可
- human accessはTailscale/private network permission + ServerSentinel invitationの二重条件
- non-owner permissionは少なくとも `live:view` / `recordings:view` を独立管理
- non-owner recording accessはbrowser playbackのみ、official download/exportなし
- historical timeline/eventは`recordings:view`に含め、`live:view`だけには公開しない
- owner-only face verificationは任意
- non-owner named face DB / cross-camera biometric re-identificationは禁止
- audio surveillanceはMVP外
- Agent media rootはdeployment設定で受け取り、想定mountの消失・置換時はroot filesystemへのsilent fallbackを拒否
- Main ServerのHardware Integrityはstartup + daily。baseline変更はOwner承認が必要
- Recording Healthはdaily self-test。hardware change / self-test failureは即時Owner通知

## PRレビュー重点

少なくとも以下を確認してください。

- 要件・仕様・受入条件との整合性
- バグ、境界条件、エラー処理
- セキュリティ/Secret管理
- privacy/biometric不変条件
- データ破壊/容量枯渇
- retry/idempotency/backpressure/競合
- 1〜4 sourceで固定2台前提がないか
- UVC identityが`/dev/videoN`だけになっていないか
- identical non-serial cameraの曖昧reconnectを自動bindしていないか
- `media-capture-agent`が不要なroot/GUI/Tailscale/admin権限を要求していないか
- capture ingest listenerとhuman dashboard listenerが分離されているか
- agent credentialからhuman/admin APIへ昇格できないか
- trusted Tailscale identity header pathをLANからbypassできないか
- ServerSentinelがTailscale ACL/Grants変更やadmin credentialを要求していないか、未招待identityへアプリ情報を漏らしていないか
- `live:view` / `recordings:view`分離がserver-sideで強制されるか
- non-owner download/exportが再導入されていないか
- low-light/poor-quality時にperson detector failureを`no person`へ変換していないか
- owner verificationがnon-owner identity DBへ拡張されていないか
- timelineがculprit/attackerと断定していないか
- repository fixtureにreal-person/publicly-licensed real-person mediaが入っていないか
- model/weights/dependency license
- Main Serverのstartup/daily hardware checkとdaily recording self-test、異常時の即時Owner通知が守られているか
- Agent media rootのmount/書込権限/free space/safety reserve確認とsilent fallback拒否が守られているか
- main / agent / Web間契約
- 実機確認とmock確認の切り分け

指摘は `重大` / `重要` / `提案` に分類してください。

## 自動レビュー

GitHub Actions上のClaude PRレビューは、利用可能なサブスクリプション枠が尽きているため現在停止中です。Ownerが明示的に再有効化するまでは、ClaudeレビューをMerge条件として扱いません。

## マージ

Claude単独でマージ可否を決めないでください。Codex と Claude の両方が current HEAD **かつ current base/diff context** をレビューし、必須CI成功、blocking finding解消後にのみマージします。
