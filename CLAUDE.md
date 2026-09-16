# Claude Code Instructions

ServerSentinel の開発・レビューでは、まず `AGENTS.md` を最上位の実行ルールとして読み、その後に変更対象に応じて `REQUIREMENTS.md`、`SPECIFICATION.md`、`SECURITY.md`、`PRIVACY.md`、`MANUAL_TEST.md` を確認してください。

## 言語

GitHub上でリポジトリ所有者が確認する以下の内容は、原則として日本語で記載してください。

- Issueタイトル・本文
- PRタイトル・本文
- PRレビューコメント
- レビュー指摘への回答
- マージ時の要約

コード、識別子、API名、ライブラリ名、コマンドなどは英語のままで構いません。

## 現在の製品前提

レビュー時に旧iOS-first仕様を前提にしないでください。

MVPの基本構成は次です。

- Ubuntu ServerSentinel backend
- React Web UI
- 1〜4個のCamera Source
- `local_uvc` USB Webcam
- `remote_web` browser-based Web Camera Node
- iPhoneはWeb Camera Nodeとして利用可能だが、native iOS/App StoreアプリはMVP要件ではない
- Camera Sourceの種類と役割/Detection Profileは分離
- owner-only face verificationは任意
- non-ownerのnamed face databaseは禁止
- motion/low-lightによる自動torch/light点灯は行わない

## PRレビュー

レビューでは少なくとも以下を確認してください。

- 要件・仕様・受入条件との整合性
- バグ、境界条件、エラー処理
- セキュリティとSecret管理
- プライバシー/biometric不変条件
- データ破壊や容量枯渇時の安全性
- 再接続、再試行、冪等性、競合状態
- 1〜4 Camera Source構成で固定2台前提が混入していないか
- UVCの`/dev/videoN`だけをstable identityとしていないか
- Web Camera Nodeのsecure context / permission / browser lifecycle
- browser background captureやlocal storageを過剰保証していないか
- audioがsourceごとにdefault OFFか
- automatic torch/lightが再導入されていないか
- low-light時にowner match/non-matchを強制していないか
- owner-only verificationがnon-owner identity DBへ拡張されていないか
- timelineが人物をculprit/attackerと断定していないか
- テスト不足と実機確認の切り分け
- 依存関係、AIモデル、weightsのライセンス
- Ubuntu / Web / Camera Source間の契約不整合
- 不要な複雑化や保守性低下

指摘は `重大`、`重要`、`提案` に分類してください。

インタラクティブにClaude Codeへレビューを依頼する場合は、レビュー時にコードを変更せず、レビューコメントのみ投稿してください。修正を依頼された場合のみ、`AGENTS.md` のIssue/branch/PRルールに従って変更してください。

**例外:** `.github/workflows/claude-review.yml` と `.github/workflows/claude-review-fork.yml` による自動PRレビューでは、workflow自身のより厳しい制約を優先します。自動レビューのClaude jobはread-onlyで動作し、GitHubへ直接コメントせず、コード・設定・スクリプトを変更または実行せず、指定されたstructured outputだけを返します。

## マージ

Claude単独のレビューでマージ可否を決めないでください。ServerSentinelでは Codex と Claude の両方のcurrent-HEADレビュー完了、必須CI成功、ブロッキング指摘解消がマージ条件です。
