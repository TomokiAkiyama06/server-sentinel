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

## PRレビュー

レビューでは少なくとも以下を確認してください。

- 要件・仕様・受け入れ条件との整合性
- バグ、境界条件、エラー処理
- セキュリティとSecret管理
- プライバシー不変条件
- データ破壊や容量枯渇時の安全性
- 再接続、再試行、冪等性、競合状態
- テスト不足と実機確認の切り分け
- 依存関係、AIモデル、weights のライセンス
- iOS / Ubuntu / Web 間の契約不整合
- App Store審査上の問題
- 不要な複雑化や保守性低下

指摘は `重大`、`重要`、`提案` に分類してください。

インタラクティブにClaude Codeへレビューを依頼する場合は、レビュー時にコードを変更せず、レビューコメントのみ投稿してください。修正を依頼された場合のみ、`AGENTS.md` のIssue/branch/PRルールに従って変更してください。

**例外:** `.github/workflows/claude-review.yml` と `.github/workflows/claude-review-fork.yml` による自動PRレビューでは、workflow自身のより厳しい制約を優先します。自動レビューのClaude jobはread-onlyで動作し、GitHubへ直接コメントせず、コード・設定・スクリプトを変更または実行せず、指定されたstructured outputだけを返します。

## マージ

Claude単独のレビューでマージ可否を決めないでください。ServerSentinelでは Codex と Claude の両方のレビュー完了、必須CI成功、ブロッキング指摘解消がマージ条件です。
