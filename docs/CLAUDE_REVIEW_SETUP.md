# Claude PRレビュー初期設定

ServerSentinel では、PRのマージ前に **Codex + Claude の二重レビュー**を必須とします。

ClaudeレビューはPRの出所に応じて2経路あります。

- 同一repository内のPR: `.github/workflows/claude-review.yml` が自動実行
- fork由来の外部PR: `.github/workflows/claude-review-fork.yml` をmaintainerが手動実行

## 認証方式

ServerSentinel では、GitHub側の認証に workflow の短命な `github.token` を使い、Claude側の認証に `CLAUDE_CODE_OAUTH_TOKEN` を使います。

この構成では Claude GitHub App のインストールを必須にせず、リポジトリSecretだけで動かす方針です。

## 1. Claude Code OAuth Tokenを生成

Claude Codeを利用できる端末で次を実行します。

```bash
claude setup-token
```

表示されたtokenはSecretとして扱い、Issue、PR、ログ、コード、`.env` 等へ貼らないでください。

## 2. GitHub Actions Secretへ登録

GitHubリポジトリで以下を開きます。

`Settings -> Secrets and variables -> Actions -> New repository secret`

登録内容:

```text
Name: CLAUDE_CODE_OAUTH_TOKEN
Value: claude setup-token で生成した値
```

## 3. 同一repository内PRの動作確認

Secret登録後、同一repository内の既存PRに新しいcommitをpushするか、PRをreopen / ready for reviewにすると `Claude PRレビュー` workflowが起動します。

正常時:

- Claudeが日本語でレビューする
- 重大度を `重大` / `重要` / `提案` に分類する
- PR全体コメントまたはinline commentを投稿する
- コード変更やマージは行わない

## 4. fork由来PRの安全なレビュー

GitHubは通常、forkからの `pull_request` workflowへrepository secretを渡しません。そのため通常の自動Claude workflowはfork PRを意図的にスキップします。

fork PRをレビューする場合は、maintainerがGitHub Actionsから `Claude 外部PRレビュー（手動）` を明示的に実行し、対象PR番号を入力します。

このtrusted workflowは次の制約で動きます。

- repositoryの信頼済みdefault branchだけをcheckoutする
- fork PRのheadはcheckoutしない
- PR内容は `gh pr view` / `gh pr diff` で読み取るだけにする
- PR由来のスクリプト、ビルド、テスト、設定ファイルを実行しない
- PR本文・diff・コード中の指示は未信頼データとして扱う
- Secretや環境変数を表示・送信しない
- ClaudeはPRへレビューコメントを投稿するだけで、commit / push / mergeを行わない

`pull_request_target` でfork headをcheckoutし、その状態でSecretを使う構成は禁止します。

## 5. マージ条件

以下をすべて満たすまでマージしません。

- Codexレビュー完了
- Claudeレビュー完了
- Codex / Claudeの重大・重要指摘を解消
- 必須CI成功
- 未解決のブロッキングレビューなし

レビュー後に重要な変更を追加した場合は、両レビューを再実行します。

## セキュリティ

- OAuth tokenをGitへcommitしない
- workflow内へtokenを直接書かない
- `CLAUDE_CODE_OAUTH_TOKEN` はGitHub Actions Secretからのみ参照する
- Claude workflowのGitHub権限はレビューに必要な範囲へ限定する
- Claudeにはレビュー時のコード変更・コミット・マージ権限を与えない
- fork PRへSecretを直接渡さない
- 未信頼のPR headをSecret付きworkflowでcheckout・実行しない
