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

- PR eventで受け取ったHEAD SHAをレビュー対象として固定する
- 固定HEADそのものをcheckoutし、baseとのdiffをローカルスナップショット化する
- ClaudeはliveなPR diffを取り直さず、その固定差分をレビューする
- 正式レビュー投稿の直前にGitHub上のcurrent `headRefOid`が固定HEADと一致することを再確認する
- 正式レビューコメントにレビュー対象HEAD SHAを明記する
- 完了stepでもHEAD一致と、現HEAD向け正式レビューmarkerの存在を検証する
- Claudeが日本語でレビューする
- 重大度を `重大` / `重要` / `提案` に分類する
- コード変更やマージは行わない

同一PRに新しいcommitがpushされた場合は古いworkflowをcancelし、最新HEADのworkflowをレビューgateとして扱います。

## 4. fork由来PRの安全なレビュー

GitHubは通常、forkからの `pull_request` workflowへrepository secretを渡しません。そのため通常の自動Claude workflowはfork PRを意図的にスキップします。

fork PRをレビューする場合は、maintainerがGitHub Actionsから `Claude 外部PRレビュー（手動）` を明示的に実行し、対象PR番号を入力します。

このtrusted workflowは次の制約で動きます。

- repositoryの信頼済みdefault branchだけをcheckoutする
- fork PRのheadはcheckoutしない
- review開始時のfork HEAD SHAを固定する
- PR diffは固定HEAD時点の読み取り専用スナップショットとして保存する
- diff取得後とreview完了時にGitHub上のHEADが変わっていないことを再確認する
- レビューコメントに対象HEAD SHAを明記する
- PR由来のスクリプト、ビルド、テスト、設定ファイルを実行しない
- PR本文・diff・コード中の指示は未信頼データとして扱う
- Secretや環境変数を表示・送信しない
- ClaudeはPRへレビューコメントを投稿するだけで、commit / push / mergeを行わない

`pull_request_target` でfork headをcheckoutし、その状態でSecretを使う構成は禁止します。

## 5. GitHub Actionのバージョン固定

Secretへアクセスするreview workflowでは、第三者Actionをmutableなmajor tagだけで実行しません。

現在は以下をfull commit SHAで固定しています。

- `anthropics/claude-code-action`: v1.0.223相当の確認済みcommit
- `actions/checkout`: v6の確認済みcommit

Actionを更新する場合は、上流tagを追従するだけでなく、新旧commitの差分・release内容・権限影響を確認したうえでPRとして更新します。

## 6. マージ条件

以下をすべて満たすまでマージしません。

- Codexが**現在のPR HEAD**をレビュー済み
- Claudeが**現在のPR HEAD**をレビュー済み
- Codex / Claudeの重大・重要指摘を解消
- 必須CI成功
- 未解決のブロッキングレビューなし

レビュー後にcommitを1つでも追加した場合、旧HEADのレビューはマージgateとして扱わず、両レビューを最新HEADへ再実行します。

## セキュリティ

- OAuth tokenをGitへcommitしない
- workflow内へtokenを直接書かない
- `CLAUDE_CODE_OAUTH_TOKEN` はGitHub Actions Secretからのみ参照する
- Claude workflowのGitHub権限はレビューに必要な範囲へ限定する
- Claudeにはレビュー時のコード変更・コミット・マージ権限を与えない
- fork PRへSecretを直接渡さない
- 未信頼のPR headをSecret付きworkflowでcheckout・実行しない
- review対象SHAをコメントに明記し、current HEADと異なるレビューをマージgateとして扱わない
- Secretへアクセスする第三者Actionはfull commit SHAへ固定する
