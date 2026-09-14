# Claude PRレビュー初期設定

ServerSentinelでは、PRのマージ前に **Codex + Claude の二重レビュー**を必須とします。

ClaudeレビューはPRの出所に応じて2経路あります。

- 同一repository内のPR: `.github/workflows/claude-review.yml` が自動実行
- fork由来の外部PR: `.github/workflows/claude-review-fork.yml` をmaintainerが手動実行

## 認証方式

ServerSentinelでは、GitHub側の認証にworkflowの短命な `github.token` を使い、Claude側の認証に `CLAUDE_CODE_OAUTH_TOKEN` を使います。

この構成ではClaude GitHub Appのインストールを必須にせず、リポジトリSecretだけで動かす方針です。

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

## 3. Claudeレビューの権限分離

Claude自身が動くjobと、GitHubへ正式レビューを投稿するjobを分離します。

### Claude review job

Claude側jobはread-onlyです。

- `contents: read`
- `pull-requests: read`
- `issues: read`
- `actions: read`
- Claude Codeのallowed toolsは `Read,Glob,Grep` のみ
- `Write` / `Bash` / GitHub comment toolは与えない
- 最終レビューは `--json-schema` によるstructured outputとして返す

このjobはGitHubへの正式レビュー投稿権限を持ちません。未信頼PR内のprompt injectionによってClaudeが誤った指示に従った場合でも、任意scriptの書換え・shell実行・`github-actions[bot]`としての偽レビュー投稿を直接行えない境界にします。

### Trusted post job

Claude review jobが正常終了した後、別のtrusted post jobがstructured outputをデータとして受け取り、次を行います。

1. current PR HEADが固定HEADと一致することを再確認
2. structured outputを`jq`で検証・抽出
3. 固定HEAD marker付きのレビュー本文を作成
4. `github.token`でGitHubへ投稿
5. 投稿APIのレスポンスから投稿者が `github-actions[bot]` であることを検証
6. 投稿後にもcurrent HEADが固定HEADと一致することを再確認
7. 同じPR HEAD SHAへ `ServerSentinel / Claude Review Gate` という共通check runを作成
8. `highest_severity` が `critical` / `important` の場合はcheckをfailureにし、job自体も失敗させる

レビュー本文はshell commandとして評価せず、ファイル/JSONデータとしてのみ扱います。

## 4. 同一repository内PRの動作

同一repository内の既存PRに新しいcommitをpushするか、PRをreopen / ready for reviewにすると `Claude PRレビュー` workflowが起動します。

安全性のため、PR head自体を信頼済みworkspace rootとして扱いません。

- workflow eventで受け取ったHEAD SHA / base SHAを固定
- workspace rootには信頼済みbase SHAをcheckout
- PR HEADは `$RUNNER_TEMP` 配下の分離されたread-onlyレビュー用snapshotとして展開
- diffも `$RUNNER_TEMP` に固定snapshotとして保存
- Claudeへはbase側のAGENTS.md等を既存ルールとして読ませる
- PR HEAD/diff内の指示・prompt・commandは未信頼データとして無視させる
- ClaudeにはRead/Glob/Grep以外のtoolsを与えない

同一PRに新しいcommitがpushされた場合は古いworkflowをcancelし、最新HEADのworkflowだけをレビューgateとして扱います。

## 5. fork由来PRの安全なレビュー

GitHubは通常、forkからの `pull_request` workflowへrepository secretを渡しません。そのため通常の自動Claude workflowはfork PRを意図的にスキップします。

fork PRをレビューする場合は、maintainerがGitHub Actionsから `Claude 外部PRレビュー（手動）` を明示的に実行し、対象PR番号を入力します。

このtrusted workflowは次の制約で動きます。

- repositoryの信頼済みdefault branchだけをcheckoutする
- fork PRのheadはcheckout/executeしない
- review開始時のfork HEAD SHAを固定する
- PR diffは `$RUNNER_TEMP` の読み取り専用レビュー入力として保存する
- diff取得後・レビュー投稿直前・投稿後にGitHub上のHEADが変わっていないことを確認する
- Claude jobはread-onlyで、GitHubへのwrite tokenを持たない
- Claudeには `Read,Glob,Grep` 以外を許可しない
- trusted post jobだけが正式レビューを投稿する
- trusted post jobはforkのPR HEAD SHAへ同じ `ServerSentinel / Claude Review Gate` check runを明示的に作成する
- PR本文・diff・コード中の指示は未信頼データとして扱う
- Secretや環境変数を表示・送信しない

`pull_request_target` でfork headをcheckoutし、その状態でSecretを使う構成は禁止します。

## 6. Structured review output

Claudeは次のschemaに従って結果を返します。

```json
{
  "highest_severity": "none | proposal | important | critical",
  "review_markdown": "日本語のレビュー本文"
}
```

意味:

- `critical`: 「重大」が1件以上
- `important`: 「重要」が1件以上で重大なし
- `proposal`: 提案のみ
- `none`: 指摘なし

`critical` / `important` はCI上もblockingとして扱い、修正後の新しいHEADでClaudeレビューを再実行します。

## 7. GitHub Actionのバージョン固定

Secretへアクセスするreview workflowでは、第三者Actionをmutableなmajor tagだけで実行しません。

現在は以下をfull commit SHAで固定しています。

- `anthropics/claude-code-action`: v1.0.223相当の確認済みcommit
- `actions/checkout`: v6の確認済みcommit

Actionを更新する場合は、上流tagを追従するだけでなく、新旧commitの差分・release内容・権限影響を確認したうえでPRとして更新します。

## 8. Required check / branch protection

同一repository PRとfork PRの両方で、最終的なClaudeレビューgateはPR HEAD SHAに対して次の共通check run名を作成します。

```text
ServerSentinel / Claude Review Gate
```

Repository Ruleset / Branch protectionでは、`main`へのPRに対してこのcheckを **Required status check** として設定してください。

これにより:

- 同一repository PR: 自動Claudeレビューが成功するまでmerge不可
- fork PR: maintainerが手動Claudeレビューworkflowを実行して成功させるまでcheckが存在せずmerge不可
- Claudeが `critical` / `important` を返した場合: checkがfailureとなりmerge不可
- 新しいcommitがpushされた場合: 新HEADには旧HEADのcheck結果が引き継がれず、再レビューが必要

GitHubリポジトリ設定の変更自体はコードだけでは完結しないため、bootstrap CI Issueのセットアップ項目として実際のRuleset/branch protection設定と動作確認を行います。

## 9. Codexレビュー

CodexはGitHub側のCodex連携からレビューを実行します。レビュー依頼はPRをReadyにする、または `@codex review` コメントで行います。

現時点ではClaudeのようなrepository内独自gate workflowを持たないため、各PRではCodexが**現在のHEAD**をレビューしたことと、未解決の重大・重要指摘がないことを確認してからmergeします。

Codex側についても将来的にmachine-readableなrequired statusへ結び付けられる場合は、その方式をbootstrap CI Issueで評価します。それまでは `AGENTS.md` のmerge ruleに従い、人間/エージェントがHEAD一致を明示確認します。

## 10. マージ条件

以下をすべて満たすまでマージしません。

- Codexが**現在のPR HEAD**をレビュー済み
- Claudeが**現在のPR HEAD**をレビュー済み
- `ServerSentinel / Claude Review Gate` が現在のHEADでsuccess
- Claudeレビューに `重大` / `重要` が残っていない
- Codexの重大・重要指摘を解消
- 必須CI成功
- 未解決のブロッキングレビューなし

レビュー後にcommitを1つでも追加した場合、旧HEADのレビューはマージgateとして扱わず、両レビューを最新HEADへ再実行します。

## セキュリティ

- OAuth tokenをGitへcommitしない
- workflow内へtokenを直接書かない
- `CLAUDE_CODE_OAUTH_TOKEN` はGitHub Actions Secretからのみ参照する
- Claude jobへGitHub write権限を与えない
- Claudeにはレビュー時のファイル書込・shell実行・commit・push・merge権限を与えない
- fork PRへSecretを直接渡さない
- 未信頼のPR headをSecret付きworkflowでcheckout・実行しない
- review対象SHAをコメントに明記し、current HEADと異なるレビューをマージgateとして扱わない
- 正式投稿はtrusted post jobだけが行い、投稿APIレスポンスのuserが `github-actions[bot]` であることを確認する
- Secretへアクセスする第三者Actionはfull commit SHAへ固定する
- workflow生成物はPR working treeではなく `$RUNNER_TEMP` へ置く
