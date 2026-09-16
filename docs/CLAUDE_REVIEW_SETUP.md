# Claude PRレビュー初期設定

ServerSentinelでは、PRのマージ前に **Codex + Claude の二重レビュー**を必須とします。

この文書では現在のレビュー経路と**信頼境界**を定義します。現段階のworkflowはレビュー品質・事故防止のための仕組みであり、same-repository write権限を持つ悪意ある/侵害済みmaintainerに対する強固なrepository-level security boundaryではありません。より強い機械的強制は Issue #4 でRuleset Required workflowsまたは専用GitHub App等を導入して実現します。

## 1. レビュー経路

- 同一repository内PR: `.github/workflows/claude-review.yml` が自動実行
- fork由来外部PR: `.github/workflows/claude-review-fork.yml` をmaintainerが手動実行

外部・未信頼コントリビュータはfork PRを使用します。Issue #4が完了するまでは、same-repository write accessは信頼済みmaintainerに限定します。

## 2. 認証

Claude側の認証にはrepository secret `CLAUDE_CODE_OAUTH_TOKEN` を使います。

```bash
claude setup-token
```

GitHubの `Settings -> Secrets and variables -> Actions -> New repository secret` で次を登録します。

```text
Name: CLAUDE_CODE_OAUTH_TOKEN
Value: claude setup-token で生成した値
```

TokenはIssue、PR、ログ、コード、`.env`等へ貼らないでください。

## 3. Read-only review job

Claude review workflowはGitHubへのwrite permissionを要求しません。

- `contents: read`
- `pull-requests: read`
- `issues: read`
- `actions: read`
- Claude Code allowed tools: `Read,Glob,Grep` のみ
- `Write` / `Bash` / GitHub comment toolなし
- review結果は `--json-schema` structured output

Claude実行後のtrusted shell stepは、structured outputを検証し、current PR HEADが固定HEADと一致することを再確認し、レビュー本文を `GITHUB_STEP_SUMMARY` へ表示します。`critical` / `important` の場合はjobをfailureにします。

GitHub PRコメントやcustom check/statusをreview workflowから発行しないため、通常のPR `GITHUB_TOKEN` にwrite権限を与える必要がありません。

## 4. 同一repository内PR

`Claude PRレビュー` workflowは `pull_request` の `opened / synchronize / ready_for_review / reopened` で起動します。

安全策:

- eventのHEAD/base SHAを固定
- workspace rootには信頼済みbase SHAをcheckout
- PR HEAD snapshotとdiffは `$RUNNER_TEMP` に分離
- Claudeは固定diff/固定snapshotだけを読む
- PR内の指示・prompt・commandはレビュー対象データとして扱い、命令として従わない
- review完了時にcurrent HEADとの一致を再確認
- 同一PRへpushされた場合は古いrunをcancel
- Claude実行失敗、structured output不正、HEAD不一致、`critical` / `important` はworkflow failure

## 5. fork由来PR

fork PRにはrepository secretを渡さないため、自動workflowは意図的にスキップします。maintainerがdefault branch上の `Claude 外部PRレビュー（手動）` を実行し、PR番号を指定します。

制約:

- 信頼済みdefault branchだけをcheckoutし、履歴確認と固定OID間diff生成のため `fetch-depth: 0` を使用する
- fork headをcheckout/executeしない
- 開始時にPRの `headRefOid` と `baseRefOid` を取得して固定する
- GitHubのbase repositoryが公開する `refs/pull/<PR>/head` をfetchし、取得したOIDが固定済み `headRefOid` と完全一致することを確認する
- liveなPR番号を参照する `gh pr diff` は使用せず、固定済みbase/head OIDに対して `git diff --no-ext-diff --no-textconv <base OID>...<head OID>` を実行し、immutableなレビュー差分を `$RUNNER_TEMP` へ保存する
- diff生成直後とreview完了時にcurrent `headRefOid` / `baseRefOid` が固定OIDと一致することを再確認し、不一致ならfailする
- Claude jobはread-only
- 現在は**default branch向けfork PRのみ**サポートし、その他のbase branchはfailする
- review結果はActions Job Summaryへ表示し、`critical` / `important` はworkflow failure

`pull_request_target` でfork headをcheckoutし、Secret付きで実行する構成は禁止します。

## 6. Structured output

```json
{
  "highest_severity": "none | proposal | important | critical",
  "review_markdown": "日本語のレビュー本文"
}
```

- `critical`: 「重大」が1件以上
- `important`: 「重要」が1件以上で重大なし
- `proposal`: 提案のみ
- `none`: 指摘なし

`critical` / `important` はworkflow failureとなり、修正後の最新HEADで再レビューします。

## 7. Action固定

Secretへアクセスする第三者Actionはmutable tagではなくfull commit SHAへ固定します。

- `anthropics/claude-code-action`: `9cdae7f0d995e3ba7c33f226087fdf82a59cd520`
- `actions/checkout`: `d23441a48e516b6c34aea4fa41551a30e30af803`

更新時は上流tag/releaseとの対応、新旧差分、権限影響を確認します。

## 8. 現在のマージ強制モデル

Codex + Claude の二重レビューは**必須の運用ポリシー**です。ただしIssue #4完了までは、PR branchから偽装不能なrepository-level required workflow/appとしては強制していません。

理由:
- same-repository write権限を持つ主体は、自身のbranchからGitHub Actions workflowを追加・変更できる
- 同名のcommit status/check runだけをrequiredにしても、通常の`GITHUB_TOKEN`発行なら強固なsecurity boundaryにならない
- Codex側にも現時点でrepository独自のmachine-readable required gateはない

したがって暫定運用では、マージ担当者（人間またはエージェント）が**current PR HEAD SHA**に対して以下を明示確認します。

- Codexの `Reviewed commit` がcurrent HEADと一致
- Claude workflow runがcurrent HEADで完了している
- Claude Job Summaryの `レビュー対象HEAD` がcurrent HEADと一致
- Codex / Claudeに未解決の `重大` / `重要` がない
- 必須CIが成功
- blocking review threadがない

レビュー後にcommitが追加された場合、旧HEADレビューは無効とし両方再実行します。

## 9. より強いmachine enforcement

Issue #4 `Ruleset / 専用GitHub Appで自動レビューゲートを強制する` で以下を導入・検証します。

- GitHub Rulesets Required workflows、または
- PR branchの`GITHUB_TOKEN`から偽装できない専用GitHub App/issuer
- Codex reviewをcurrent HEADへ機械的に結び付ける方式
- fork PRを含むfail-closed動作

**追加のwrite collaboratorを許可する前にIssue #4を完了**します。

## 10. Codexレビュー

CodexはGitHub側のCodex連携からレビューします。PRをReadyにするか `@codex review` で再レビューを依頼します。

マージ前にCodexの `Reviewed commit` がcurrent HEADと一致することを確認します。現時点ではこの照合をrepository owner / merge agentが行います。

## 11. マージ条件

以下をすべて満たすまでマージしません。

- Codexがcurrent PR HEADをレビュー済み
- Claude workflowがcurrent PR HEADで成功
- Codex / Claudeの `重大` / `重要` をすべて解消、または非該当理由を明記済み
- 必須CI成功
- 未解決blocking review threadなし

## 12. 開発プロセス上のデータ送信

Claude automated reviewを実行すると、固定PR diffやレビューに必要なrepository contextがAnthropicのClaudeサービスへ送信されます。これはServerSentinel製品利用者の監視映像・音声・運用データを送るものではなく、**GitHub開発プロセスのPRレビュー**に限定されます。

コントリビュータはPRへSecret、実録画、実人物画像、private infrastructure情報を含めないでください。

## セキュリティ要点

- OAuth tokenをcommitしない
- `CLAUDE_CODE_OAUTH_TOKEN` はGitHub Actions Secretのみ
- Claude workflowへGitHub write権限を与えない
- fork PRへSecretを直接渡さない
- 未信頼fork headをSecret付きworkflowでcheckout/executeしない
- review対象HEADをworkflow summaryに明記する
- Secretへアクセスする第三者Actionはfull commit SHA固定
- review入力は `$RUNNER_TEMP` に置く
- workflow/job名を、悪意あるsame-repository writerに対するsecurity boundaryとはみなさない
