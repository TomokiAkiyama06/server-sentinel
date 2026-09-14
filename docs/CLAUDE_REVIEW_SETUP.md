# Claude PRレビュー初期設定

ServerSentinelでは、PRのマージ前に **Codex + Claude の二重レビュー**を必須とします。

この文書では、現在のレビュー経路と、その**信頼境界**を明確にします。現段階のレビューworkflowはレビュー品質・事故防止のための仕組みであり、same-repository write権限を持つ悪意ある/侵害済みmaintainerに対する強固なrepository-level security boundaryではありません。より強い機械的強制は Issue #4 でRuleset Required workflowsまたは専用GitHub App等を導入して実現します。

## 1. レビュー経路

- 同一repository内のPR: `.github/workflows/claude-review.yml` が自動実行
- fork由来の外部PR: `.github/workflows/claude-review-fork.yml` をmaintainerが手動実行

外部・未信頼コントリビュータはfork PRを使用します。Issue #4が完了するまでは、same-repository write accessは信頼済みmaintainerに限定します。

## 2. 認証

Claude側の認証にはrepository secret `CLAUDE_CODE_OAUTH_TOKEN` を使います。

生成:

```bash
claude setup-token
```

GitHubで `Settings -> Secrets and variables -> Actions -> New repository secret` を開き、次を登録します。

```text
Name: CLAUDE_CODE_OAUTH_TOKEN
Value: claude setup-token で生成した値
```

TokenはIssue、PR、ログ、コード、`.env` 等へ貼らないでください。

## 3. 権限分離

Claude自身が動くreview jobと、GitHubへ結果を投稿するtrusted post jobを分離します。

### Claude review job

- GitHub権限はread-only
- Claude Code allowed toolsは `Read,Glob,Grep` のみ
- `Write` / `Bash` / GitHub comment toolは与えない
- PR由来データは未信頼入力として扱う
- review結果は `--json-schema` によるstructured outputとして返す

このjobはGitHubへレビューを書き込めず、PR内prompt injectionから任意shell実行やbotコメント投稿へ直結しない構成です。

### Trusted post job

review jobのstructured outputをデータとして受け取り、次を行います。

1. current PR HEADと固定HEADの一致確認
2. structured outputの検証
3. Secretらしき値の機械的伏字化
4. 固定HEAD SHA入りのClaudeレビューコメント投稿
5. `github-actions[bot]` 投稿であることをAPI応答から確認
6. 投稿後にもう一度current HEAD一致確認
7. `critical` / `important` ならjobをfailureにする

40桁hex commit SHAはsecret redaction前に退避し、長いtoken検出の誤検知から保護します。

## 4. 同一repository内PR

`Claude PRレビュー` workflowは `pull_request` の `opened / synchronize / ready_for_review / reopened` で起動します。

安全策:

- eventで受け取ったHEAD/base SHAを固定
- workspace rootには信頼済みbase SHAをcheckout
- PR HEAD snapshotとdiffは `$RUNNER_TEMP` に分離
- Claudeは固定diff/固定snapshotだけを読む
- PR内の指示・prompt・commandはレビュー対象データとして扱い、命令として従わない
- 同一PRへpushされた場合は古いrunをcancel
- review/postのどちらかが失敗したらそのrunは失敗扱い

## 5. fork由来PR

fork PRにはrepository secretを渡さないため、自動workflowは意図的にスキップします。maintainerが `Claude 外部PRレビュー（手動）` を実行し、PR番号を指定します。

制約:

- repositoryの信頼済みdefault branchのみcheckout
- fork headをcheckout/executeしない
- fork HEAD SHAを開始時に固定
- `gh pr diff` で固定diffを `$RUNNER_TEMP` に保存
- diff取得後、投稿直前、投稿後にHEAD一致を確認
- Claude jobはread-only
- trusted post jobだけがレビューコメントを投稿
- 現在は**default branch向けfork PRのみ**をこの経路の対象とし、それ以外のbase branchならfailする

`pull_request_target` でfork headをcheckoutしSecret付きで実行する構成は禁止します。

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

`critical` / `important` のrunはfailureになり、修正後の最新HEADで再レビューします。

## 7. Actionの固定

Secretへアクセスする第三者Actionはmutable tagではなくfull commit SHAで固定します。

- `anthropics/claude-code-action`: `9cdae7f0d995e3ba7c33f226087fdf82a59cd520`
- `actions/checkout`: `d23441a48e516b6c34aea4fa41551a30e30af803`

更新時は上流tag/releaseとcommit SHAの対応、新旧差分、権限影響を確認します。

## 8. 現在のマージ強制モデル

Codex + Claude の二重レビューは**必須の運用ポリシー**です。ただし、Issue #4が完了するまでは、PR branchから偽装不能なrepository-level required workflow/appとしては強制していません。

理由:

- 同一repositoryのwrite権限を持つ主体は、自身のbranchからGitHub Actions workflowを追加・変更できる
- 同名のcommit status/check runだけをrequiredにしても、発行元が通常の`GITHUB_TOKEN`なら強固なsecurity boundaryにならない
- Codex側にも現時点でこのrepository独自のmachine-readable gateはない

したがって暫定運用では、マージ担当者（人間またはエージェント）が**現在のPR HEAD SHA**に対して次を明示確認します。

- Codex reviewがcurrent HEADを対象としている
- Claude reviewコメントの `レビュー対象HEAD` がcurrent HEADと一致する
- 両方に未解決の `重大` / `重要` がない
- 必須CIが成功している
- blocking review threadが残っていない

レビュー後にcommitが1つでも追加された場合、旧HEADレビューは無効とし、両レビューを最新HEADへ再実行します。

## 9. より強いmachine enforcement

Issue #4 `Ruleset / 専用GitHub Appで自動レビューゲートを強制する` で、以下を導入・検証します。

- GitHub Rulesets Required workflows、または
- PR branchの`GITHUB_TOKEN`から偽装できない専用GitHub App/issuer
- Codex reviewをcurrent HEADへ機械的に結び付ける方式
- fork PRを含むfail-closed動作

**追加のwrite collaboratorを許可する前にIssue #4を完了**する方針です。

## 10. Codexレビュー

CodexはGitHub側のCodex連携からレビューします。PRをReadyにするか、`@codex review` で再レビューを依頼します。

マージ前に、Codexの `Reviewed commit` がcurrent HEADと一致することを確認します。現在はこの確認をmerge agent/ownerが行います。

## 11. マージ条件

以下をすべて満たすまでマージしません。

- Codexがcurrent PR HEADをレビュー済み
- Claudeがcurrent PR HEADをレビュー済み
- Codex / Claudeの `重大` / `重要` をすべて解消、または非該当理由を明記済み
- 必須CI成功
- 未解決のblocking review threadなし

## 12. 開発プロセス上のデータ送信

Claude automated reviewを実行すると、PRの固定diffやレビューに必要なリポジトリ内容がAnthropicのClaudeサービスへ送信されます。これはServerSentinel製品利用者の監視映像・音声・運用データを送るものではなく、**GitHub開発プロセスのPRレビュー**に限定されます。

コントリビュータはPRへSecret、実録画、実人物画像、private infrastructure情報を含めないでください。

## セキュリティ要点

- OAuth tokenをcommitしない
- `CLAUDE_CODE_OAUTH_TOKEN` はGitHub Actions Secretのみ
- Claude jobへwrite権限を与えない
- fork PRへSecretを直接渡さない
- 未信頼fork headをSecret付きworkflowでcheckout/executeしない
- review対象SHAをコメントへ明記する
- Secretへアクセスする第三者Actionはfull commit SHA固定
- workflow生成物は `$RUNNER_TEMP` に置く
- 現在のreview workflow/status名を、悪意あるsame-repository writerに対するsecurity boundaryとはみなさない