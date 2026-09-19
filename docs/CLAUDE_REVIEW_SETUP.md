# Claude PRレビュー初期設定

ServerSentinelでは、PRのマージ前に **Codex + Claude の二重レビュー**を必須とします。

この仕組みはレビュー品質・事故防止のための運用ゲートです。Issue #4が完了するまでは、same-repository write権限を持つ悪意ある/侵害済みmaintainerに対する完全なrepository-level security boundaryではありません。

## 1. レビュー経路

- 同一repository内PR: `.github/workflows/claude-review.yml` が自動実行
- fork PR: `.github/workflows/claude-review-fork.yml` をmaintainerが手動実行

外部/未信頼コントリビュータはfork PRを使用します。Issue #4完了まではsame-repository write accessを信頼済みmaintainerに限定します。

## 2. 認証

Claude側はrepository secret `CLAUDE_CODE_OAUTH_TOKEN` を使用します。TokenはIssue/PR/log/code/`.env`へ貼りません。

## 3. Read-only job

Claude job:

- `contents: read`
- `pull-requests: read`
- `issues: read`
- `actions: read`
- allowed tools: `Read,Glob,Grep`
- `Write` / `Bash` / GitHub write toolなし
- structured outputのみ返す

PR内容は未信頼データとして扱い、PR内のprompt/commandへ従いません。

## 4. HEAD + baseを固定する理由

レビュー対象は「HEAD commit」だけではなく、**固定baseに対する固定HEADの差分**です。

同じHEADでもbase branchが進めば、実際にmergeされる差分/コンテキストが変わります。そのためsame-repository workflowでもfork workflowと同様に次を固定・再確認します。

```text
PINNED_HEAD_SHA
PINNED_BASE_SHA
```

開始時、diff作成前後、レビュー完了前/完了直前に現在の `headRefOid` / `baseRefOid` と固定OIDを比較し、どちらかが変化したらfailして最新差分で再レビューします。

## 5. 同一repository内PR

安全策:

- eventのHEAD/base SHAを固定;
- current `headRefOid` / `baseRefOid` がevent固定値と一致することを開始時に確認;
- workspace rootは信頼済みbase SHA;
- PR HEAD snapshot/diffは `$RUNNER_TEMP` に分離;
- `git diff <base>...<head>` の固定差分だけをレビュー;
- Claude実行後もHEAD/base両方を再確認;
- 同一PRへpushされた古いrunはcancel;
- Claude失敗、structured output不正、HEAD/base不一致、`critical`/`important` はfailure.

## 6. fork PR

fork PRへrepository secretを直接渡しません。maintainerがdefault branchの手動workflowを実行します。

- default branchを信頼済みworkspaceとしてcheckout;
- `headRefOid` / `baseRefOid` を固定;
- GitHubのPR head refから固定head OIDだけを取得;
- live `gh pr diff` ではなく固定OID間のgit diffを生成;
- review完了時もHEAD/base両方を再確認;
- untrusted fork codeをSecret付きで実行しない;
- `pull_request_target` でfork headをcheckout/executeしない.

## 7. Structured output

```json
{
  "highest_severity": "none | proposal | important | critical",
  "review_markdown": "日本語のレビュー本文"
}
```

`critical` / `important` はworkflow failureです。

## 8. Action固定

Secretへアクセスするthird-party Actionはfull commit SHAへ固定します。

- `anthropics/claude-code-action`: `9cdae7f0d995e3ba7c33f226087fdf82a59cd520`
- `actions/checkout`: `d23441a48e516b6c34aea4fa41551a30e30af803`

更新時は上流release/tagとの対応と権限影響を確認します。

## 9. 暫定マージ強制モデル

Issue #4完了まではmerge actorが以下を明示確認します。

- Codex `Reviewed commit` がcurrent HEADと一致;
- Claude runがcurrent HEAD **かつcurrent base** の固定差分を対象に成功;
- Codex/Claudeの重大/重要が解消;
- 必須CI成功;
- blocking review threadなし.

HEADまたはbaseが変わったら旧レビューはstaleです。

## 10. Issue #4後の強化

Rulesets Required workflowsまたは専用GitHub App/issuer等で、PR branchの通常`GITHUB_TOKEN`から偽装できないmachine enforcementを導入/検証します。追加のwrite collaboratorを広げる前に完了させます。

## 11. 開発プロセスのデータ送信

Claude reviewでは固定PR diffと必要なrepository contextがAnthropicのClaudeサービスへ送信されます。製品利用者の監視映像/運用データを送る機能ではありません。

コントリビュータはPRへSecret、実録画、実人物画像、private infrastructure情報を含めません。Repository/CI media fixtureはsynthetic/generated onlyです。
