# Claude PRレビュー設定

> **現在停止中**: 利用可能なClaudeサブスクリプション枠が尽きているため、GitHub Actions上のClaude PRレビューはOwner判断で一時停止しています。停止中は **Codex + CI** をマージ条件とし、Claudeはマージゲートではありません。`.github/workflows/claude-review.yml` と `.github/workflows/claude-review-fork.yml` は停止期間中削除されています。再有効化する場合は、この文書の安全設計を基にworkflowと運用ゲートを同時に復元してください。

以下はClaudeレビューを再有効化するときの設計・運用リファレンスです。

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
- checkout済みworkspaceのHEADが固定base SHAと一致することを検証し、不一致なら停止して再実行（base objectの存在だけでは不十分）;
- GitHubのPR head refから固定head OIDだけを取得;
- live `gh pr diff` ではなく固定OID間のgit diffを生成;
- review完了時もHEAD/base両方を再確認;
- untrusted fork codeをSecret付きで実行しない;
- `pull_request_target` でfork headをcheckout/executeしない.

## 7. Structured outputと公開境界

Claudeの出力schemaには自由記述欄を設けません。`review_markdown`、ファイル名、パス、URL、コード/差分の引用は受け付けません。

```json
{
  "highest_severity": "important",
  "findings": [
    {"severity": "important", "category": "authorization", "diff_line": 42}
  ]
}
```

- `highest_severity`: `none` / `proposal` / `important` / `critical`;
- `findings`: 最大20件、重大・重要を優先;
- findingの`severity`: `proposal` / `important` / `critical`;
- `category`: `requirements` / `correctness` / `security` / `authorization` / `secrets` / `privacy` / `data_loss` / `storage` / `concurrency` / `tests` / `licensing` / `camera_source` / `protocol` / `maintenance`;
- `diff_line`: 固定diffの範囲内にある1始まり整数行番号。

指摘なしは`highest_severity=none`かつ`findings=[]`です。最高重要度は全findingと一致させます。余分なfield、未知enum、不正な行番号、JSON key/同一finding重複、不整合、Action失敗は検証をfailさせます。`critical` / `important`もworkflow failureです。

`display_report: false` / `show_full_output: false`を明示し、Actionの自由文report・全文ログを公開しません。raw responseをstepの環境変数へ渡すとActionsが検証前に表示するため、検証stepは固定Actionのrunner-local execution JSONから最終成功resultの`structured_output`を直接読みます。raw executionはsummary/artifactへ出力しません。JSONが不正な場合もpayload/parse errorをログへ転記せず、定型エラーだけを返します。

公開Job Summaryは検証済みの固定分類ラベル、重要度、行番号、固定HEAD/baseだけから生成します。同じ検証済みreportをjob logにも出し、REST/CLIから指摘位置を取得できるようにします。raw responseは出しません。Secret形式のregex検出やentropy推定には依存しません。場所と分類を基に同じ固定差分を確認し、重大・重要の解消を検証してください。

行番号を再現するには、Summaryの40桁HEAD/baseを次のplaceholderに入れて実行します。

```bash
git -c core.quotePath=true diff --no-ext-diff --no-textconv --no-color --no-renames --diff-algorithm=myers --no-indent-heuristic --src-prefix=a/ --dst-prefix=b/ --unified=3 --inter-hunk-context=0 <base>...<head> | nl -ba
```

## 8. Action固定

Secretへアクセスするthird-party Actionはfull commit SHAへ固定します。

- `anthropics/claude-code-action`: `9cdae7f0d995e3ba7c33f226087fdf82a59cd520`
- `actions/checkout`: `d23441a48e516b6c34aea4fa41551a30e30af803`

更新時は上流release/tagとの対応、権限影響、出力/ログの契約を確認します。現在の固定Actionは[execution JSONをrunner tempへ保存](https://github.com/anthropics/claude-code-action/blob/9cdae7f0d995e3ba7c33f226087fdf82a59cd520/base-action/src/execution-file.ts)し、[SDK resultにstructured_outputを保持](https://github.com/anthropics/claude-code-action/blob/9cdae7f0d995e3ba7c33f226087fdf82a59cd520/base-action/src/run-claude-sdk.ts)します。この契約が変わる場合はvalidatorも更新し、raw responseが公開されないことを再検証します。

## 9. 現在の暫定マージ強制モデル

Claudeレビュー停止中、Issue #4完了まではmerge actorが以下を明示確認します。

- Codexレビュー依頼時に取得した40桁のHEAD/base SHAを、レビュー依頼コメントとPRのレビュー記録へ明記;
- Codexにその固定HEAD/base差分を指定して依頼し、完了時とマージ直前に`Reviewed commit`がcurrent HEAD、依頼時に固定したbase SHAがcurrent baseと一致することを照合;
- Codexの重大/重要が解消;
- 必須CI成功;
- blocking review threadなし.

Codexの`Reviewed commit`だけではbaseを検証できません。依頼時の固定baseの記録と、レビュー完了時・マージ直前のcurrent base照合を必須にします。baseの来歴が確認できないレビューを最終レビューとして採用しません。Issue #4による機械的な強制が完成するまでは、merge actorがこの照合を明示的に行います。

HEADまたはbaseのどちらかが変わったら旧Codexレビューはstaleです。Claudeレビューを再有効化した場合は、復元したworkflowの固定HEAD/base要件も再び満たしてください。

## 10. Issue #4後の強化

Rulesets Required workflowsまたは専用GitHub App/issuer等で、PR branchの通常`GITHUB_TOKEN`から偽装できないmachine enforcementを導入/検証します。追加のwrite collaboratorを広げる前に完了させます。

現状のpersonal repositoryではRequired workflowsの組織設定を利用できません。調査結果、専用AppのOwner設定・鍵分離・collector/publisher契約・復旧手順、disabled ruleset候補生成とoffline検証の範囲は[REVIEW_GATE_SETUP.md](REVIEW_GATE_SETUP.md)に記載しています。実際のApp・repository強制・test PR受入は未完了であり、Issue #4はOpenのままです。

## 11. 開発プロセスのデータ送信

Claude reviewでは固定PR diffと必要なrepository contextがAnthropicのClaudeサービスへ送信されます。製品利用者の監視映像/運用データを送る機能ではありません。

コントリビュータはPRへSecret、実録画、実人物画像、private infrastructure情報を含めません。Repository/CI media fixtureはsynthetic/generated onlyです。
