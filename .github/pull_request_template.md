## 関連 Issue

Closes #

## 変更内容

-

## 変更理由

-

## テスト

- [ ] Unit
- [ ] Integration / API
- [ ] Web checks
- [ ] Camera Source mock (1〜4 source)
- [ ] Mock E2E
- [ ] Docker / build
- [ ] その他:

## 実機・ブラウザ確認

- [ ] 不要
- [ ] `hardware-required`
- [ ] `server-required`
- [ ] `manual-test-required`

実機確認の詳細（Main Server / Capture Node / UVC Cameraそれぞれの必要・不要を記載）:

## セキュリティ / プライバシー / Biometric影響

- [ ] 新たにユーザー環境外へ送信されるデータはない
- [ ] 新しい Secret / pairing credential の取り扱いはない、または安全に管理している
- [ ] owner biometric template/verificationへの影響を確認した、または非該当
- [ ] non-owner enrollment / named identity / cross-camera biometric re-identificationを追加していない
- [ ] non-owner face crop/template/embedding/profileの永続libraryを、氏名の有無を問わず作成・保存していない（権限・保持期間に従う通常録画とは区別）
- [ ] 追加依存関係・モデル・weights のsource/licenseを確認した
- [ ] 必要な仕様・セキュリティ・プライバシー文書を更新した

補足:

## Camera Source影響

- [ ] 固定front/rearや固定2台構成を前提にしていない
- [ ] `local_uvc` / `remote_agent` のどちらかを不必要に特別扱いしていない、または理由を記載した
- [ ] remote-agent pairing/ingest/reconnect/bufferへの影響を確認した、または非該当
- [ ] automatic torch/lightを導入していない

## スクリーンショット

UI変更で添付が必要な場合は、synthetic/generated/demo素材のみを使用する。実人物・実環境の監視映像、実機カメラpreview、実運用環境が写る画像・動画・音声は、本人同意の有無にかかわらずPRへ添付せずローカルに保持する。owner face template/embeddingも添付しない。

## 自動レビュー

マージ前に以下を必須とする。

レビュー依頼時の固定SHAと証跡:

- HEAD SHA:
- BASE SHA:
- Codex レビュー依頼・結果URL:
- Claude レビュー: 一時停止中（Ownerが再有効化するまで非ゲート）

- [ ] Codex レビュー完了（固定HEAD/base差分）
- [ ] 完了時とマージ直前に、レビュー対象HEAD/baseがcurrent HEAD/baseと一致すると確認（Codexは`Reviewed commit`に加えて依頼時のbase記録も照合）
- [ ] Claudeレビューが再有効化されている場合のみ、そのレビューゲートも完了
- [ ] HEADまたはbase変更後は両レビューを最新の固定差分で再実行（baseのみの変更を含む）
- [ ] 両レビューの重大・重要な指摘を解消
- [ ] 必須CI成功
- [ ] 未解決のブロッキングレビューがない

PRタイトル・本文、およびエージェントが投稿するレビュー対応コメントは原則日本語で記載する。技術用語、識別子、コード、固有名詞は英語のままでよい。
