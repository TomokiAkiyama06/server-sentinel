# 2026-10-22: 重みのライセンスが明確な人物検出モデルの調査（Issue #20）

- Status: **Accepted（Q1〜Q4、Owner 判断 2026-10-22）／ Q5・Q6 は未決**。
  下の「Owner 判断（2026-10-22）」の節を見てください。D-FINE の評価は承認済みですが、本番採用はまだ承認されていません。
- Date: 2026-10-22
- Related: Issue #20、`docs/THIRD_PARTY_POLICY.md`、
  [`2026-09-30-yolox-person-evaluation.md`](2026-09-30-yolox-person-evaluation.md)、
  `server/docs/DETECTOR_MODEL_AUDIT.md`、`server/docs/YOLOX_EVALUATION_AUDIT.md`、
  `server/docs/RTDETR_RUNTIME_AUDIT.md`、`server/docs/DETECTOR_FOUNDATION.md`
- Scope: 文書だけです。この文書は依存、lock、`license/components.json` /
  `license/owner-approvals.json` の記録、コード、重みファイルのどれも追加しません。
  どの重みも採用・同梱・再配布・自動 download を承認しません。

## Owner 判断（2026-10-22）

Owner は 2026-10-22 に、下の「Owner への質問」の Q1〜Q4 について次のとおり判断しました。
Q5 と Q6 は未決です。

- **Q1（重みのライセンスの基準）**：**新しく本番採用する重みには、配布元による明示を必須とします。**
  RT-DETRv2-S は維持します。ただし、根拠が弱いことを既知の弱点として記録します
  （`apache-2.0` は Hugging Face の変換者の metadata で、原著者の表明はなく、upstream の
  [RT-DETR #685](https://github.com/lyuwenyu/RT-DETR/issues/685) は未回答）。
  RT-DETRv2 を置き換えるかどうかは、D-FINE の評価の後に判断します。
  `server/docs/RTDETR_RUNTIME_AUDIT.md` の「Official model」という記述の訂正は、別の follow-up で行います。
- **Q2（学習データの残余リスク）**：COCO の画像（Flickr の条件）と、backbone の ImageNet 系
  事前学習（non-commercial research の条件）の残余リスクを、**研究室内での運用に限り、
  重みを再配布しない範囲で受け入れます**。これは Owner の承認として、この文書に記録します。
  `license/owner-approvals.json` にはまだ入れません。重みの `model_weight` component を追加する
  PR で、この文書を参照する approval entry として記録します。
- **Q3（Objects365 系譜）**：Objects365 を事前学習に使った重みは、**当面除外します**。
  RF-DETR は候補から外します（D-FINE の maintainer の見解とも整合します）。
- **Q4（D-FINE の評価）**：**D-FINE-N / S の COCO-only checkpoint を、評価専用で追加します。**
  artifact は upstream の元の `dfine_{n,s}_coco.pth`（`Peterande/storage` の release `dfinev1.0`）から作ります。
  `torch.load(..., weights_only=True)` を使い、隔離した環境で ONNX に export します。
  HF の `ustc-community/dfine-{nano,small}-coco` の safetensors は、値が一致するかの照合だけに使います。
  扱いは YOLOX と同じです：重みはリポジトリ外、digest 固定、CI での download なし、
  deployment schema では拒否。
- **Q5（export 用の環境）**：未決です。
- **Q6（YOLOX の評価用 adapter）**：未決です。

### Q1 と D-FINE の関係

今ある D-FINE の根拠は、書き込み権限を持つ maintainer の Issue コメントです。論文の著者や、
重みを upload した `Peterande` の表明ではありません。Q1 の「配布元による明示」が原著者や
upload した人を指すなら、この根拠だけでは**本番採用の条件を満たしません**。

- **評価は進めてかまいません**（Q4）。
- **本番採用の前に**、次のどちらかが必要です。
  1. upstream（`Peterande` または論文の著者）が、README か release notes で、COCO-only の重みが
     Apache-2.0 であると明示する。
  2. この maintainer の表明で足りると、Owner が別に判断する。

## 背景

2026-09-30 の Owner 判断で YOLOX を評価しましたが、公式の学習済み重みに明示的な
ライセンスがないため、採用は保留になっています（upstream
[Issue #1865](https://github.com/Megvii-BaseDetection/YOLOX/issues/1865) は 2026-10-22
時点でも open です。maintainer の回答はありません。2026-10-14 に第三者が、商用の医療製品での利用について同じ趣旨の質問を追加しただけです）。

2026-10-22 の Owner 判断（Issue #20 のコメント）により、**重みのライセンスが明確な**
人物検出モデルを調査します。成果物は docs だけで、採用は調査の後に改めて判断します。

## 前提（変わらない条件）

- 人物 detector の失敗・skip・品質不足・model 不在は必ず `unknown` / unavailable です。
  `no person` / `absent` にはしません（REQUIREMENTS DET-007、SPECIFICATION §7.5、
  PRIVACY.md）。低照度は #22 の detector 別品質ゲートで `unknown` になります。
- 人物検出は「人がいるか」だけを扱います。人物の識別、non-owner の名前付き顔 DB、
  カメラ間の biometric re-identification はしません。Owner の顔照合（#25 / #206）は
  別の判断で、MVP では無効のままです。この調査の対象外です。
- 推論は Main Server で行い、既存の isolated worker（`app.detection.foundation`）を使います。
  実行時の model download、URL 指定、fallback model への切り替えはしません。
- 本番の runtime は CPU のみです（`onnxruntime==1.28.0` CPU wheel）。
  `onnxruntime-gpu` は評価専用で、NVIDIA の CUDA / cuDNN / TensorRT は proprietary の
  条件のため、リポジトリの lock や allowlist には入れません（2026-09-30 判断）。
- license gate（`scripts/ci/license_gate.py`）は、`model_code` と `model_weight` を別々に
  記録し、weights は予約ディレクトリに commit された実体と SHA-256 で照合します。
  現在、commit された重みはありません（`model_weight` scope は `reviewed-empty`）。
  RT-DETRv2 と同じく、運用者がリポジトリ外に置いた digest 固定の artifact を読む形を想定します。
- `docs/THIRD_PARTY_POLICY.md` の規則：GPL / AGPL / 不明ライセンスは Owner 承認なしに
  入れません。コードのライセンスは重みのライセンスを意味しません。

## 判定の基準

「重みのライセンスが明確」とは、この文書では次のどれかを指します。強い順に並べます。

1. **配布元（原著者・公式組織）が、重みファイルそのもののライセンスを文章で明示している。**
2. 重みを配布する場所（release を持つ repository、model card）に、明示的なライセンス
   metadata がある。ただし変換者による metadata は 1 より弱い根拠です。
3. コードの repository のライセンスだけがある。重みについては何も書いていない
   → **不明** とします（YOLOX と同じ扱い）。

学習データの条件は、重みのライセンスとは別の問題として記録します。

- **COCO**：annotation は CC BY 4.0、画像は COCO Consortium の所有ではなく、Flickr の
  利用条件に従うと書かれています
  （[terms of use の原文](https://github.com/cocodataset/cocodataset.github.io/blob/master/dataset/termsofuse.htm)。
  cocodataset.org の該当ページは script で描画されるため、site の repository 上の原文を
  2026-10-22 に確認しました）。
- **Objects365**：[公式 download ページ](https://www.objects365.org/download.html)に
  「The Objects365 dataset is available for the academic purpose only.」と書かれています
  （annotation は CC BY 4.0、画像は Flickr 条件、画像の再配布は禁止）。
- **ImageNet**：[terms of access](https://image-net.org/download.php) は
  「non-commercial research and educational purposes」に限ります。多くの detector の
  backbone は ImageNet で事前学習されています。

学習済みパラメータが学習画像の条件をどこまで引き継ぐかは、法的に決着していません。
**この文書は法的結論を出しません。** 根拠の強さと残るリスクを並べ、Owner が判断できる
ようにします。

## 候補の比較

すべて 2026-10-22 に確認しました。AP は upstream が公表した COCO val2017 の全クラス
AP<sup>val</sup> です。**この調査では測定していません。** person クラスだけの AP は、
どの候補も upstream が公表していません（Main host での測定が必要です）。

### 表 1：ライセンスと学習データ

| 候補 | コード | 重みのライセンスと根拠 | 学習データ | 判定 |
| --- | --- | --- | --- | --- |
| **D-FINE（`*_coco` のみ）** | Apache-2.0（[Peterande/D-FINE](https://github.com/Peterande/D-FINE)） | **Apache-2.0（upstream の maintainer が明示）**。書き込み権限を持ち現在も活動している maintainer の RicePasteM（Zhangchi Hu, USTC。GitHub 上の関係は `COLLABORATOR`。2026-07 に PR #355 を merge し、2026-08-19 に README を更新）が、[Issue #357 のコメント](https://github.com/Peterande/D-FINE/issues/357#issuecomment-5344034723)（2026-08-19）で「COCO-only checkpoints (`*_coco.pth`) are also released by us under Apache-2.0」と明言。ただしこの人は論文の著者でも、重みを upload した人（`Peterande`）でもない。README にあるのは Objects365 系の重みについての否定的な note だけで、COCO-only の重みを Apache-2.0 とする文はない。重みの release を持つ [Peterande/storage](https://github.com/Peterande/storage) は Apache-2.0 の LICENSE を持つが、release 自体には重みのライセンスの記載がない。HF の [ustc-community/dfine-small-coco](https://huggingface.co/ustc-community/dfine-small-coco) の `apache-2.0` は変換者（card では contributed by VladOS95-cyber）が付けた metadata | COCO train2017。backbone は HGNetv2 の ImageNet 系事前学習（`PPHGNetV2_*_stage1.pth`、詳細な系譜は未検証） | **候補（最有力）** |
| D-FINE（`*_obj365` / `*_obj2coco`） | 同上 | 同じコメントで「should not be considered commercially cleared」。README にも同趣旨の [License note](https://github.com/Peterande/D-FINE/blob/956d1709314c2c6a4df6f34de232054578a7449f/README.md)（commit `956d170`） | Objects365 → COCO | 除外（Objects365 は academic only） |
| **RT-DETRv2-S（r18vd、COCO）** | Apache-2.0（[lyuwenyu/RT-DETR](https://github.com/lyuwenyu/RT-DETR)。maintainer が [#433](https://github.com/lyuwenyu/RT-DETR/issues/433) で「entire codebase is licensed under Apache 2.0」と回答） | **HF metadata で `apache-2.0`**（[PekingU/rtdetr_v2_r18vd](https://huggingface.co/PekingU/rtdetr_v2_r18vd/blob/5650961749fa93567c0d46fc7f43ea4f9e914107/README.md)。card には「contributed by @jadechoghari」とあり、Hugging Face 側の変換）。採用済み adapter が使う [onnx-community 変換](https://huggingface.co/onnx-community/rtdetr_v2_r18vd-ONNX/blob/936f90b6a476c6da4dfe053fc521af55285976ba/README.md)も `apache-2.0`。**原著者による重みの表明はない**：元の `.pth` を置く [lyuwenyu/storage](https://github.com/lyuwenyu/storage) には LICENSE がなく、重みについて尋ねる [Issue #685](https://github.com/lyuwenyu/RT-DETR/issues/685)（2026-08-19）は回答 0 件で open | COCO train2017。backbone は ImageNet 系事前学習（未検証） | **候補（既存の比較基準）** |
| RT-DETR / RT-DETRv2 の Objects365 版 | 同上 | 明示なし | Objects365 → COCO | 除外 |
| RF-DETR Nano / Small / Medium / Large | Apache-2.0（[roboflow/rf-detr](https://github.com/roboflow/rf-detr)） | **Apache-2.0（配布元が明示）**。README の License 節：「Apache-designated model weights are licensed under Apache License 2.0」。model 表で N/S/M/L が Apache 2.0。Atto/Femto/Pico/XL/2XL は **PML 1.0**（別ライセンス、対象外） | 公式 docs は「trained on the Microsoft COCO dataset」。ただし [論文](https://arxiv.org/html/2511.09554v2)の Table 6 注に「All models are pretrained with 60 epochs of Objects-365」。Table 11 の caption も Objects365 事前学習を前提にしている。配布 checkpoint についての明示はなく未確定。backbone は DINOv2（LVD-142M で学習、系譜は未検証） | 条件付きとして調査 → **Q3（2026-10-22）で除外** |
| YOLOX | Apache-2.0 | **不明**（上記 #1865） | COCO | 保留中（既存判断のまま） |
| DEIM / DEIMv2 | DEIM：LICENSE は Apache-2.0 の本文（GitHub の判定は `NOASSERTION`） | 重みは Google Drive。明示なし。DEIMv2 は DINOv3（Meta の独自ライセンス）由来の variant があり、[DEIMv2 #167](https://github.com/Intellindust-AI-Lab/DEIMv2/issues/167) が未回答 | COCO / Objects365 | 除外（不明） |
| Ultralytics YOLOv8 / YOLO11 など | AGPL-3.0 | AGPL-3.0（重みも同じ条件で配布）。商用の Enterprise License は有償の個別契約 | COCO ほか | 除外（ポリシーで既定ブロック） |
| YOLOv6 / YOLOv7 / YOLOv9 | GPL-3.0（meituan/YOLOv6、WongKinYiu/yolov7・yolov9） | GPL-3.0 の repository の release | COCO | 除外（GPL） |
| YOLOv10 | AGPL-3.0（THU-MIG/yolov10） | 同上 | COCO | 除外（AGPL） |
| MMYOLO | GPL-3.0（open-mmlab/mmyolo） | — | — | 除外（GPL） |
| RTMDet（MMDetection） | Apache-2.0 | 明示なし。model zoo の重みのライセンスを尋ねる [mmdetection #11484](https://github.com/open-mmlab/mmdetection/issues/11484)（2024-02、2026-10-15 にも RTMDet-tiny について追加質問）に maintainer の回答なし | COCO。backbone CSPNeXt は ImageNet 事前学習（upstream README） | 除外（不明） |
| PP-YOLOE / PP-YOLOE+ | Apache-2.0（PaddleDetection） | 明示なし。[#9499](https://github.com/PaddlePaddle/PaddleDetection/issues/9499)（PP-YOLOE+_s の重みと ONNX 再配布）が未回答 | PP-YOLOE+ は Objects365 事前学習（[configs/ppyoloe/README.md](https://github.com/PaddlePaddle/PaddleDetection/blob/develop/configs/ppyoloe/README.md)） | 除外（不明、+ は Objects365） |
| torchvision の detection model（Faster R-CNN、RetinaNet、FCOS、SSD、SSDlite） | BSD-3-Clause | [公式 docs](https://docs.pytorch.org/vision/stable/models.html) が「may have their own licenses or terms and conditions derived from the dataset used for training. It is your responsibility to determine whether you have permission」と明記。**明示的な許諾ではない** | COCO | 除外（配布元自身が条件を保証しない） |
| NanoDet / NanoDet-Plus | Apache-2.0 | 重みは GitHub release / Google Drive。明示なし | COCO | 除外（不明） |
| EfficientDet（google/automl） | Apache-2.0、repository は archived | 明示を見つけられなかった（深くは未検証） | COCO | 除外（不明・保守終了） |
| MediaPipe Object Detector（EfficientDet-Lite0/2、SSD MobileNetV2） | Apache-2.0 | [解説ページ](https://developers.google.com/edge/mediapipe/solutions/vision/object_detector)に model のライセンスの記載なし（ページ本文は CC BY 4.0） | COCO | 除外（不明、TFLite 形式） |
| OpenVINO Open Model Zoo `person-detection-0202` など | Apache-2.0（repository は「maintenance mode」） | [model README](https://github.com/openvinotoolkit/open_model_zoo/blob/master/models/intel/person-detection-0202/README.md) に重みのライセンスの記載なし。学習データの記載なし | 不明（AP 0.322 は Intel 内部 test set） | 除外（不明、OpenVINO IR で新しい runtime が必要） |

DETR（`facebook/detr-resnet-50`、HF card `apache-2.0`）も重みの metadata は明示されていますが、
real-time 用ではなく CPU の負荷が大きいため、比較から外しました（性能は未検証）。

### 表 2：精度・大きさ・実行環境（upstream の公表値、測定していません）

| 候補 | COCO AP<sup>val</sup> | Params | 入力 | ONNX / 既存 runtime との適合 | 保守 |
| --- | ---: | ---: | --- | --- | --- |
| D-FINE-N（`dfine_n_coco`） | 42.8 | 4M | 640 | upstream に `tools/deployment/export_onnx.py`（opset 16。出力は `labels/boxes/scores` で後処理込み）。HF 変換版は RT-DETRv2 と同じ `RTDetrImageProcessor` 設定（640×640 直接 resize、/255、normalize なし、300 query、class 0 = person）。**ライセンス metadata のある ONNX は配布されていない**（`onnx-community/dfine_*_coco-ONNX` は license 欄が空）ので、自前で export が必要 | 最終 push 2026-10-05 |
| D-FINE-S（`dfine_s_coco`） | 48.5 | 10M | 640 | 同上 | 同上 |
| D-FINE-M（`dfine_m_coco`） | 52.3 | 19M | 640 | 同上 | 同上 |
| RT-DETRv2-S（r18vd） | 48.1（GitHub の再学習版）。HF card は数値なし | 20M | 640 | **adapter 実装済み**（`rtdetr-v2-r18vd-onnx-cpu`、onnx-community 変換、81,057,510 bytes、SHA-256 固定）。ORT 1.28 CPU で動作確認済み | 最終 push 2026-10-09 |
| RF-DETR Nano | 48.4（README）／48.0（論文 Table 2） | 30.5M | 384 | `rfdetr` package に ONNX export がある。package は既定で `repo.roboflow.com` から重みを download し、照合は MD5 だけ。PyTorch / transformers 系の依存が大きい | 活発（release 1.11.2、2026-10-04） |
| RF-DETR Small | 53.0（README）／52.9（論文） | 32.1M | 512 | 同上 | 同上 |
| YOLOX-S / Tiny（参考） | 40.5 / 32.8（upstream model zoo、未再確認） | 9.0M / 5.1M | 640 / 416 | 評価用 adapter 実装済み | 最終 release 2022 |

D-FINE と RT-DETRv2 の公表 latency は T4 + TensorRT FP16 の値で、Main host の CPU 値ではありません。
既存の Main host 測定（`DETECTOR_FOUNDATION.md`、generated frame）は、benchmark の修正前の値で、
同文書で superseded とされています。**比較には使えません。** 新しい候補と同じ条件で測り直す必要があります。
D-FINE-N/S は params と FLOPs が RT-DETRv2-S より小さい（upstream 表：D-FINE-N 7 GFLOPs、S 25 GFLOPs。
RT-DETR README の R18 は 60 GFLOPs）ので CPU でも速い見込みですが、**未測定です**。

GPU：どの候補も upstream は ONNX → TensorRT の手順を示しています。ただし TensorRT と
`onnxruntime-gpu` の CUDA 部分は NVIDIA の proprietary 条件で、2026-09-30 判断により評価専用です。
本番は CPU のみ、という前提はこの調査でも変えません。

## 候補ごとの所見

### D-FINE（COCO-only checkpoint）— 推奨

- 調べた候補の中で、**重みのライセンスを upstream の maintainer が文章で明示し、しかも Objects365 系譜の
  重みを自分たちで除外している**のは D-FINE だけです。この点で、調べた候補の中で根拠が最も強いです。
  ただし根拠の中身は次のとおりで、どれも原著者や upload した本人の文ではありません。
  - 書き込み権限を持つ現役 maintainer（RicePasteM）の Issue #357 のコメント。論文の著者でも、
    重みを upload した `Peterande` でもありません。
  - 重みの置き場所である storage repository が Apache-2.0 の LICENSE を持つこと。release
    （`dfinev1.0`、release の公開は 2024-10-01）には重みのライセンスの記載がありません。
    asset ごとの upload 日は `dfine_s_coco.pth` が 2024-10-02、`dfine_n_coco.pth` が 2024-11-06
    （どちらも uploader は `Peterande`）。
  - README の note は Objects365 系の重みを除外する否定的な文だけです。
  - HF card の `apache-2.0` は変換者（VladOS95-cyber）が付けた metadata です。
- 前処理と出力の形が RT-DETRv2 と同じ系統なので、既存の `RtDetrPersonDetector` と同じ形の
  adapter で扱えます（focal-loss の sigmoid score、class 0 = person、640×640 RGB、
  品質ゲート後だけ評価、異常時は `unknown`）。
- 残る課題：
  - **ONNX は自前で作る必要があります。** 方法は 2 つあります。
    (a) 元の `dfine_{n,s}_coco.pth` を upstream の `export_onnx.py` で export する。
    GitHub release は `digest: null` で checksum を配っていないので、size と SHA-256 は
    download 後にローカルで計算するしかありません。`torch.load` は pickle を読むので、
    `weights_only=True` で、隔離した scratch 環境で行います。
    (b) HF の `ustc-community/dfine-{nano,small}-coco` の `model.safetensors`（LFS SHA-256 あり、
    pickle なし）から export する。HF 変換が元の `.pth` と同じ値かどうかは**未検証**です。
  - export には PyTorch などが要ります。runtime の依存にはせず、GPU 評価と同じく
    commit しない scratch 環境で行い、手順、tool の version、出力 ONNX の SHA-256 を記録します。
  - export した graph が標準 ONNX domain だけを使い、ORT 1.28 CPU で全 node が動くかは
    **未確認**です（D-FINE の decoder は RT-DETRv2 と同じ GridSample 系の op を使う想定）。
  - backbone（HGNetv2 stage1）の ImageNet 系事前学習は、D-FINE の Apache-2.0 表明でも
    解消されません。これは RT-DETRv2 と同じ残余リスクです。
  - **原著者または upload した本人（`Peterande`）に確認を求めます。** 本番採用の前に、
    COCO-only の重みが Apache-2.0 であることを README か release notes に書いてもらうよう
    upstream に依頼することを提案します（Owner の判断事項）。

### RT-DETRv2-S（r18vd）— 比較基準として維持

- adapter、digest 固定、CPU smoke、Main host の latency 測定まですでにあり、deployment schema が
  名前で受け付ける唯一の人物 model です。
- ただし重みの `apache-2.0` は Hugging Face 側の変換者が付けた metadata で、原著者の表明は
  ありません（Issue #685 は未回答）。既存の audit（`RTDETR_RUNTIME_AUDIT.md`）は PekingU の
  card を「Official model」と書いていますが、card 自体は「contributed by @jadechoghari」です。
  この点は既存の判断の根拠を弱めるので、Owner に報告します。

### RF-DETR（Nano / Small）— 条件付き

- 配布元（Roboflow）が重みを Apache-2.0 と明示し、model ごとに PML 1.0 との区別まで表に
  している点は、根拠として強いです。精度も高いです。
- ただし論文によれば、事前学習に Objects365 を使っています（Table 6 の注「All models are pretrained with 60 epochs of Objects-365」。Table 11 の caption も、D-FINE の nano を「not pretrained on Objects-365」という理由で比較から外しており、比較対象の RF-DETR が Objects365 で事前学習されていることを前提にしています）。D-FINE の maintainer は、同じ
  系譜の重みを「commercially cleared ではない」と判断しています。配布元の Apache-2.0 表明が
  Objects365 の「academic purpose only」を上書きできるかは、この調査では判断できません。
- 実行面でも、package は既定で `repo.roboflow.com` から download して MD5 だけで照合し、
  PyTorch 系の依存が大きいです。採用するなら、export 済み ONNX をリポジトリ外で
  SHA-256 固定する形に限るべきです。

### 除外した候補の理由（まとめ）

- **コードが GPL / AGPL**：Ultralytics、YOLOv6/v7/v9/v10、MMYOLO。ポリシーで既定ブロックです。
  Ultralytics の Enterprise License は有償の個別契約で、Apache-2.0 で配る ServerSentinel の
  利用者全員には及ばないため、この project には合いません。
- **重みのライセンスが不明**：YOLOX、DEIM、RTMDet、PP-YOLOE、NanoDet、EfficientDet、
  MediaPipe、Open Model Zoo。
- **配布元が許諾を保証しない**：torchvision（docs が利用者の責任と明記）。
- **Objects365 系譜**：D-FINE obj365/obj2coco、RT-DETR の O365 版、PP-YOLOE+（RF-DETR は上記のとおり条件付き）。

## 提案（Owner 判断の前の推奨。判断の結果は冒頭の「Owner 判断（2026-10-22）」）

1. **D-FINE-N と D-FINE-S の COCO-only checkpoint を「評価専用」で追加すること**を提案します。
   YOLOX と同じ扱いにします：重みはリポジトリ外、digest 固定、CI での download なし、
   deployment schema では拒否。
2. **RT-DETRv2-S は比較基準として残します。** adapter の変更は不要です。
3. Main host で測定し、D-FINE が RT-DETRv2-S 以上の人物検出（下記）と CPU 予算内の latency を
   示した場合に、本番採用を別 PR で Owner に提案します。その時点で、weights の
   provenance 文書、`model_code` の記録、運用者が artifact を置く手順を用意します。
4. RF-DETR は Owner が Objects365 系譜を受け入れる場合だけ、評価候補に加えます。
5. YOLOX は upstream の回答がない限り、評価専用のまま採用しません。

このあとの実装（adapter、export 手順書、benchmark）は別 PR で行います。この PR は文書だけです。

## Main host で測る必要があること

repository / CI には、実在の人物の映像や公開の人物 dataset を入れません。実画角の映像は
Owner の同意のもとで Main host のローカルだけで使い、結果の数値だけを記録します。

1. **CPU latency と cadence**：`app.detection.foundation.person_benchmark` で 1〜4 source、
   intra-op thread 1 / 4 の p50 / p95 / max、replay の drop と health。
   既存の RT-DETRv2 / YOLOX と同じ条件で比べます。
2. **ONNX graph の確認**：標準 domain だけか、external data がないか、ORT 1.28 CPU で
   全 node が CPU kernel を持つか。PyTorch 出力と ONNX 出力の差（generated frame と
   ローカル映像）。
3. **人物の検出性能（ローカル映像）**：実際のカメラ画角で、人がいる frame の検出率、
   人がいない frame の誤検出（モニター画面、ポスター、反射）、部分的な遮蔽。
   person クラスの AP は upstream が公表していないので、ここで初めて分かります。
4. **低照度の挙動**：照度を下げたとき、(a) #22 の品質ゲートが `unknown` に切り替わる前に
   score が下がり始めるか、(b) ゲートを通る明るさで見逃しが増えないか。見逃しが増える
   範囲があれば、その範囲は品質ゲートで `unknown` にする必要があります。
   どの場合も detector の失敗を `absent` にしないことを確認します。
5. **資源**：worker の rlimit（memory）、model load 時間、watchdog の timeout 内に収まるか。
6. （評価専用）GPU：`onnxruntime-gpu` の scratch 環境で、2026-09-30 の測定と同じ方法。

## Owner への質問

Q1〜Q4 は 2026-10-22 に判断済みです（冒頭の節）。Q5・Q6 は未決です。記録のため、質問は元の文のまま残します。

1. **重みのライセンスの基準**：本番採用には「配布元（原著者・公式組織）の明示」を必須に
   しますか。それとも、RT-DETRv2 のような Hugging Face 変換者の metadata でも十分としますか。
   前者なら、現在の RT-DETRv2 の扱いも見直しが必要です。
2. **学習データの残余リスク**：COCO の画像（Flickr の条件）と、backbone の ImageNet 系事前学習
   （non-commercial research の条件）は、どの候補でも解消されません。これを受け入れて進めますか。
   （RT-DETRv2 は、この残余リスクを明示的に検討した記録がないまま deployment schema に入っています。）
3. **Objects365 系譜**：「academic purpose only」の Objects365 を事前学習に使った重みは、
   配布元が Apache-2.0 と書いていても除外しますか（RF-DETR が該当します）。
4. **D-FINE の評価開始**：D-FINE-N / S の COCO-only checkpoint を評価専用で追加してよいですか。
   artifact の取り方は (a) 元の `.pth` から自前 export、(b) HF の safetensors から自前 export、
   のどちらにしますか（推奨は (a)。maintainer の表明が対象とする file そのものだからです。
   ただし pickle を読むので隔離環境で `weights_only=True` を使います）。
5. **export 用の環境**：ONNX export のために PyTorch などを、commit しない scratch 環境で
   使ってよいですか（GPU 評価環境と同じ扱い）。
6. **YOLOX**：評価専用の adapter は残しますか。それとも D-FINE の評価後に外しますか。

## 確認できなかったこと

- 各候補の person クラスだけの AP（どの upstream も公表していません）。
- HF の `ustc-community/dfine-*-coco` と元の `dfine_*_coco.pth` が同じ値かどうか。
- D-FINE の ONNX graph が ORT 1.28 CPU で動くかどうか（export していません）。
- HGNetv2 / PResNet backbone の事前学習データの詳しい系譜。
- RF-DETR の DINOv2 backbone の学習データ（LVD-142M。公開されていない web 画像の集合）の系譜と条件。
- RF-DETR の COCO 用 checkpoint の系譜に Objects365 が入るかどうか（論文の Table 6 の注と Table 11 の caption は入ることを示唆しますが、配布された checkpoint についての明示はありません）。
- EfficientDet（google/automl）の重みのライセンス表記（深くは調べていません）。
- YOLOX の model zoo の AP（以前の audit の値を再確認していません）。
- 法的な結論。この文書は upstream の表明と dataset の条件を並べただけです。

この調査では、重み・ソース・dataset を一切 download していません（GitHub API と
Hugging Face API の metadata、README、Issue、論文、dataset の条件ページだけを読みました）。
