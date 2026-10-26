# 2026-10-22: 重みのライセンスが明確な人物検出モデルの調査（Issue #20）

- Status: **Accepted（Q1〜Q6、Owner 判断 2026-10-22）**。
  下の「Owner 判断（2026-10-22）」の節を見てください。D-FINE の評価は承認済みですが、本番採用はまだ承認されていません。
  2026-10-26 に、MediaPipe / EfficientDet-Lite（TFLite）の再評価（Issue #327）を追補しました。
  追補の Q7・Q8 は 2026-10-26 に Owner が判断しました（「追補：MediaPipe / EfficientDet-Lite（TFLite）の再評価」の節の「Owner 判断（2026-10-26）」）。
- Date: 2026-10-22（追補 2026-10-26）
- Related: Issue #20、Issue #327、`docs/THIRD_PARTY_POLICY.md`、
  [`2026-09-30-yolox-person-evaluation.md`](2026-09-30-yolox-person-evaluation.md)、
  `server/docs/DETECTOR_MODEL_AUDIT.md`、`server/docs/YOLOX_EVALUATION_AUDIT.md`、
  `server/docs/RTDETR_RUNTIME_AUDIT.md`、`server/docs/DETECTOR_FOUNDATION.md`
- Scope: 文書だけです。この文書は依存、lock、`license/components.json` /
  `license/owner-approvals.json` の記録、コード、重みファイルのどれも追加しません。
  どの重みも採用・同梱・再配布・自動 download を承認しません。

## Owner 判断（2026-10-22）

Owner は 2026-10-22 に、下の「Owner への質問」の Q1〜Q6 について次のとおり判断しました
（Q5・Q6 は同日に PR #319 のコメントで追加）。

- **Q1（重みのライセンスの基準）**：**新しく本番採用する重みには、配布元による明示を必須とします。**
  RT-DETRv2-S は維持します。ただし、根拠が弱いことを既知の弱点として記録します
  （`apache-2.0` は Hugging Face の変換者の metadata で、原著者の表明はなく、upstream の
  [RT-DETR #685](https://github.com/lyuwenyu/RT-DETR/issues/685) は未回答）。
  RT-DETRv2 を置き換えるかどうかは、D-FINE の評価の後に判断します。
- **Q2（学習データの残余リスク）**：COCO の画像（Flickr の条件）と、backbone の ImageNet 系
  事前学習（non-commercial research の条件）の残余リスクを、**研究室内での運用に限り、
  重みを再配布しない範囲で受け入れます**。これは Owner の承認として、この文書に記録します。
- **Q3（Objects365 系譜）**：Objects365 を事前学習に使った重みは、**当面除外します**。
  RF-DETR は候補から外します（D-FINE の maintainer の見解とも整合します）。
- **Q4（D-FINE の評価）**：**D-FINE-N / S の COCO-only checkpoint を、評価専用で追加します。**
  artifact は upstream の元の `dfine_{n,s}_coco.pth`（`Peterande/storage` の release `dfinev1.0`）から作ります。
  `torch.load(..., weights_only=True)` を使い、隔離した環境で ONNX に export します。
  HF の `ustc-community/dfine-{nano,small}-coco` の safetensors は、値が一致するかの照合だけに使います。
- **Q5（export 用の環境）**：commit しない、CPU を制限した container の中で、export のために
  PyTorch を使うことを許可します。PyTorch の version を固定し、`weights_only=True` を明示し、
  使った tool の version と出力した ONNX の SHA-256 を記録します。
- **Q6（YOLOX の評価用 adapter）**：D-FINE の評価が終わるまで残します。

### 実施条件

上の判断を実施するための条件です。Owner が判断した条件（「（Q5 の Owner 条件）」）と、
この PR が加える条件（「（この PR の追加条件）」）を、タグで区別して書きます。
タグのない項目は、この PR の提案です。
Q5 の export については、Owner の条件（version 固定、`weights_only=True` の明示、tool の version と
出力 SHA-256 の記録、commit しない CPU 制限 container）に、この PR が次の条件を加えます：
PyTorch 2.10.0 以上、network なし・memory 制限・non-root の使い捨て container、固定 revision の
code と checkpoint だけを使うこと。

- Q4 の D-FINE の評価は、YOLOX と同じ扱いにします：重みはリポジトリ外、digest 固定、
  CI での download なし、deployment schema では拒否。
- Q1 に関連して、`server/docs/RTDETR_RUNTIME_AUDIT.md` の「Official model」という記述は、
  別の follow-up で訂正します。
- Q2 の承認は、YOLOX と同じく、この decision 文書（と、後に作る D-FINE の評価 audit）に
  記録します。`license/owner-approvals.json` と `license/components.json` には入れません。
  license gate は、`model_weight` の component を、予約ディレクトリに commit された実体と
  SHA-256 で照合し（実体がなければ `missing model artifact`）、存在しない component を指す
  approval を `owner approval references an absent component` で拒否します。重みを
  リポジトリ外に置く限り、gate の inventory には記録できません。重みを本番用に commit する
  ことになった場合にだけ、その PR で `model_weight` の記録と、この文書を参照する approval entry
  を追加します（2026-09-30 の YOLOX の判断と同じ扱い）。
- Q4 の export は、Q5 で許可された環境で行います。また、upstream の
  `tools/deployment/export_onnx.py` をそのまま使ってはいけません。
  [`956d170` の該当行](https://github.com/Peterande/D-FINE/blob/956d1709314c2c6a4df6f34de232054578a7449f/tools/deployment/export_onnx.py#L30)
  は `torch.load(args.resume, map_location="cpu")` で、`weights_only` を指定していません。
  [`requirements.txt`](https://github.com/Peterande/D-FINE/blob/956d1709314c2c6a4df6f34de232054578a7449f/requirements.txt#L1) は
  `torch>=2.0.1` を許しており、PyTorch 2.6 より前の版では `torch.load` の既定は制限のない
  pickle の読み込みです（既定が `weights_only=True` に変わったのは 2.6。PyTorch の release notes に
  基づく記述で、この調査では再確認していません）。そのため、export は次の条件で行います。
  - （Q5 の Owner 条件）`torch.load` に `weights_only=True` を**明示的に**渡します。既定値には頼りません。
  - （この PR の追加条件）そのために、checkpoint は自前の小さな wrapper（または upstream の呼び出しを
    patch したもの）で `torch.load(path, map_location="cpu", weights_only=True)` として読みます。
  - （Q5 の Owner 条件）PyTorch は exact version で固定します。
  - （この PR の追加条件）固定した版で `weights_only=True` が有効なことを、手順書に記録します。
  - （この PR の追加条件）その版は **2.10.0 以上**でなければなりません。PyTorch の security advisory
    [GHSA-63cw-57p8-fm3p](https://github.com/pytorch/pytorch/security/advisories/GHSA-63cw-57p8-fm3p)
    （CVE-2026-24747、2026-01-26 公開、severity high）は、細工した `.pth` を
    `torch.load(..., weights_only=True)` で読むと、`weights_only` の unpickler の検証漏れにより
    memory が壊れ、任意のコード実行に至りうる、としています。影響を受ける版は `<=2.9.1`、
    修正版は `>=2.10.0` です（2026-10-22 に advisory の原文と GitHub Advisory Database の記録を確認）。
    upstream の下限 `torch>=2.0.1` の版はすべて影響を受けます。実装の時点で、選んだ版に
    この advisory 以降の同種の advisory がないことも確認し、版と確認日を手順書に記録します。
  - （この PR の追加条件）それでも `weights_only=True` だけには頼りません（多層防御）。export は、固定 revision の
    checkpoint（size と SHA-256 をローカルで記録したもの）だけを対象に、network なし
    （`--network none`）、CPU と memory を制限した、non-root の使い捨て container の中で行います。
    container の外へ持ち出すのは、出力した ONNX とその SHA-256 だけです。CPU の制限と、container を
    commit しないことは Q5 の Owner 条件です。
  - （Q5 の Owner 条件）使った tool（PyTorch、ONNX、D-FINE の revision など）の version と、
    出力した ONNX の SHA-256 を記録します。
  - `weights_only=True` で読めない checkpoint（独自 class などを含むもの）は、その場で export を中止します。
    `weights_only=False` に戻すことはしません。
  - D-FINE のコードは、下記の固定 revision だけを使います。
- D-FINE の upstream は、この調査で確認した revision
  **`956d1709314c2c6a4df6f34de232054578a7449f`**（master、2026-08-19 の commit。README の Objects365 note を含む）に固定します。
  コードのライセンス（LICENSE）、export script、`requirements.txt` の確認は、この revision に
  対して行いました。別の revision を使うときは、改めて確認します。

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
| **D-FINE（`*_coco` のみ）** | Apache-2.0（[`956d170` の LICENSE](https://github.com/Peterande/D-FINE/blob/956d1709314c2c6a4df6f34de232054578a7449f/LICENSE)） | **Apache-2.0（upstream の maintainer が明示）**。書き込み権限を持ち現在も活動している maintainer の RicePasteM（Zhangchi Hu, USTC。GitHub 上の関係は `COLLABORATOR`。2026-07 に PR #355 を merge し、2026-08-19 に README を更新）が、[Issue #357 のコメント](https://github.com/Peterande/D-FINE/issues/357#issuecomment-5344034723)（2026-08-19）で「COCO-only checkpoints (`*_coco.pth`) are also released by us under Apache-2.0」と明言。ただしこの人は論文の著者でも、重みを upload した人（`Peterande`）でもない。README にあるのは Objects365 系の重みについての否定的な note だけで、COCO-only の重みを Apache-2.0 とする文はない。重みの release を持つ [Peterande/storage](https://github.com/Peterande/storage) は Apache-2.0 の LICENSE を持つが、release 自体には重みのライセンスの記載がない。HF の [ustc-community/dfine-small-coco](https://huggingface.co/ustc-community/dfine-small-coco) の `apache-2.0` は変換者（card では contributed by VladOS95-cyber）が付けた metadata | COCO train2017。backbone は HGNetv2 の ImageNet 系事前学習（`PPHGNetV2_*_stage1.pth`、詳細な系譜は未検証） | **候補（最有力）** |
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
| EfficientDet（google/automl の checkpoint） | Apache-2.0、repository は archived | automl の README が置く checkpoint（`cloud-tpu-checkpoints/efficientdet/coco/*`）には明示を見つけられなかった（深くは未検証）。TensorFlow 組織の Kaggle Models の配布物は別の行（下）で扱う | COCO | 除外（不明・保守終了） |
| **EfficientDet-Lite0 / Lite2（Kaggle Models `tensorflow/efficientdet` の TFLite 配布物）**（2026-10-26 追補） | 実装は google/automl（Apache-2.0、archived） | **Apache 2.0（配布元の公式組織の metadata）**。publisher `TensorFlow` の各 TFLite variation（`lite0-detection-default` / `lite0-detection-metadata` / `lite0-int8` / `lite2-detection-default` / `lite2-detection-metadata`）の `licenseName` が `Apache 2.0`。文章による表明ではなく、配布 page の license 欄。詳細は追補の節 | COCO 2017。backbone は EfficientNet-Lite（ImageNet 系事前学習と推定、未検証）。Objects365 の記載なし | **候補として記録するだけ（Q8（2026-10-26）により Q1〜Q3 を満たす。評価に進む時点で license を再確認）。D-FINE の評価が終わるまで評価しない**（Q7（2026-10-26）） |
| MediaPipe Object Detector の配布物（`storage.googleapis.com/mediapipe-models/object_detector/*`：EfficientDet-Lite0/2、SSD MobileNetV2） | Apache-2.0（google-ai-edge/mediapipe） | **不明（2026-10-26 に再確認）**。[解説ページ](https://developers.google.com/edge/mediapipe/solutions/vision/object_detector)に model のライセンスの記載なし（ページ本文は CC BY 4.0、code sample は Apache 2.0）。model card なし。GCS object の metadata にも記載なし。Kaggle の TFLite 配布物とは file size が違い、同じ file ではない | COCO（解説ページ：「The model was trained with the COCO dataset」） | 除外（不明。Kaggle の license は別 file には及ばない） |
| OpenVINO Open Model Zoo `person-detection-0202` など | Apache-2.0（repository は「maintenance mode」） | [model README](https://github.com/openvinotoolkit/open_model_zoo/blob/master/models/intel/person-detection-0202/README.md) に重みのライセンスの記載なし。学習データの記載なし | 不明（AP 0.322 は Intel 内部 test set） | 除外（不明、OpenVINO IR で新しい runtime が必要） |

DETR（`facebook/detr-resnet-50`、HF card `apache-2.0`）も重みの metadata は明示されていますが、
real-time 用ではなく CPU の負荷が大きいため、比較から外しました（性能は未検証）。

### 表 2：精度・大きさ・実行環境（upstream の公表値、測定していません）

| 候補 | COCO AP<sup>val</sup> | Params | 入力 | ONNX / 既存 runtime との適合 | 保守 |
| --- | ---: | ---: | --- | --- | --- |
| D-FINE-N（`dfine_n_coco`） | 42.8 | 4M | 640 | upstream に [`tools/deployment/export_onnx.py`](https://github.com/Peterande/D-FINE/blob/956d1709314c2c6a4df6f34de232054578a7449f/tools/deployment/export_onnx.py)（revision `956d170`。opset 16。checkpoint の読み込みに `weights_only` を指定していない。出力は `labels/boxes/scores` で後処理込み）。HF 変換版は RT-DETRv2 と同じ `RTDetrImageProcessor` 設定（640×640 直接 resize、/255、normalize なし、300 query、class 0 = person）。**ライセンス metadata のある ONNX は配布されていない**（`onnx-community/dfine_*_coco-ONNX` は license 欄が空）ので、自前で export が必要 | 最終 push 2026-10-05 |
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
- （2026-10-26 追補）上の「D-FINE だけ」は、2026-10-22 に調べた範囲での記述です。EfficientDet-Lite の
  Kaggle の TFLite 配布物は、公式組織（`TensorFlow`）が配布 page の license 欄で Apache 2.0 としています
  （文章による表明ではなく、判定の基準の 2 にあたる license metadata です）。Owner は 2026-10-26 の Q8 で、
  これを Q1 の「配布元の明示」とみなすと判断しました（評価に進む時点で license を再確認することが条件）。
  ただし精度が大きく低く、TFLite 形式で、Q7 により D-FINE の評価が終わるまで評価しません
  （下の「追補：MediaPipe / EfficientDet-Lite（TFLite）の再評価」）。
- 前処理と出力の形が RT-DETRv2 と同じ系統なので、既存の `RtDetrPersonDetector` と同じ形の
  adapter で扱えます（focal-loss の sigmoid score、class 0 = person、640×640 RGB、
  品質ゲート後だけ評価、異常時は `unknown`）。
- 残る課題：
  - **ONNX は自前で作る必要があります。** 方法は 2 つあります。
    (a) 元の `dfine_{n,s}_coco.pth` を、固定 revision の D-FINE のコードで export する。
    GitHub release は `digest: null` で checksum を配っていないので、size と SHA-256 は
    download 後にローカルで計算するしかありません。upstream の `export_onnx.py` は
    `torch.load` に `weights_only` を指定していないので、そのまま使わず、`weights_only=True` を
    明示する自前の wrapper（または patch）で、隔離した scratch 環境で行います
    （上の「実施条件」を参照）。
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
- **重みのライセンスが不明**：YOLOX、DEIM、RTMDet、PP-YOLOE、NanoDet、EfficientDet（automl の checkpoint）、
  MediaPipe の配布物、Open Model Zoo。EfficientDet-Lite の Kaggle 配布物は、公式組織の license 欄に Apache 2.0 があり、Q8（2026-10-26）により配布元の明示とみなすため、ここには入れません（評価に進む時点で license を再確認します）。
- **配布元が許諾を保証しない**：torchvision（docs が利用者の責任と明記）。
- **Objects365 系譜**：D-FINE obj365/obj2coco、RT-DETR の O365 版、PP-YOLOE+、RF-DETR（RF-DETR も Q3 により除外）。

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

Q1〜Q6 は 2026-10-22 に判断済みです（冒頭の節）。記録のため、質問は元の文のまま残します。

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

## 追補：MediaPipe / EfficientDet-Lite（TFLite）の再評価（2026-10-26、Issue #327）

PR #319 の Codex P2 は、次の点を指摘しました。この文書は MediaPipe を「解説ページに license がない」という理由だけで外しました。しかし、同じ系統の
TensorFlow EfficientDet-Lite2 の TFLite 配布物は、配布ページで Apache 2.0 とされています。この指摘を受けて、
配布物ごとに一次情報を確かめ直しました。確認日はすべて **2026-10-26** です。
重み・graph・dataset は一切 download していません。精度・速度は配布元の公表値で、**測定していません**。

### 確かめた配布物とライセンス表記

**(1) Kaggle Models `tensorflow/efficientdet`（TF Hub から移行した公式の配布物）**

- 配布 page：[kaggle.com/models/tensorflow/efficientdet](https://www.kaggle.com/models/tensorflow/efficientdet)
  （Codex が示した [`tfLite/lite2-detection-metadata/1`](https://www.kaggle.com/models/tensorflow/efficientdet/tfLite/lite2-detection-metadata/1) を含む）。
  page は script で描画されます。そこで、同じ内容を返す Kaggle の public API の JSON を読みました。
  [`/api/v1/models/tensorflow/efficientdet/get`](https://www.kaggle.com/api/v1/models/tensorflow/efficientdet/get) と、
  variation ごとの `/api/v1/models/tensorflow/efficientdet/tfLite/<variation>/get` です。
- model の `author` は `TensorFlow`（Google の公式組織）です。`provenanceSources` は
  [`tensorflow/tfhub.dev` の `assets/docs/tensorflow`](https://github.com/tensorflow/tfhub.dev/tree/master/assets/docs/tensorflow) です。
  tfhub.dev の README には「TensorFlow Hub has moved to Kaggle Models」「Starting November 15th 2023, links to tfhub.dev
  redirect to their counterparts on Kaggle Models」と書かれています（tfhub.dev の repository は archived です。
  確認した commit は `81fdea8ffa53b5acbd66a012d17fb8f9602c714b` です）。
- TFLite の variation と、API が返した値を次の表に示します。`licenseName` はどれも **`Apache 2.0`** です。

  | variation（version 1） | 入力 | `totalUncompressedBytes` | 公表 mAP（COCO 2017 val） | `licenseName` |
  | --- | --- | ---: | --- | --- |
  | `lite0-detection-default`（説明：「Same TFLite model as tensorflow/efficientdet/lite0/int8/1」） | 320×320 uint8 | 4,561,184 | 25.69% | Apache 2.0 |
  | `lite0-detection-metadata`（TFLite metadata と label file を含む） | 320×320 | 4,563,519 | 25.69% | Apache 2.0 |
  | `lite0-int8` | 320×320 | 4,561,184 | 25.69% | Apache 2.0 |
  | `lite2-detection-default` | 448×448 | 7,555,552 | 33.97% | Apache 2.0 |
  | `lite2-detection-metadata` | 448×448 | 7,557,887 | 33.97% | Apache 2.0 |

  出力は `detection_boxes` / `detection_classes` / `detection_scores` / `num_detections` で、最大 25 件です。
  TFLite の graph の中に後処理（NMS）が含まれています。公表 latency は Pixel 4 の値で、Main host の値ではありません。
  親の TF2 SavedModel 版（`lite0-detection` / `lite2-detection`）の説明は「trained on COCO 2017 dataset」です。
  tfhub.dev の元の文書（[`efficientdet/lite0/detection/1.md`](https://github.com/tensorflow/tfhub.dev/blob/81fdea8ffa53b5acbd66a012d17fb8f9602c714b/assets/docs/tensorflow/models/efficientdet/lite0/detection/1.md)）は
  `dataset: coco-2017` で、実装は [google/automl の EfficientDet](https://github.com/google/automl/tree/master/efficientdet)
  とされています。
- 根拠の強さ：上の「判定の基準」の 2（配布する場所にある、明示的な license metadata）にあたります。
  ただし、metadata を付けたのは変換者ではなく、**配布元の公式組織そのもの**です。
  RT-DETRv2 の HF metadata（変換者が付けたもの）より強く、文章による表明（基準の 1）よりは弱い、という位置です。
  tfhub.dev の元の文書には license の tag がありません（tfhub.dev の `tags/license.yaml` には `apache-2.0` などの値が
  定義されていますが、この文書はそれを使っていません）。Apache 2.0 という表記は、Kaggle の配布 page の license 欄で
  だけ確認できます。
- `licenseName` の値の出どころは未確認です。API では、model 自体の `licenseName` は `null` です。一方で、
  全 33 instance（TF2 SavedModel の d0〜d7、feature-vector、すべての TFLite を含む）が一律に `Apache 2.0` です。
  元の tfhub.dev の文書には license の tag がありません。そのため、この値は model ごとに付けたものではなく、
  TF Hub から Kaggle への移行の時にまとめて設定された可能性があります（未確認）。
  なお、archived の [`terms_archive/TERMS.md`](https://github.com/tensorflow/tfhub.dev/blob/81fdea8ffa53b5acbd66a012d17fb8f9602c714b/terms_archive/TERMS.md)
  には、明示のない公開 content について、他の利用者に MIT の許諾を与える条項があります。ただし、これは利用者が
  投稿した content の条項で、Google 自身の content に当てはまるかは不明です。どちらも Q8 の判断材料として示しました。この経緯の未確認は、Q8 の条件（評価に進む時点での再確認）で扱います。
- `*-metadata` variation に埋め込まれた TFLite metadata に `license` 欄があるかどうかは、file を download していないため未確認です。

**(2) MediaPipe Object Detector の配布物（`storage.googleapis.com/mediapipe-models`）**

- [解説ページ](https://developers.google.com/edge/mediapipe/solutions/vision/object_detector)（「Last updated 2026-10-01 UTC」）の
  Models 節には、次の download link があります。EfficientDet-Lite0（int8 / float16 / float32、320×320）、
  EfficientDet-Lite2（int8 / float16 / float32、448×448）、SSDMobileNet-V2（int8 / float32、256×256）です。
  学習データは「The model was trained with the COCO dataset」と書かれています。
  **model のライセンスの記載はありません。** footer は
  「Except as otherwise noted, the content of this page is licensed under the Creative Commons Attribution 4.0 License」と
  「code samples are licensed under the Apache 2.0 License」です。これは page の本文と code sample の条件です。
  なお、page の EfficientDet-Lite0 float32 と SSDMobileNet-V2 int8 の link は、`float16` の path を指しています。
  page 自体に不整合があります（SSDMobileNet-V2 の `int8/latest/ssd_mobilenet_v2.tflite` は HEAD で 404 でした）。
- model card：MediaPipe の object detector（Tasks 版）の model card は見つかりませんでした。
  [google-ai-edge/mediapipe の `docs/solutions/models.md`](https://github.com/google-ai-edge/mediapipe/blob/bfafeaed685be63fbf7ace1c3fbc4bfcbbc30128/docs/solutions/models.md)
  の legacy の Object Detection 節には、model card の link がありません。その節が link する
  `mediapipe-assets/object_detection_saved_model/README.md` は `NoSuchKey` でした。
  repository の test data の [`efficientdet_lite0_v1.json`](https://github.com/google-ai-edge/mediapipe/blob/bfafeaed685be63fbf7ace1c3fbc4bfcbbc30128/mediapipe/tasks/testdata/metadata/efficientdet_lite0_v1.json)
  （metadata writer の期待値）にも、`license` 欄はありません。ただし、これは test data で、配布物そのものの metadata ではありません。
- GCS の object metadata（HEAD と JSON API で取得）：license に関する field はありません。値は次のとおりです。

  | object | size（bytes） | `md5`（GCS） | 作成日 |
  | --- | ---: | --- | --- |
  | `object_detector/efficientdet_lite0/int8/latest/efficientdet_lite0.tflite` | 4,602,795 | `zr9kr2w15avXNElGhQZIQg==` | 2023-04-27 |
  | `object_detector/efficientdet_lite0/float32/latest/efficientdet_lite0.tflite` | 13,836,895 | `ymabHfDr6add3N5X/geg0A==` | 2023-04-27 |
  | `object_detector/efficientdet_lite2/int8/latest/efficientdet_lite2.tflite` | 7,515,971 | `uQw0TrvGfuxOCI6jypzUvw==` | 2023-04-27 |

- **MediaPipe の file は、Kaggle の file と同じではありません**（Lite0 int8 は 4,602,795 bytes と 4,561,184 bytes、
  Lite2 int8 は 7,515,971 bytes と 7,555,552 bytes）。MediaPipe 用の metadata を足した同じ重みである可能性はありますが、
  未検証です。したがって、Kaggle の `Apache 2.0` を、MediaPipe の file にそのまま当てはめることはできません。
- 第三者の package（pub.dev の Flutter wrapper など）が「Apache 2.0」と書いている例はあります。
  しかし、配布元の表明ではないので、根拠にはしません。

### 学習データ（COCO）と repository の方針

- どちらの配布物も、COCO 2017 で学習したと書かれています。COCO の annotation は CC BY 4.0、画像は Flickr の
  条件です（上の「判定の基準」）。backbone の EfficientNet-Lite は ImageNet 系の事前学習と推定しますが、
  Lite の配布物の説明には書かれていません（未検証）。
- repository の方針では、この残余リスクは **Q2（2026-10-22）**で受け入れ済みです。条件は「研究室内での運用に限り、
  重みを再配布しない範囲で」です。EfficientDet-Lite でも条件は同じです。repository / CI に重みを入れず、運用者が
  リポジトリ外に digest 固定で置く形に限ります。
- Objects365 の使用は、Kaggle、tfhub.dev の元の文書、automl の README のどこにも書かれていません。
  automl の Lite の checkpoint は、`cloud-tpu-checkpoints/efficientdet/coco/` に置かれています
  （[README](https://github.com/google/automl/blob/6a54c8741e7c3265d4547c4f35f47a0391122dc5/efficientdet/README.md)）。

### 精度（person class）

- person class だけの AP は、Kaggle、tfhub.dev、automl、MediaPipe のどれも公表していません。
- 全クラスの COCO val mAP は、Kaggle の TFLite 版で Lite0 が 25.69%、Lite2 が 33.97% です。automl の README の表では、
  Lite0 が 26.41（int8 は 26.10）、Lite2 が 35.06（int8 は 34.69）です。
- これは、D-FINE-N（42.8）、D-FINE-S（48.5）、RT-DETRv2-S（48.1）より、全クラスで約 9〜23 point 低い値です。
  品質ゲートを通った frame での人物の見逃し（false negative）は、`unknown` に変えられない失敗です。
  そのため、この差は小さくありません。

### runtime の適合

- 既存の inference worker（`app.detection.foundation`）は、`onnxruntime==1.28.0` の CPU だけを使います
  （`server/requirements-detector.lock`、`CPUExecutionProvider`、fallback なし）。TFLite は読めません。
- 選択肢は 2 つです。どちらも、この追補では実施しません。
  1. **TFLite のまま使う**：LiteRT（`ai-edge-litert`）、`tflite-runtime`、MediaPipe Tasks などの、新しい runtime の
     依存が要ります。依存のレビュー（license、transitive、wheel、network の挙動）と、Owner の判断が必要です。
     これらの package の license は、この追補ではレビューしていません。
  2. **ONNX に変換する**：[onnx/tensorflow-onnx（tf2onnx）](https://github.com/onnx/tensorflow-onnx)（Apache-2.0。
     最新 release は `v1.17.0`、確認した commit は `f77f5acf9be6066ea3345887119204453d1da32e`）は、TFLite の入力に対応しています。
     graph に含まれる後処理の custom op は、
     [`tfl_postprocess.py`](https://github.com/onnx/tensorflow-onnx/blob/f77f5acf9be6066ea3345887119204453d1da32e/tf2onnx/tflite_handlers/tfl_postprocess.py)
     が変換します（`TFL_TFLite_Detection_PostProcess` → ONNX の `NonMaxSuppression` など）。変換には TensorFlow などが
     要ります。そのため、D-FINE の export（Q5）と同じく、commit しない、CPU を制限した、network なしの使い捨て container で
     行う必要があります。TensorFlow を export 環境で使うことは、Q5（PyTorch）の許可の範囲外です。
     int8 版の変換は量子化 op の変換になるので、float32 / float16 の file を変換元にする方が単純と見込みます（未検証）。
- ONNX 変換のライセンス上の扱い：変換した ONNX は、Apache 2.0 の artifact の派生物になると考えます。Apache-2.0 の
  条件（license の写しを添えること、変更した旨を表示すること、NOTICE がある場合はそれを残すこと）を守れば、
  変換と研究室内での利用は許されると読めます。**法的な結論ではありません。** 変換した ONNX を repository や
  release に入れる場合は、別の PR で `model_weight` の記録を加えます（上の「実施条件」と同じ扱い）。
- graph の形：入力は uint8 の画像（320 / 448）で、出力は後処理済みの最大 25 件です。既存の `RtDetrPersonDetector`
  とは前処理と出力の形が違うので、別の adapter が要ります。label file の何番が person かは、artifact の label file で
  確認する必要があります（未確認）。品質ゲートの後だけ評価し、異常時は `unknown` にする、という条件は変わりません。

### Q1〜Q3 に照らした判定

| 配布物 | Q1（配布元の明示） | Q2（COCO / ImageNet の残余リスク） | Q3（Objects365 の除外） | 表への追加 |
| --- | --- | --- | --- | --- |
| EfficientDet-Lite0 / Lite2（Kaggle `tensorflow/efficientdet` の TFLite variation） | **満たす（Q8、Owner 判断 2026-10-26）**：公式組織の `TensorFlow` が、配布 page の license 欄で `Apache 2.0` としている。文章ではなく license 欄（metadata）で、値の設定の経緯は未確認。Owner は、これを配布元の明示とみなすと判断した。ただし、評価に進む時点で license を再確認する | Q2 の範囲内（研究室内、再配布なし） | 該当なし（Objects365 の記載なし） | **追加**（候補として記録するだけ。Q7 により D-FINE の評価が終わるまで評価しない） |
| MediaPipe Object Detector の配布物（GCS の `mediapipe-models`） | **満たさない**：page、model card、GCS の metadata のどこにも、重みの license がない。Kaggle の file とは別の file | — | 該当なし | 除外のまま（理由を「不明、別の file」と明記） |
| MediaPipe の SSDMobileNet-V2 | 満たさない（同上）。Kaggle の `tensorflow/ssd-mobilenet-v2` は TF2 / TF.js 版だけで、TFLite の variation はない | — | — | 除外のまま |

まとめると、Codex の指摘のとおり、EfficientDet-Lite の公式の TFLite 配布物には、配布元の license 欄があります。Q8（2026-10-26）により、license の上では候補です。
一方で、MediaPipe の配布物そのものは、license が不明なままです。license とは別に、EfficientDet-Lite をすぐ評価に進めない理由が
次の 2 点です（Q7 の判断の背景）。

1. **精度**：全クラスの mAP が、評価中の D-FINE-N/S と、比較基準の RT-DETRv2-S より大きく低い。
2. **runtime**：TFLite は既存の ORT CPU worker で読めない。新しい runtime の依存か、TensorFlow を使う変換環境が必要。

### Owner 判断（2026-10-26）

Owner は 2026-10-26 に、下の追補の質問 Q7・Q8 について次のとおり判断しました。

- **Q7（EfficientDet-Lite の扱い）**：**(a)**。EfficientDet-Lite0 / Lite2（Kaggle の TFLite 配布物）は、表に候補として
  記録するだけにします。D-FINE の評価が終わるまで評価しません。TFLite の runtime 依存（LiteRT など）も、TensorFlow を
  使う変換環境も、承認していません。評価に進めるかは、D-FINE の評価の後に改めて判断します。
- **Q8（Q1 の「配布元の明示」の範囲）**：**はい**。公式組織が配布 page の license 欄に記載した license を、Q1 の
  「配布元の明示」とみなします。**条件：評価に進む時点で、license を再確認します。** 再確認では、少なくとも次を行い、
  確認日とともに記録します。
  - 対象の variation の `licenseName` が、引き続き公式組織の配布 page で `Apache 2.0` であること。
  - 評価に使う file の配布元・version・digest を固定し、それが license を確認した配布物そのものであること
    （MediaPipe の GCS の file など、別の file には当てはめない）。
  - 値の設定の経緯（上の「確かめた配布物とライセンス表記」の未確認事項）について、新しい情報があれば反映すること。

### 追補の Owner への質問（2026-10-26 に判断済み）

判断は上の「Owner 判断（2026-10-26）」です。記録のため、質問は元の文のまま残します。


7. **EfficientDet-Lite の扱い**：EfficientDet-Lite0 / Lite2（Kaggle の TFLite 配布物）を、次のどちらにしますか。
   (a) 表に候補として記録するだけにして、D-FINE の評価が終わるまで評価しない（推奨）。
   (b) D-FINE と並べて、評価専用で追加する。
   (b) の場合は、さらに次のどちらかを判断してください。TFLite の runtime 依存（LiteRT など）を評価用に入れるか、
   tf2onnx で ONNX に変換するために、TensorFlow を commit しない使い捨て container で使うことを許可するか（Q5 と同じ条件で）です。
8. **Q1 の「配布元の明示」の範囲**：公式組織が配布 page の license 欄（metadata）で示した license を、文章による
   表明と同じく、Q1 を満たすものとして扱いますか。判断材料：根拠は判定の基準の 2（配布場所の license metadata）に
   あたり、文章による表明（基準の 1）ではありません。metadata を付けたのは変換者ではなく公式組織です。ただし、
   値は全 instance で一律で、設定の経緯は未確認です（上の「確かめた配布物とライセンス表記」）。
   この追補は、EfficientDet-Lite を条件付きの候補として記録しただけです。認めない場合は「不明」として除外します。

この追補は、どの重みの評価・採用・同梱・自動 download も承認しません。`license/components.json` と
`license/owner-approvals.json` も変更しません。重みを repository に commit しない限り、license gate の inventory には
記録できないためです（上の「実施条件」と同じ扱い）。

## 確認できなかったこと

- 各候補の person クラスだけの AP（どの upstream も公表していません）。
- HF の `ustc-community/dfine-*-coco` と元の `dfine_*_coco.pth` が同じ値かどうか。
- D-FINE の ONNX graph が ORT 1.28 CPU で動くかどうか（export していません）。
- HGNetv2 / PResNet backbone の事前学習データの詳しい系譜。
- RF-DETR の DINOv2 backbone の学習データ（LVD-142M。公開されていない web 画像の集合）の系譜と条件。
- RF-DETR の COCO 用 checkpoint の系譜に Objects365 が入るかどうか（論文の Table 6 の注と Table 11 の caption は入ることを示唆しますが、配布された checkpoint についての明示はありません）。
- EfficientDet（google/automl）の checkpoint の重みのライセンス表記（深くは調べていません）。
- MediaPipe の TFLite 配布物と Kaggle の TFLite 配布物の重みが同じかどうか（file size は違います。
  確かめるには両方を download して tensor を比べる必要があり、この調査ではしていません）。
- Kaggle の `*-metadata` variation に埋め込まれた TFLite metadata の `license` 欄の内容（file を download していません）。
- EfficientDet-Lite の TFLite graph を tf2onnx で ONNX に変換できるか、ORT 1.28 CPU で全 node が動くか、
  変換前後の出力が一致するか（変換していません）。
- EfficientDet-Lite の backbone（EfficientNet-Lite）の事前学習データの系譜。
- Kaggle の `licenseName`（`Apache 2.0`）が、いつ、誰によって、どの根拠で設定されたか（Q8 の条件により、評価に進む時点で再確認します）。
- YOLOX の model zoo の AP（以前の audit の値を再確認していません）。
- 法的な結論。この文書は upstream の表明と dataset の条件を並べただけです。

この調査では、重み・ソース・dataset を一切 download していません（GitHub API と
Hugging Face API の metadata、README、Issue、論文、dataset の条件ページだけを読みました）。
2026-10-26 の追補でも同じです（Kaggle の public API の JSON、GCS の object metadata（HEAD と JSON API）、
GitHub API、解説ページだけを読みました）。
