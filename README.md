# WordPress Plugin Static Analysis Tool

WordPressプラグインのPHPコードから、XSSなどにつながる可能性のあるデータフローを抽出し、ソースレビューの候補を作る研究用静的解析ツールです。

現在の実装は `v1.11_work` にあります。正規表現ベースの検出に、スコープ別の軽量taint追跡、WordPressのentrypoint推定、保存APIの書込み・読出し対応、出力コンテキスト別の優先度付けを組み合わせています。結果は脆弱性の確定判定ではなく、必ず人が関連ソースと到達条件を確認するための候補です。

## 主な機能

- request、shortcode属性、保存済みWordPressデータなどのSource検出
- HTML、属性、URL、JavaScript、terminal outputなどのSink検出
- 同一スコープ、限定的な関数間・ファイル間、WordPress保存APIの軽量taint追跡
- public、authenticated、admin-only、unknownのentrypoint推定
- severity、confidence、flow evidenceを含むCSV、JSON、HTML出力
- プラグイン単位のレビューキュー生成と厳格なreview report検証
- 凍結ベンチマーク用のblind-review、lock、比較ツール
- 固定artifactからのcohort作成、scan manifest作成、Stored XSS handoff生成ツール

## 必要環境

- Python 3.11以降
- 解析対象として利用許可のあるWordPressプラグインのソース

スキャナ本体とテストはPython標準ライブラリだけで動作します。

## 実行方法

解析対象は、1プラグインにつき1ディレクトリとして配置します。

```text
plugins/
├── plugin-a/
│   └── plugin-a.php
└── plugin-b/
    ├── plugin-b.php
    └── includes/
```

PowerShellでは次のように実行できます。

```powershell
cd v1.11_work
$env:WP_PLUGIN_ROOT = "C:\path\to\plugins"
python main.py
```

`WP_PLUGIN_ROOT`を省略した場合は `v1.11_work/plugins` を使います。出力先は既定で `v1.11_work/output` です。別の出力先を使う場合は `WP_SCANNER_OUTPUT_DIR` を設定してください。

生成される主なファイルは次の3つです。

- `findings.csv`
- `findings.json`
- `report.html`

終了コードは、正常に全対象を解析できた場合が`0`、入力ルート不正または対象PHP系ファイルが0件の場合が`1`、ファイル単位の解析失敗がある場合が`2`です。候補が0件でも、対象ファイルを正常に解析できていれば`0`です。部分失敗時も3形式のレポートを残し、`SCAN_ERROR`とコンソールの`ERRORS`件数を確認できます。

CSVは表計算ソフト向けの表示用です。数式として解釈され得る先頭文字や先頭制御文字を持つテキストへapostrophe（`'`）を付けます。数値型は変更しません。原文の引用・機械処理には`findings.json`を使ってください。JSONは原文を保持し、HTMLは表示時にescapeします。[CSV数式解釈の背景（OWASP）](https://community.owasp.org/attacks/CSV_Injection)

## 候補キューとソースレビュー

以下はリポジトリのルートで実行します。`--plugin-root`はスキャン時と同じディレクトリを指定してください。

```powershell
python .agents/skills/review-wp-vulnerability-candidates/scripts/build_review_queue.py --findings v1.11_work/output/findings.json --plugin-root "C:\path\to\plugins" --output v1.11_work/review/queue.jsonl --campaign operational-i53
```

`--findings`はJSON配列と従来のCSVを受け入れます。JSON入力はCSVと同じ選択規則・候補IDを使い、CSV表示用の変更を原文へ持ち込みません。`.php`、`.inc`、`.module`などの対象ソースからfingerprintを作ります。

キュー生成はレビューそのものを実行しません。人またはCodexが、finding、スキャナ規則、プラグインの該当ソースと呼出経路を確認し、schema v2のreview reportを作成します。必要なfieldと合成例は[report validator](.agents/skills/review-wp-vulnerability-candidates/scripts/validate_review_report.py)と[テストのreport例](v1.11_work/tests/test_review_report_validator.py)を参照してください。候補ID、version引用、trace、一次情報などを実際の対象に合わせます。

```powershell
python .agents/skills/review-wp-vulnerability-candidates/scripts/validate_review_report.py --queue v1.11_work/review/queue.jsonl --report v1.11_work/review/example-review.json
python .agents/skills/review-wp-vulnerability-candidates/scripts/record_review.py --queue v1.11_work/review/queue.jsonl --report v1.11_work/review/example-review.json
```

登録時はreportとqueueだけでなく、現在のソースfingerprintも照合します。ソースを編集した場合は再スキャン・キュー再生成・再レビューが必要です。スキャン中やレビュー登録中は対象ソースを変更しないでください。

## テスト

`v1.11_work` から回帰テストを実行します。

```powershell
python -m unittest -v
```

テストにはスキャナ規則、taint追跡、レビューキュー、blind-review契約、cohort作成、handoff生成の検証が含まれます。

## Stored XSS handoff

`v1.11_work/review/scripts/build_xss_v2_handoff.py`は、固定したソース、経路、対照patchなどから引き渡しデータを生成します。v2契約のrole、action identifier、environment role、sink contextに合わない値は生成前に拒否します。このチェックは、受け手のPoCプロジェクトによる正式なschema／semantic validationやruntime検証の代替ではありません。

spec、artifact manifest、完成済みreview、公式ZIP、展開source、patch候補を用意して実行します。合成入力の構造は[handoffテスト](v1.11_work/tests/test_xss_v2_handoff.py)を参照できます。

```powershell
python v1.11_work/review/scripts/build_xss_v2_handoff.py --spec inputs/spec.json --artifact-manifest inputs/manifest.json --review inputs/review.json --artifact-zip inputs/official.zip --source-root inputs/source --patched-root inputs/patched-candidate --patched-output-root outputs/patched --output outputs/handoff.json --patch-output outputs/patch.diff --receipt outputs/receipt.json
```

`--patched-output-root`は存在しないか空のディレクトリが必要です。既存の内容を自動削除・上書きせず拒否し、書込み後のtree hashも検証します。handoff、patch、receiptはpatched treeの外へ別々のパスで保存してください。runtime PoCの実行機能は同梱していません。

## 固定artifactの整合性

`download_and_prepare_legacy_cohort.py`は、要求した版・URLとcacheを照合し、ZIP全ファイルと展開済みソースの一致を確認します。版の不一致や展開先の残存データがある場合は解析対象へ含めません。既存ソースやstagingディレクトリは保全するため、競合時は新しい`--output-dir`を指定してください。不正なslug／version、リンクによる出力先の逸脱も拒否します。

`run_scanner_for_artifact_manifest.py`はmanifestと実ソースのhashをスキャン前後に照合します。不一致の場合は正常な`scan_run.json`を作成しません。sourceや版を変更した場合はartifact manifestも再生成してください。

## ベンチマークの入力

manifestの形式を検証する`v1.11_work/benchmark/legacy_xss_core_v1/manifest.schema.json`を同梱しています。実際のmanifest、プラグインartifact、正解データ、レビュー結果は同梱していないため、利用者が許可された入力を用意してください。

## ディレクトリ構成

- `v1.11_work/main.py`: スキャン実行入口
- `v1.11_work/config.py`: 入出力パスと出力名
- `v1.11_work/rules/`: Source、Sink、Sanitizer、Storage規則
- `v1.11_work/scanner/`: entrypoint推定、taint追跡、scoring、report生成
- `v1.11_work/tests/`: 回帰テスト
- `v1.11_work/review/scripts/`: cohort、dataset、handoff、manifest用ツール
- `v1.11_work/benchmark/legacy_xss_core_v1/scripts/`: blind benchmark用ツール
- `.agents/skills/review-wp-vulnerability-candidates/scripts/`: プラグイン単位レビューキューとreport validator

## 公開物に含めないもの

第三者プラグインのソース、スキャン結果、レビュー結果、ベンチマークartifact、PoC成果物、認証情報はこのリポジトリに含めません。これらは各自の許可されたローカル環境で管理してください。

## 注意事項

- 誤検知と見逃しの両方が発生します。
- severityやscoreは調査順の目安であり、脆弱性の証明ではありません。
- 自分が所有する対象、または明示的に解析を許可された対象だけに使用してください。
- 未確認の脆弱性候補を公開せず、必要に応じて責任ある開示手順に従ってください。
- 本ツールはruntime PoCや第三者サイトへの攻撃を自動実行しません。

## ライセンス

本リポジトリの独自コードと文書は `LICENSE.txt` に記載されたGNU General Public License version 3の条件で公開します。第三者のWordPressプラグインやそのソースには、それぞれの権利者が定める条件が適用されます。
