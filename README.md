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

## テスト

`v1.11_work` から回帰テストを実行します。

```powershell
python -m unittest -v
```

テストにはスキャナ規則、taint追跡、レビューキュー、blind-review契約、cohort作成、handoff生成の検証が含まれます。

## Stored XSS handoff

`v1.11_work/review/scripts/build_xss_v2_handoff.py`は、固定したソース、経路、対照patchなどから引き渡しデータを生成します。v2契約のrole、action identifier、environment role、sink contextに合わない値は生成前に拒否します。このチェックは、受け手のPoCプロジェクトによる正式なschema／semantic validationやruntime検証の代替ではありません。

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
