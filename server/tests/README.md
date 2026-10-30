# 試験の入口（0.11.10-rc1）

2026-10-30に試験を再開しました。結果はリポジトリの `docs/TEST-REPORT.md` を参照してください。186件の既存Pythonテストは形式5の保守資格情報を補う専用ハーネスで実行し、169件成功、旧形式向け17件の不適合を記録しました。このフォルダーの全件を無条件に成功扱いにはしていません。

DB不要の確認はサーバーディレクトリで次を実行できます。

```text
python -m unittest discover -s tests -p test_workflow_contract.py -v
node tests/operator_ui.test.cjs
node tests/portal_state.test.cjs
```

response-fixtures.jsonは今回の隔離試験で生成した合成データです。本番データではありません。

MySQL試験には本番と異なるデータディレクトリ・資格情報を必ず使用します。既存mysql_fixtureは `WIFI_TEST_MYSQL_CONFIG` と127.0.0.1:13307、専用データディレクトリを照合します。旧試験の新形式への全面移植は残作業で、現在の形式5初期化には別の保守アカウントも必要です。試験データ/ログの自動削除はありません。
