# 学校祭ゲストWi-Fi — 0.11.10-rc1

2026年10月30日の修正・試験版です。0.11.9/docs19から、起動を妨げる3件を修正しました。

**ローカル確認用です。本番の通信許可・AP連携は実装していません。** MySQL形式5、31表を使用します。同意・監査・ログ・旧版を自動削除しません。

## 実行ファイル

GitHubの非公開ReleasesからOS別のファイルを取得し、フォルダー全体を展開します。`_internal`を実行ファイルの隣に残してください。Pythonの別途導入は不要です。MySQLサーバーは別途必要です。

- Windows x64：`festival-wifi.exe`
- Linux x86_64：`./festival-wifi`。Ubuntu 24.04 / glibc 2.39で作成。古いglibc・ARM向けではありません。

```text
festival-wifi --version
festival-wifi --self-check
festival-wifi --help
festival-wifi --home <専用のデータ保存先> preflight
festival-wifi --home <専用のデータ保存先> serve
festival-wifi --home <専用のデータ保存先> worker
```

Windowsではコマンド名を`festival-wifi.exe`、Linuxでは`./festival-wifi`に置き換えます。`serve`と`worker`は別のプロセスで実行します。配布フォルダーとデータ保存先を分離してください。

新規導入には空の専用MySQL DB、サービス用の最小権限アカウント、別の保守アカウントが必要です。接続情報やパスワードをコマンド引数に書かず、保護されたJSONファイルを指定します。

```text
festival-wifi --home <新規保存先> init --db-config <runtime.json> --maintenance-db-config <maintenance.json>
festival-wifi --home <保存先> add-admin <利用者名> --role settings
```

`runtime.json`はhost・port・user・password・databaseを持つJSONです。リモートDBでは検証可能な`ssl_ca`も必要です。実際の接続情報は配布物に含めません。権限定義は[server/workflow-privileges.json](server/workflow-privileges.json)です。初期状態は受付停止で、未承認8項目の値を本番用として承認したことにはなりません。

[試験結果](docs/TEST-REPORT.md)・[修正内容](docs/CHANGES.md)・[残る作業](docs/NEXT-STEPS.md)を先に読んでください。server内の旧資料は履歴です。このREADMEと試験結果が今回の状態を示します。OS署名は付けていません。SHA256SUMS.txtで配布内容を照合できます。
