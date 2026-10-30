# 学校祭Wi-Fi MySQL版 ローカルサーバー

リリース0.10.0 / 2026-10-20 / DB形式4 / MySQL専用

同意保存、管理者認証と4役割、監視通知、暗号化バックアップと復元をMySQL用に実装しています。SQLite版の保存処理は使用しません。AP/RADIUSは未接続、本番受付は無効です。Webサーバーは同じPCの127.0.0.1だけで動作します。

**利用者の指示により、ログ・同意記録・監査・通知・バックアップの自動削除を停止しています。** 保存期限は対象件数の確認だけを行い、期限超過でも削除しません。試験用データと試験ログも残します。automatic_deletion_enabled=trueでは起動を拒否します。ログアウト・権限変更時は監査記録を残してログイン状態を失効させます。

## 実装内容

| 項目 | 内容 |
|---|---|
| 同意保存 | 規約版・ハッシュ・言語・同意日時・接続参照IDをMySQLへ保存。同意と許可待ち・操作記録をInnoDBで一括保存 |
| 認証・権限 | scrypt、30分の管理者セッション、Origin/CSRF確認、試行制限、閲覧・運用・記録・設定の4役割 |
| 記録の保持 | ログ等を削除しない。期限を過ぎた記録の件数を確認。CSV出力は監査記録を残す |
| バックアップ | InnoDBの一貫した読み取りから論理スナップショットを作りFernetで暗号化。復元は別の空DBだけ |
| 通知 | AP未接続、未完了操作、容量不足、バックアップ失敗・遅延、保存設定未定、自動削除停止、worker停止 |

来場者画面は日本語・英語、管理画面は日本語です。仮の利用条件を同梱しています。実際のWi-Fi接続人数や回線負荷は取得していません。

## 必要な環境

- Python 3.12、MySQL 8.0.16以降または8.4。実際の検証環境はMySQL Community Server 8.0.46でした。
- 本サービス専用の**空のデータベース**とMySQL利用者。既存DBや共有の学校データへ初期化しないでください。
- MySQL管理者がDBとアカウントを用意します。接続情報はCLIで対話入力し、パスワードを引数・ログ・ZIPへ入れません。
- 初期化時は専用DBに対するCREATE/ALTER/REFERENCES/TRIGGERとSELECT/INSERT/UPDATE/DELETEが必要です。初期化後はSELECT/INSERT/UPDATE/DELETEへ絞ってください。アプリの通常起動にDDL権限やMySQL rootは不要です。
- 遠隔MySQLは信頼するCAファイルを指定し、証明書とホスト名を検証します。ローカルMySQL接続はTLSを利用しますが、CA・ホスト名の検証を必須にするのは遠隔接続です。

## Windowsでの導入

ZIPを展開したフォルダーでPowerShellを開きます。パスは例です。データ保存先・接続情報の保存先は存在しない新しいフォルダーを使います。

```powershell
python .\verify_package.py
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check

# 接続情報を対話入力。専用の空DBが先に必要です
.\.venv\Scripts\python.exe .\manage.py --home 'C:\FestivalWiFi\mysql-connection' configure-mysql

# 標準初期化：受付停止、正式期間未設定、本番無効、自動削除停止
.\.venv\Scripts\python.exe .\manage.py --home 'C:\FestivalWiFi\local-data' init --db-config 'C:\FestivalWiFi\mysql-connection\mysql.json'

# 管理者パスワードを対話入力（14文字以上）。初期パスワードはありません
.\.venv\Scripts\python.exe .\manage.py --home 'C:\FestivalWiFi\local-data' add-admin owner --role settings

# 端末1
.\start.ps1 -DataDirectory 'C:\FestivalWiFi\local-data' -Mode serve
# 端末2
.\start.ps1 -DataDirectory 'C:\FestivalWiFi\local-data' -Mode worker
```

管理画面は http://127.0.0.1:8890/admin です。停止は各端末でCtrl+Cです。同じOS利用者・同じデータ保存先でサーバーとworkerを起動します。MySQLサービス自体は管理者の既存運用に従います。Webサーバーの停止で既存MySQLサービスを停止しません。

install.ps1を使う場合は、MySqlConfigへ準備済み接続ファイルを指定します。

```powershell
.\install.ps1 -DataDirectory 'C:\FestivalWiFi\local-data' -MySqlConfig 'C:\FestivalWiFi\mysql-connection\mysql.json'
```

データフォルダーにはmysql.json、config.json、session.key、backup.keyを保存します。Windowsでは作成時に現在の利用者とSYSTEMへアクセス権を限定します。MySQL内のデータファイルとサーバーログはMySQL管理者の保護対象です。

## ローカル同意保存

開発用に別の空DBと別の接続ファイルを用意し、initへ --sample-policy を加えます。受付期間は作成から1日、保存期限の確認用目安は7日です。**7日で削除する設定ではありません。本番の期間の決定値でもありません。**

```powershell
.\.venv\Scripts\python.exe .\manage.py --home 'C:\FestivalWiFi\sample-data' init --db-config 'C:\FestivalWiFi\sample-connection\mysql.json' --sample-policy
.\.venv\Scripts\python.exe .\manage.py --home 'C:\FestivalWiFi\sample-data' mint-local-link
```

発行リンクは300秒有効で、最初のブラウザーに対応します。同意は実際にMySQLへ保存されます。APの照合は行わず、接続資格情報やインターネットへの許可も発行しません。成功表示は「同意保存済み・AP未接続」です。

## 権限と運営

| 役割 | 状態・通知 | 失効要求・通知確認 | 同意CSV | 設定・利用者一覧 |
|---|---|---|---|---|
| viewer | 可 | 不可 | 不可 | 不可 |
| operator | 可 | 可 | 不可 | 不可 |
| records | 可 | 不可 | 可 | 不可 |
| settings | 可 | 可 | 可 | 可 |

add-admin USER --role ROLEで追加、change-admin USER --disableで無効化、--role ROLEで変更、--passwordで対話的にパスワード変更・再有効化します。最後の有効なsettingsアカウントの無効化・降格は拒否します。変更時は対象者の既存ログイン状態を失効させます。

同意に氏名、メール、生のMAC/IP、閲覧履歴は保存しません。規約本文と同意は更新禁止のトリガーで保護します。規約を変更する場合は両プロセスを止め、新しいterms_document_idと規約版・本文を設定して再起動します。

CSVは最大1,000件ずつ、保存期限内の記録を出力します。保存期限を過ぎた同意もDB内には残ります。CSVの数式文字を無害化し、出力操作を監査記録へ残します。CSVファイルを自動削除しません。

workerは30秒ごとに期限の確認・操作状態・監視を処理し、既定で24時間ごとにバックアップを作ります。通知は種類ごとに集約し、確認済みは解決を意味しません。バックアップと通知・監査を自動削除しません。容量不足時は通知するので、保管容量の見直しが必要です。

/health/liveはプロセス応答、/health/readyはDB接続、/health/jobsは最後の定期処理成功から120秒以内かを確認します。DB停止時にはDB内通知を書けないため、503と端末のエラーを確認します。メール・SNS・外部監視先へ送信していません。

## バックアップと復元

詳細は[運用と復旧.md](運用と復旧.md)を参照してください。アプリの23テーブルを一つのREPEATABLE READトランザクションで読み取り、JSON形式を認証付き暗号化します。平文ダンプファイルを作りません。DB接続パスワードはバックアップに含めません。管理者のパスワードハッシュは含むため、暗号化鍵は保護して別途保管してください。

この論理バックアップはMySQLサーバー全体、MySQL利用者・権限、binlog、設定ファイルのバックアップではありません。mysqldump等によるDB管理者のバックアップと組み合わせる場合も、ログやバックアップの自動削除は行いません。

## 試験と本番までの範囲

testsは本番DBや既存MySQLへ接続しません。専用のデータディレクトリを持つ127.0.0.1:13307の試験用MySQLだけを受け付けます。WIFI_TEST_MYSQL_CONFIGにはtest_only=trueを持つ保護した試験接続ファイルを指定します。試験で作ったsff_test_接頭辞のDB、試験データ、ログは削除しません。

```powershell
$env:WIFI_TEST_MYSQL_CONFIG = '試験用接続ファイルの絶対パス'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tests/http_smoke.py
```

本番用保存先・担当者・正式規約・利用期間は未確定です。本番HTTPS、APの誘導情報照合、資格情報発行、RADIUS、実機の絶対期限・許可ロールの観測・切断、IPv6の同等制御は未実装です。来場者数3,500人／雨天2,400人を同時接続数の性能保証へ読み替えていません。APの模擬試験や実機ネットワークの負荷試験は実施していません。

## 参照した公式資料

- [MySQL InnoDBのトランザクション](https://dev.mysql.com/doc/refman/8.4/en/innodb-transaction-model.html)
- [MySQL Connector/Pythonの接続方法](https://dev.mysql.com/doc/connector-python/en/connector-python-example-connecting.html)
- [MySQLバックアップ方式](https://dev.mysql.com/doc/refman/8.4/en/backup-methods.html)
- [Flaskのセキュリティ](https://flask.palletsprojects.com/en/stable/web-security/)
- [Fernet暗号化](https://cryptography.io/en/50.0.2/fernet/)


## 運営機能の追加

操作履歴の検索、保存容量・バックアップ一覧、MySQL接続・権限診断、AP情報の確認を追加しました。詳細は[運営画面とAP確認.md](運営画面とAP確認.md)を参照してください。DB形式4を継続し、スキーマ変更はありません。ログ・記録・バックアップの自動削除は停止を継続します。


## 追加機能と形式2からの更新

通知の引き継ぎ、規約の下書き・ローカル適用、追加認証、まとめて起動・停止、画面改善、容量の増加傾向を追加しました。[追加機能の使い方](追加機能の使い方.md)を確認してください。DB形式4への明示的な更新が必要です。形式2のバックアップは別の空DBへの復元に対応します。ログと記録は保持します。



## 運営準備機能の追加

バックアップの復号・復元検証結果、障害調査資料の出力、当日の運営チェックを追加しました。DB形式4への更新が必要です。[運営準備とバックアップ検証](運営準備とバックアップ検証.md)と[HTTPS導入準備](HTTPS導入準備.md)を参照してください。形式2・3のバックアップは別の空DBへの復元に対応します。ログと記録は保持します。

## 0.7.0の追加

[HTTPS対応コードと導入準備](HTTPS導入準備.md)、[容量警告と管理画面](容量警告と管理画面.md)、[予備サーバーへの移行手順](予備サーバーへの移行手順.md)を追加しました。DB形式4を継続し、形式4からのDB更新は不要です。cryptographyを50.0.2へ更新したため、新しい仮想環境へ依存関係を導入してください。HTTPSは明示的に設定する準備用機能で、受付停止が必須です。通常のローカル画面は従来通り使用できます。

## 0.7.0の復旧・導入機能

[復旧用一式・分割バックアップ・オフライン導入・起動前チェック](復旧とオフライン導入.md)を追加しました。DB形式4を継続します。旧版からは別フォルダーへ展開し、同梱wheelとハッシュ固定で新しい実行環境を準備してください。新しい分割形式は0.7.0以降で復元し、旧形式は256MiBまでの扱いを継続します。

## 0.8.0の検証と修正

[TLS・中断復旧・保存形式の確認](検証と安全性確認.md)を実施しました。復元元の変更検出、Windowsのジャンクションと紛らわしいファイル名の拒否、tar終端の確認、稼働中のDB更新拒否を強化しています。DB形式4と既存の暗号化形式を継続し、0.7.0からのDB更新は不要です。[容量と復旧時間の計画](容量と復旧時間の計画.md)と[切り替え・障害判断・引き継ぎ](切り替えと引き継ぎ.md)も参照してください。公開HTTPS、AP、学校ネットワークへの適用は別途必要です。

## 0.9.0の来場者案内と集計

[画面・多言語・集計の使い方](画面と集計の使い方.md)と[問い合わせ対応の練習資料](問い合わせ対応の練習資料.md)を追加しました。案内は日本語・英語・やさしい日本語、表示は文字200%・高コントラストに対応します。やさしい日本語は案内だけを変更し、規約は原文を表示します。MySQLの既存metaへ時刻とエラー分類ごとの件数だけを保管します。DB形式4を継続し、更新は不要です。集計は同時接続人数を表しません。公開サイト・学校機器には適用していません。

## 0.10.0の運営支援

案内情報の変更案、未保存入力の確認、ログイン期限の予告、10万件集計計測、受付早見表を追加しました。詳しくは「案内情報と入力保護.md」を参照してください。DB形式4・23テーブルを維持します。
