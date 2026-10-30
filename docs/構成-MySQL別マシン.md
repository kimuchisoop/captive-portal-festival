# 構成2：MySQLを別マシンに置く

共通部分は[FreeBSD共通手順](FreeBSD共通手順.md)。**FreeBSD実機・別マシン接続での動作は未確認です。**

```text
[来場者] → [AP/スイッチ/VyOS] → [FreeBSD 15.1：nginx → festival-wifi serve/worker]
                                          │ TLS（CA・ホスト名検証必須）、3306はこの経路だけ
                                          ▼
                                   [DBマシン：MySQL 8.0.16以上]
```

## アプリ側の制約（コードで固定）

127.0.0.1/localhost以外への接続では`ssl_ca`が必須で、証明書とホスト名の両方を検証します（`server/database.py`）。検証を無効にする設定はありません。

## DBマシン

1. 学校内用のCAを作り、MySQLサーバー証明書を発行します。証明書のSANに、`host`に書く名前（例：`db.festival.example`）またはIPを必ず入れます。CAの秘密鍵はDBマシン・アプリマシンに置かず別に保管します。
2. MySQLに`ssl_cert`・`ssl_key`を設定し、`require_secure_transport=ON`にします。
3. 空の専用DB`app_db`、`app_service@<アプリのIP>`、`app_maintenance@<アプリのIP>`を作り、両方に`REQUIRE SSL`を付けます。サービス用の権限は[workflow-privileges.json](../server/workflow-privileges.json)の`runtime`の範囲だけにし、`init`後に`diagnose-mysql`で確認します。
4. DBマシンのファイアウォールで、3306をアプリマシンのIPからだけ許可します。

## アプリ側（FreeBSD）

- [runtime.remote.example.json](../server/runtime.remote.example.json)と[db-maintenance.remote.example.json](../server/db-maintenance.remote.example.json)を`/usr/local/etc/festival-wifi/`へコピーし、festival所有・600にします。
- CA証明書（公開部分のみ）を`/usr/local/etc/festival-wifi/mysql-ca.pem`に置きます。
- pfで、アプリからDBマシンの3306への送信だけを許可します。
- 名前で接続する場合、DNSまたは`/etc/hosts`で名前を固定します（証明書のSANと一致させる）。

## 注意

- DBとの通信が切れると新規受付は確定しません（現行設計）。復旧後に保存結果を確認します。
- 時刻がずれると証明書検証に失敗するため、両マシンでNTPを有効にします。
- バックアップはDBマシンとも別の媒体・マシンに保管します。
