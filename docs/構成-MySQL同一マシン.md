# 構成1：MySQLを同じFreeBSDマシンに置く

共通部分は[FreeBSD共通手順](FreeBSD共通手順.md)。**FreeBSD実機での動作は未確認です。**

```text
[来場者] → [AP/スイッチ/VyOS] → [FreeBSD 15.1：nginx → festival-wifi serve/worker → MySQL(127.0.0.1)]
                                                         └ バックアップ → 別媒体/別マシン（必須）
```

## MySQL

```sh
pkg search -x '^mysql8[0-9]-server'   # 実機の名称を確認（例：mysql84-server）
pkg install mysql84-server
sysrc mysql_enable=YES mysql_args="--bind-address=127.0.0.1 --mysqlx=OFF"
service mysql-server start
```

- 外部から3306へ接続させません（bind-address=127.0.0.1、pfでも3306を閉じる）。
- 空の専用DB`app_db`、サービス用`app_service@127.0.0.1`、保守用`app_maintenance@127.0.0.1`を作ります。サービス用の権限は[workflow-privileges.json](../server/workflow-privileges.json)の`runtime`の範囲だけにし、`init`後に`diagnose-mysql`で確認します。GRANT OPTIONや全体権限を付けません。

## 接続設定

[runtime.example.json](../server/runtime.example.json)と[db-maintenance.example.json](../server/db-maintenance.example.json)をそのまま使えます（host=127.0.0.1、`ssl_ca`不要）。`/usr/local/etc/festival-wifi/`へコピーし、festival所有・600にしてパスワードを書き換えます。

## 起動順

rc.dスクリプトは`REQUIRE: mysql`を持ち、MySQL → serve → worker の順に起動します。

## 注意

- 1台が壊れるとDBとバックアップを同時に失います。バックアップファイルと鍵は必ず別媒体・別マシンへ保管し、別の空DBへの復元確認を行います。
- アプリ・MySQL・バックアップが同じディスクを使います。`db_warning_bytes`と`backup_warning_bytes`を実容量から決めます。
