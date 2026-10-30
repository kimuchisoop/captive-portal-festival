# FreeBSD 15.1 amd64 共通手順（バイナリ配置）

MySQLの置き場所による違いは各構成ブランチの資料を参照します。この資料は両構成で共通の部分です。**FreeBSD実機での動作は未確認です。** パッケージ名は`pkg search`で実機の名称を確認してから使ってください。

## 1. ビルド（FreeBSD 15.1 amd64上で実行）

Windows/Linux版のバイナリはFreeBSDでは動きません。配置先と同じFreeBSD 15.1 amd64（専用のビルド用環境を推奨）でビルドします。

```sh
pkg install python312 py312-cryptography git
python3.12 -m venv --system-site-packages ~/build-venv
~/build-venv/bin/pip install Flask==3.1.3 Werkzeug==3.1.9 waitress==3.0.2 blinker==1.9.0 click==8.5.0 itsdangerous==2.2.0 Jinja2==3.1.6 MarkupSafe==3.0.4 mysql-connector-python==9.7.0 pyinstaller==6.22.3
~/build-venv/bin/python tools/build_binary.py --output /tmp/festival-build
```

- cryptography（とcffi）はPyPIにFreeBSD用wheelがないため、署名されたpkgのものを使います。`requirements.lock`のハッシュはWindows用なので使いません。使った版を`pkg info py312-cryptography`で記録してください。
- PyInstallerはFreeBSD用の起動部を導入時にビルドします（ベースのclangを使用）。
- 成功すると`/tmp/festival-build/dist/festival-wifi/`ができ、`--version`・`--self-check`・`--help`まで自動で確認します。

## 2. 配置

```sh
pw useradd festival -d /nonexistent -s /usr/sbin/nologin -c "Festival Wi-Fi"
mkdir -p /usr/local/festival-wifi /var/db/festival-wifi
cp -R /tmp/festival-build/dist/festival-wifi/ /usr/local/festival-wifi/
chown -R root:wheel /usr/local/festival-wifi
chown festival:festival /var/db/festival-wifi && chmod 700 /var/db/festival-wifi
```

プログラム（root所有・書込不可）とデータ（festival所有・700）を分けます。DB接続のJSONは`/var/db/festival-wifi`の外の、festivalだけが読める場所（例：`/usr/local/etc/festival-wifi/`、600）に置きます。

## 3. 初期化と自動起動

```sh
su -m festival -c '/usr/local/festival-wifi/festival-wifi --home /var/db/festival-wifi preflight'
cp server/deployment/freebsd/rc.d/festival_wifi_* /usr/local/etc/rc.d/ && chmod 555 /usr/local/etc/rc.d/festival_wifi_*
sysrc festival_wifi_serve_enable=YES festival_wifi_worker_enable=YES
service festival_wifi_serve start && service festival_wifi_worker start
```

`init`・`add-admin`はREADMEの手順に従います。rc.dスクリプトは改行がLFである必要があります（`.gitattributes`で固定済み）。HTTPS配置計画（`https-plan`）では`deployment_os`に`freebsd`を指定できます。
