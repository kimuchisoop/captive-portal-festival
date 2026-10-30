> **docs8の履歴資料**：以下は0.10.0/0.10.1までの説明を含みます。形式5の現在の実装候補は[README](README.md)と[0.11.0の実装と未確認範囲](0.11.0実装と未確認.md)を優先します。試験・DB適用は保留中です。

# HTTPS対応コードと導入準備

0.8.0 / DB形式4 / 本番受付とAP連携は無効のままです。

この版はHTTPSの接続元・プロキシ・Cookie処理を備えます。ローカルのNginx 1.31.7と試験用証明書を使った実TLS、証明書検証、接続元制限の25項目を確認しました。詳細は[検証結果](検証と安全性確認.md)を参照してください。正式証明書の発行、DNS変更、学校ネットワークへの適用は行っていません。公開環境での検証が残ります。

## 二つの接続先と一つのプロキシ

来場者用と管理者用には異なるホスト名を使用します。HTTPSは443番だけを想定し、URL末尾のスラッシュや任意ポートは受け付けません。フロントのNginxから同じサーバーの127.0.0.1へ転送する一段構成です。CDNや別ホストのプロキシ、複数段の転送には対応していません。VyOSをアプリ配信サーバーへ流用する前提ではありません。

管理者の画面・API・healthは管理ホストだけ、来場者の画面・APIは来場者ホストだけで受け付けます。staticは両ホストで使います。Nginx側にも管理用CIDR制限と来場者側の管理経路拒否が必要です。アプリ側の境界判定をネットワーク制限の代わりにしません。

## アプリ設定（未適用の記入例）

config.jsonのoriginは内部待受のhttp://127.0.0.1:8890のままです。別に以下を設定します。例のドメインは説明用で、正式な値へ差し替えてください。

```json
"https_transport": {
  "enabled": true,
  "portal_origin": "https://wifi.example.org",
  "admin_origin": "https://admin.example.org",
  "trusted_proxy": "127.0.0.1"
}
```

mode=local、production_enabled=false、automatic_deletion_enabled=falseを維持し、local_intake_enabled=falseを必須にします。HTTPS対応を有効にしても来場者の受付や通信許可は有効になりません。この設定では通常のlocalhostブラウザーによる直接接続も拒否します。ローカルの画面確認ではenabled=falseを使います。

## 転送境界

WSGIの生の接続元が127.0.0.1で、Hostが設定した正確な接続先、X-Forwarded-Protoが単独のhttps、X-Forwarded-Forが一つのIPの場合だけ受け付けます。任意のForwarded、転送ホスト・ポート・プレフィックス、複数IPの列、不明なX-Forwarded-*を拒否します。検査後にHTTPSと接続元IPをアプリへ渡し、転送ヘッダーを取り除きます。ローカルOS利用者がloopbackへ直接到達できる点はOSのアクセス制御で管理します。

Waitress自身では転送値を解釈せず、アプリの境界処理が一度だけ検査します。ローカル通常モードではWaitressが未信頼の転送ヘッダーを除去します。POST等のOrigin一致検査・CSRF・権限検査は両モードで維持します。HTTPS時のログイン・追加認証・ログアウトのCookieはSecure/HttpOnly/SameSite=Strict、ホスト限定、Path=/です。HSTSはまずmax-age=3600だけで、includeSubDomains/preloadは設定しません。

## 停止状態の設定生成

deployment/https-plan.example.jsonに配信OS・二つのホスト・各証明書/秘密鍵のパス・管理ネットワークを記入し、次を実行します。

```powershell
.\.venv\Scripts\python.exe .\manage.py --home 'C:\FestivalWiFi\local-data' prepare-https --plan '.\deployment\https-plan.example.json' --output 'C:\FestivalWiFi\https-review-新しい名前'
```

不明な値はnullのままにします。不足項目を報告し、完全な入力の場合だけ停止状態の設定を生成します。生成結果はアプリへ転送せず503を返します。管理側はCIDR許可の後にコンテンツ処理へ進む構成です。新しい空の停止用ディレクトリが必要です。生成処理は証明書ファイルの実在や期限を検査しません。

deployment/nginx.proxy-headers.example.confは、将来転送する際のヘッダー指定の参照資料です。閉じた設定へそのままincludeしません。実際のproxy_passは意図的に記載していません。転送時は固定Hostを使い、利用者のX-Forwarded-Forを追記せず$remote_addrで上書きします。

## 本番導入前に確認するもの

| 項目 | 必要な確認 |
|---|---|
| 配信先 | OS、保守担当、二つの正式ホスト、DNS、NTP |
| TLS | 正式証明書、SAN、チェーン、期限、秘密鍵のアクセス権、更新方法 |
| 接続制限 | IPv4/IPv6、管理ネットワーク、公開側の管理経路拒否、内部ポート非公開 |
| Nginx | nginx -t、未知Hostの拒否、実際のTLS通信、管理CIDR外からの拒否 |
| アプリ | 実ブラウザーでCookieとOrigin、ログイン・追加認証・ログアウト、受付停止 |
| ログ | access_logはIPやqueryを含めない既存の形式を使用。error_logにIP等が入る可能性を踏まえアクセス制限・容量を管理。削除しない |
| 学校運用 | 利用条件・保存担当者・回線・AP方式・利用期限・承認と実機試験 |

コード・HTTPヘッダー試験に加え、0.8.0でローカルの実TLS試験を実施しています。Windows版Nginxと試験証明書での結果を公開環境の性能保証には使用しません。公開可能の判定は常にfalseを継続します。

参考：[Flaskのプロキシ境界](https://flask.palletsprojects.com/en/stable/deploying/proxy_fix/)、[Waitressの転送設定](https://docs.pylonsproject.org/projects/waitress/en/latest/reverse-proxy.html)、[Nginx HTTPS](https://nginx.org/en/docs/http/configuring_https_servers.html)、[Nginxのアクセス制御](https://nginx.org/en/docs/http/ngx_http_access_module.html)。
