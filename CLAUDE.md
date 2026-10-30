# CLAUDE.md

## ブランチ運用（FreeBSD配置）

配置先はFreeBSD 15.1 amd64（通常のFreeBSD）。MySQLの置き場所で構成を2つに分け、ブランチを分ける。

| ブランチ | 構成 | 構成資料 |
|---|---|---|
| `feat/offline-build-db-templates` | 両構成の共通基点（wheelhouse取得、ビルドworkflow、DB設定ひな形、FreeBSD共通対応） | `docs/FreeBSD共通手順.md` |
| `freebsd/mysql-local` | MySQLを同じFreeBSDマシンに置く（127.0.0.1のみ） | `docs/構成-MySQL同一マシン.md` |
| `freebsd/mysql-remote` | MySQLを別マシンに置く（TLS＋証明書検証必須） | `docs/構成-MySQL別マシン.md` |

- 両構成に共通する変更は基点ブランチに入れ、各構成ブランチへ取り込む。構成固有の変更だけを各構成ブランチに入れる。
- バイナリはFreeBSD上でビルドする（`docs/FreeBSD共通手順.md`）。Windows/Linux版はFreeBSDで動かない。
- AP連携は未実装（adapter=disconnected）。本番値・承認状態の`false`を書き換えない。
- 実際の接続情報・パスワード・鍵・wheelhouseをコミットしない。
- APIクレジット節約：必要なファイル・範囲だけ読み、大きいPDFや資料は必要なページだけ読む。
