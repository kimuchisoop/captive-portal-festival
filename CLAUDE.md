# CLAUDE.md

## ブランチ運用（FreeBSD配置）

配置先はFreeBSD 15.1 amd64（通常のFreeBSD）。MySQLの置き場所で構成を2つに分け、ブランチを分ける。

| ブランチ | 構成 | 資料 |
|---|---|---|
| `feat/offline-build-db-templates` | 両構成の共通基点（wheelhouse取得、ビルドworkflow、DB設定ひな形、FreeBSD共通対応） | `docs/ガイド.md` |
| `freebsd/mysql-local` | MySQLを同じFreeBSDマシンに置く（127.0.0.1のみ） | `docs/ガイド.md` 4章 |
| `freebsd/mysql-remote` | MySQLを別マシンに置く（TLS＋証明書検証必須） | `docs/ガイド.md` 4章 |

- 資料は`docs/ガイド.md`に集約する。例外は利用者の指示で分けた`docs/キャプティブポータル作成手順.md`（VyOS連携の作成・試験手順）のみ。それ以外の新しい.mdは増やさず、該当の章に追記する（README.mdは案内のみ、CLAUDE.mdは作業ルール）。
- 両構成に共通する変更は基点ブランチに入れ、各構成ブランチへ取り込む。構成固有の変更だけを各構成ブランチに入れる。
- バイナリはFreeBSD上でビルドする（`docs/ガイド.md`）。Windows/Linux版はFreeBSDで動かない。
- AP連携は未実装（adapter=disconnected）。本番値・承認状態の`false`を書き換えない。
- 実際の接続情報・パスワード・鍵・wheelhouseをコミットしない。
- APIクレジット節約：必要なファイル・範囲だけ読み、大きいPDFや資料は必要なページだけ読む。
