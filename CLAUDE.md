# CLAUDE.md

## ブランチ運用（FreeBSD配置）

配置先はFreeBSD 15.1 amd64（通常のFreeBSD）。MySQLは同じマシンに置く（127.0.0.1のみ）を主構成とする。組み込みだけで対応しきれなかった場合に備え、別マシン構成を`freebsd/mysql-remote`に保険として保存する。

| ブランチ | 構成 | 資料 |
|---|---|---|
| `feat/offline-build-db-templates` | 両構成の共通基点（wheelhouse取得、ビルドworkflow、DB設定ひな形、FreeBSD共通対応） | `docs/ガイド.md` |
| `freebsd/mysql-local` | 主構成。MySQLを同じFreeBSDマシンに置く（127.0.0.1のみ） | `docs/ガイド.md` 4章 |
| `freebsd/mysql-remote` | 保険。MySQLを別マシンに置く（TLS＋証明書検証必須）。基点へ取り込まない | `docs/ガイド.md` 4章 |

- 資料は`docs/ガイド.md`に集約する。例外は利用者の指示で分けた`docs/キャプティブポータル作成手順.md`（VyOS連携の作成・試験手順）と、利用者が追加した`RELEASE.md`（版ごとのリリース判断と試験記録。内容はガイドと食い違わないように保つ）のみ。それ以外の新しい.mdは増やさず、該当の章に追記する（README.mdは案内のみ、CLAUDE.mdは作業ルール）。
- 両構成に共通する変更は基点ブランチに入れ、`mysql-local`へ取り込む。`mysql-remote`は保険なので、共通変更の取り込みは必要になったときに行い、`mysql-remote`側の変更を基点へ戻さない。構成固有の変更だけを各構成ブランチに入れる。
- `main`へのPRは主構成の`freebsd/mysql-local`から出す。基点から直接`main`へ出すと、`main`にある同一マシン構成の手順やrc.dの`REQUIRE: mysql`が消える。
- バイナリはFreeBSD上でビルドする（`docs/ガイド.md`）。Windows/Linux版はFreeBSDで動かない。
- AP連携は未実装（adapter=disconnected）。本番値・承認状態の`false`を書き換えない。
- 実際の接続情報・パスワード・鍵・wheelhouseをコミットしない。
- APIクレジット節約：必要なファイル・範囲だけ読み、大きいPDFや資料は必要なページだけ読む。
