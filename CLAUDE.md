# CLAUDE.md

## ブランチ運用（FreeBSD配置）

配置先はFreeBSD 15.1 amd64（通常のFreeBSD）。MySQLは別マシンに置く（2026-10-30決定、ガイドC07）。

| ブランチ | 構成 | 資料 |
|---|---|---|
| `feat/offline-build-db-templates` | 基点（wheelhouse取得、ビルドworkflow、DB設定ひな形、FreeBSD対応）。別マシン構成の内容も含む | `docs/ガイド.md` |
| `freebsd/mysql-remote` | MySQLを別マシンに置く（TLS＋証明書検証必須）。採用した構成 | `docs/ガイド.md` 4章 |
| `freebsd/mysql-local` | MySQLを同じFreeBSDマシンに置く構成。**使わない**（取り込み・追加をしない。消さずに残す） | — |

- 資料は`docs/ガイド.md`に集約する。例外は利用者の指示で分けた`docs/キャプティブポータル作成手順.md`（VyOS連携の作成・試験手順）のみ。それ以外の新しい.mdは増やさず、該当の章に追記する（README.mdは案内のみ、CLAUDE.mdは作業ルール）。
- 変更は基点ブランチに入れ、`freebsd/mysql-remote`へ取り込む。`freebsd/mysql-local`へは取り込まない。
- バイナリはFreeBSD上でビルドする（`docs/ガイド.md`）。Windows/Linux版はFreeBSDで動かない。
- AP連携は未実装（adapter=disconnected）。本番値・承認状態の`false`を書き換えない。
- 実際の接続情報・パスワード・鍵・wheelhouseをコミットしない。
- APIクレジット節約：必要なファイル・範囲だけ読み、大きいPDFや資料は必要なページだけ読む。
