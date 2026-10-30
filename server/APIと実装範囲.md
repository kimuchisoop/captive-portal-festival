> **docs8の履歴資料**：以下は0.10.0/0.10.1までの説明を含みます。形式5の現在の実装候補は[README](README.md)と[0.11.0の実装と未確認範囲](0.11.0実装と未確認.md)を優先します。試験・DB適用は保留中です。

> **0.10.1候補 / docs7**：本版の修正・軽量化と未検証範囲は[今回の変更](今回の変更と確認範囲.md)を優先します。以下は0.10.0までの手順/説明を含みます。試験・DB適用は保留中です。

> **0.10.0 資料整理版の案内**：この文書には機能追加当時の記述・旧版向けコマンドが含まれます。導入・起動・更新は [最新版の入口](導入・更新の入口.md)、採用済み方針と旧設計の差は [決定事項](運用の判断と決定事項.md) を先に確認してください。DB形式4からの更新は不要です。今回、試験は保留です。

# APIと実装範囲

MySQL版ローカル開発版0.7.0。旧「認証連携詳細設計」の全体を実装したものではありません。外部ポータル／RADIUS／NASに関わる入口と引き継ぎは未接続です。IPv6や実機設定も変更していません。

## 共通

変更要求はapplication/json、設定と完全一致のOrigin、X-CSRF-Tokenを要求します。最初のセッション発行だけはCSRF不要で、Originは必要です。Hostも設定値に限定します。CORSは許可しません。本文上限64KiBです。

来場者Cookie portal_sessionと管理者Cookie admin_sessionは別です。サーバーにはCookie値のSHA-256とCSRF検証値を保存します。CookieはHttpOnly・SameSite=Strictです。通常のループバックHTTPモードではSecure属性は無効、明示的なHTTPS準備モードではSecure属性を有効にします。準備モードは受付停止が必須で、本番配信へ適用した状態ではありません。

APIの応答にはno-storeとX-Correlation-IDを設定します。エラーはcode / message / retryable / correlation_idです。ログへ要求本文、パスワード、Cookie、接続の生情報を出力しません。

## 来場者

| メソッド | パス | 状態 |
|---|---|---|
| GET | /v1/public?lang=ja または en | 仮規約・サービス状態 |
| POST | /v1/session | 来場者セッションとCSRF発行 |
| POST | /v1/contexts | CLI発行のローカルリンクだけを検証。本番NAS署名や属性の検証は未実装 |
| GET | /v1/contexts/{id}?lang=ja または en | 所有者・有効期限を確認して規約を返す |
| POST | /v1/consents | 不変の同意、pendingの許可、authorize操作を一括保存 |
| GET | /v1/grants/{id} | 所有者だけが照会。network_verifiedは常にfalse |
| POST | /v1/grants/{id}/handoffs | 所有者確認後503 adapter_unavailable。資格情報は発行しない |

contexts / consents / 管理者のrevocationsはUUIDのIdempotency-Keyが必須です。同じ所有者・パス・キー・本文なら同じ結果を返し、本文が変わると409です。再送の成功応答は保存直後の結果なので、後からGETで現在状態を確認します。コンテキストは別のキーでも複数の同意を作らず、異なる言語・規約での再同意を同一記録へ紐付けて成功扱いしません。

context作成の本文はlaunch_refのみです。MAC/IP/NAS/戻り先の任意入力を受け付けません。外部NASの検証情報の受け取りは将来の別アダプターで実装します。

同意作成の本文は context_id / accepted（真偽値trueのみ）/ terms_document_id / terms_sha256 / policy_version / language の6項目です。不一致の規約は409、所有者不一致・期限切れcontextは404です。同意記録と規約アーカイブのUPDATEはDBでも禁止します。

## 管理者

| メソッド | パス | 権限・機能 |
|---|---|---|
| GET, POST | /v1/admin/session | GETは既存セッション、POSTはログイン前のCSRF準備にも対応 |
| POST | /v1/admin/login | username / password、試行制限、セッション切り替え |
| POST | /v1/admin/logout | 自分のセッション破棄 |
| GET | /v1/admin/overview | 全役割、件数・定期処理・バックアップ状況 |
| GET | /v1/admin/notifications | 全役割、未解消通知、最大100件 |
| POST | /v1/admin/notifications/{id}/acknowledgements | operator/settings、確認済みへの変更 |
| GET | /v1/admin/grants | operator/settings、最新100件 |
| POST | /v1/admin/grants/{id}/revocations | operator/settings、失効とdisconnect操作を一括保存 |
| GET | /v1/admin/operations/{id} | operator/settings、操作の実際の進捗 |
| GET | /v1/admin/consents/export?after=0 | records/settings、最大1,000件、X-Next-Cursorで続き |
| GET | /v1/admin/settings | settings、鍵を除いた設定の参照 |
| GET | /v1/admin/users | settings、パスワードハッシュを除いた一覧 |

ログイン・セッション・ログアウト・確認済み変更には業務処理用のIdempotency-Keyを要求しません。確認済み変更は状態の上書きなので繰り返しても複数の通知は作りません。上記3業務操作についてはDBの排他トランザクションで並行再送も一括処理します。

失効理由はoperator_request / abuse / service_endのいずれかです。自由記入に個人情報を残さない設計です。許可をrevokedへ変更したうえで操作をqueuedにします。workerはAP未接続を検出してfailedにし、confirmed・acknowledgedを捏造しません。この版のfailedは自動再試行しません。アダプター未接続の永続エラーで、実機向けの送信処理自体がないためです。

## 実装済みと未実装の境界

実装済み：MySQL InnoDB、排他制御、セッション、権限、入力検証、規約保存、保存期限の確認（自動削除停止）、暗号化バックアップ、復元、内部通知、ローカル画面、テストと手順。

未実装：実NASの誘導情報照合、認証資格情報の発行と120秒暗号化キャッシュ、RADIUSパケット処理、Message-Authenticator検証、絶対時刻の装置設定、通信許可と対象ロールの観測、CoA/Disconnect応答、実ネットワークでの期限・再接続・AP移動、上流帯域／同時利用数の収集、本番用DBとHTTPS配信、外部監視先への送信。

受理済みのDB行にactiveの値があっても、本版のnetwork_verifiedはfalseのままです。設定を書き換えて本番へ出せるスイッチはなく、production_enabled=trueまたはmodeがlocal以外なら起動できません。これは未確定の実機仕様を隠して本番利用を始めないための実装上の境界です。


## MySQL版の保持設定

DB形式4、MySQL専用です。ログ・同意記録・通知・バックアップを期限で自動削除しません。期限対象件数だけをworkerが確認します。バックアップはMySQLの一貫した読み取りから作成する認証付き暗号化JSONです。SQLite用の保存・復元処理は含みません。


## 運営機能の追加

操作履歴の検索、保存容量・バックアップ一覧、MySQL接続・権限診断、AP情報の確認を追加しました。詳細は[運営画面とAP確認.md](運営画面とAP確認.md)を参照してください。DB形式4を継続し、スキーマ変更はありません。ログ・記録・バックアップの自動削除は停止を継続します。


## 追加機能と形式2からの更新

通知の引き継ぎ、規約の下書き・ローカル適用、追加認証、まとめて起動・停止、画面改善、容量の増加傾向を追加しました。[追加機能の使い方](追加機能の使い方.md)を確認してください。DB形式4への明示的な更新が必要です。形式2のバックアップは別の空DBへの復元に対応します。ログと記録は保持します。


## 運営準備機能の追加

バックアップの復号・復元検証結果、障害調査資料の出力、当日の運営チェックを追加しました。DB形式4への更新が必要です。[運営準備とバックアップ検証](運営準備とバックアップ検証.md)と[HTTPS導入準備](HTTPS導入準備.md)を参照してください。形式2・3のバックアップは別の空DBへの復元に対応します。ログと記録は保持します。
