> **docs8の履歴資料**：以下は0.10.0/0.10.1までの説明を含みます。形式5の現在の実装候補は[README](README.md)と[0.11.0の実装と未確認範囲](0.11.0実装と未確認.md)を優先します。試験・DB適用は保留中です。

> **0.10.1候補 / docs7**：本版の修正・軽量化と未検証範囲は[今回の変更](今回の変更と確認範囲.md)を優先します。以下は0.10.0までの手順/説明を含みます。試験・DB適用は保留中です。

# 運営機能追加・AP確認手順

0.7.0 / 2026-10-19 / MySQL DB形式4を継続。DBスキーマの変更はありません。

## 操作履歴

設定管理者でログインし「操作履歴を検索」を使用します。開始日・終了日は日本時間で指定し、終了日当日を含めます。担当者・操作内容を選択でき、1ページ50件、続きは「次の履歴を表示」です。同時刻の履歴もIDを含む順序でページを分けます。検索で記録を更新・削除しません。検索中の新しい操作を反映するときは、もう一度検索してください。

設定管理者だけが履歴の担当者・操作番号を閲覧できます。他の役割にはAPI側でも許可しません。ログイン失敗には、入力したパスワードや未認証の利用者名を保存しません。以前の記録で担当者IDや操作対象が保存されていない箇所は、遡って補完した扱いにしません。

## 容量とバックアップ

全役割が「保存容量」で集計値を確認できます。MySQL使用量はinformation_schemaのDATA_LENGTHとINDEX_LENGTHから求める推定値です。MySQLの実ファイル容量やサーバー本体の空き容量を示す値ではありません。空き容量の測定対象はアプリのデータフォルダーを置くディスクです。[MySQLの容量情報](https://dev.mysql.com/doc/refman/8.4/en/information-schema-tables-table.html)

MySQLとバックアップの警告値は、保護したconfig.jsonのdb_warning_bytes、backup_warning_bytesにバイト単位で指定します。初期値nullは未設定です。両プロセスを停止して設定・再起動してください。値は実際の保管容量と運営方針から決めます。仮の値を本番の容量上限にしません。

workerが警告値以上を検出すると通知します。未設定も通知します。通知後もログ、同意、バックアップを削除しません。容量不足時は保管容量を増やす、保管先を見直すなど運営側で対応してください。

記録担当者と設定管理者はバックアップの日時・ファイル名・容量を確認できます。「次のバックアップを表示」で続きを取得し、「一覧を更新」で最新から再表示します。ファイル内容や鍵をブラウザーへ配布しません。一覧取得では復号・復元試験をしないため、表示は「復元未検査」です。シンボリックリンクや想定外の名前は一覧対象外ですが、削除しません。

## MySQLの診断

設定管理者が「診断を実行」を押すと、接続先、現在の通信の暗号化、証明書検証設定、現在のMySQL利用者の権限を読み取ります。診断結果を保護したdiagnosticsフォルダーに保存し、実行を監査記録へ残します。接続パスワード、パスワードハッシュ、暗号化鍵、SHOW GRANTSの原文は結果に出しません。

通常動作用の専用DBに対するSELECT/INSERT/UPDATE/DELETEだけを直接確認できた場合を権限の確認済みとします。追加権限、別DB・全体への権限、権限の再付与、展開できていないロールは要確認にします。ロールを自動的に展開したり、GRANT/REVOKEを実行したりしません。[MySQL SHOW GRANTS](https://dev.mysql.com/doc/refman/8.4/en/show-grants.html)

ローカルで暗号化されていても、CA・ホスト名の検証が未設定なら別の要確認として表示します。遠隔MySQLは既存の接続設定でCAとホスト名の検証が必須です。権限の確認済みだけで本番開始可能と判定しません。[MySQL暗号化接続](https://dev.mysql.com/doc/refman/8.4/en/using-encrypted-connections.html)

端末からも次を実行できます。診断コマンドは権限を変更しません。

```powershell
.\start.ps1 -DataDirectory 'C:\FestivalWiFi\local-data' -Mode diagnose-mysql
.\start.ps1 -DataDirectory 'C:\FestivalWiFi\local-data' -Mode ap-check
```

## APの確認：現在の到達点

利用者から「まだ不明」との回答を受けたため、製品番号・起動OS・管理方式は未確認のままです。過去の引継ぎにあるAPIN0315は、AP-315とIAP-315に共通する認証用型式です。この値だけで実機の管理方式を決めません。[310 Series公式スタートガイド](https://arubanetworking.hpe.com/techdocs/hardware/aps/ap310/sug/AP-310_Startup_Guide_EN.pdf)

1. 本体ラベルの製品名と製品番号（SKU）を文字で記録します。APIN0315以外の項目です。
2. 既存の管理画面を開ける場合は、機器情報から起動中のOS名・バージョンを記録します。管理先がVCかコントローラーかも確認します。
3. 既に利用できるコンソールがある場合は、実機と一致する公式CLI資料に従い、読み取り用のshow version等で確認します。CLI資料はOS別です。OS未確認の機器へ設定用コマンドを流しません。[Instant CLI資料](https://arubanetworking.hpe.com/techdocs/Aruba-Instant-8.x-Books/Aruba-Instant-8.x-CLI-Guide.pdf)
4. Instantと確認でき、対応するコマンドがある版では、show external-captive-portalで既存プロファイルを読み取れます。コマンドがない場合は実機版の資料を確認します。[Instant読み取りコマンド](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/sh-extern-cp.htm)
5. 工場出荷状態へのリセット、ファームウェア変更、管理方式の変換、ネットワーク設定の上書きは、この確認手順には含めません。

確認できた値だけをdevice-profile.example.jsonから保護したデータフォルダー内のdevice-profile.jsonへ記入します。management_modeはinstantまたはcontrollerです。不明値はnullのままにします。設定管理者画面とap-checkは、未記入の項目を列挙します。

## 管理方式が判明した後の連携計画

| 管理方式 | 次に確認する対象 |
|---|---|
| Instant | 実機OS版、VC、外部ポータルの認証方式・HTTPS設定、RADIUS設定、端末別の制限 |
| コントローラー管理 | コントローラーの正式型番とOS、APとの対応、外部ポータル、RADIUS、ロールと端末状態の照合 |
| 未確認 | ラベルと起動情報の確認を先に行う |

Instant 8.5の公式資料はRADIUSを使う外部ポータルと認証テキスト方式を区別しています。今回の設計では、実機適合を確認した上で外部ポータル＋RADIUSの経路へ対応付ける方針です。資料に記載された誘導パラメーターを、そのまま本人確認の根拠にしません。[外部ポータルの公式設定例](https://arubanetworking.hpe.com/techdocs/Archived/Instant-AOS-8/Instant_85_WebHelp/Content/instant-ug/captive-portal/conf-ext-cp.htm)

次の7点は引き続き実機確認が必要です。画面や確認ファイルを埋めただけでは確認済みにしません。

- NAS側と照合できる接続元確認
- HTTPSの認証引き継ぎ先とフォーム項目
- RADIUS要求と認証情報の検証
- 装置による絶対時刻の利用期限
- 対象端末の許可ロールと接続状態の観測
- 対象セッションへの切断と結果確認
- IPv6を含む同等の制限

この版は情報が揃ってもAPへの通信を開始しません。adapter=disconnected、live_verified=false、production_ready=falseを継続します。既存の同意保存はMySQLへ行い、インターネットへの許可成立とは扱いません。

## APIの追加

| API | 権限 |
|---|---|
| GET /v1/admin/audit | 設定管理者 |
| GET /v1/admin/storage | 全役割、集計のみ |
| GET /v1/admin/backups | 記録担当・設定管理者 |
| POST /v1/admin/diagnostics | 設定管理者、Origin/CSRF必須 |
| GET /v1/admin/ap-readiness | 設定管理者 |

履歴のfromはUTCの開始時刻以上、untilはUTCの終了時刻未満です。actor/actionで絞り込み、before_timeとbefore_idを一緒に渡して続きを取得します。limitは1〜100です。バックアップのbeforeには直前応答のnext_cursorを使います。パスを指定してファイルを取得する機能はありません。


## 追加機能と形式2からの更新

通知の引き継ぎ、規約の下書き・ローカル適用、追加認証、まとめて起動・停止、画面改善、容量の増加傾向を追加しました。[追加機能の使い方](追加機能の使い方.md)を確認してください。DB形式4への明示的な更新が必要です。形式2のバックアップは別の空DBへの復元に対応します。ログと記録は保持します。


## 運営準備機能の追加

バックアップの復号・復元検証結果、障害調査資料の出力、当日の運営チェックを追加しました。DB形式4への更新が必要です。[運営準備とバックアップ検証](運営準備とバックアップ検証.md)と[HTTPS導入準備](HTTPS導入準備.md)を参照してください。形式2・3のバックアップは別の空DBへの復元に対応します。ログと記録は保持します。
