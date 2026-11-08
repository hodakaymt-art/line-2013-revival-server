# LINE 2.5.0 (iOS) 登録フロー — 実機で確認できたこと

2026-11-05 時点。端末: iPod touch 4G (iOS 5.1.1, 脱獄済み)。サーバー line_server.py v0.21。

## 到達状況
- 登録(電話番号 → 認証コード → 端末登録)を通過し、ホーム画面側の初期化呼び出しまで到達
- 認証コードはどの値でも通る検証モード。サーバーはLAN内のみで使うこと

## 呼び出し順と応答の形 (Binary プロトコル, /api/v3/TalkService.do)
1. startVerification(2 region, 3 carrier i32, 4 phone, 5 udidHash, 6 DeviceInfo)
   → VerificationSessionData {1 sessionId, 2 method(1=SMS), 3 callback, 4 phone, 5 countryCode, 6 nsn, 7 availableMethods list<i32>, 8 callerIdMask}
2. verifyPhone(2 sessionId, 3 pinCode, 4 udidHash) → **i32** (成功値は 1 で通過)
3. registerDevice(2 sessionId) → **string** (authToken)
4. 続けて /S3, /P3, /BUDDY3, /SHOP3 で初期化(updateSettings, updateProfileAttribute, updateSettingsAttribute, updateNotificationTokenWithBytes, getPromotedBuddyContacts, getNewlyReleasedBuddyIds, getActivePurchaseVersions)
- changeVerificationMethod(2 sessionId, 3 method i32) → VerificationSessionData

## 教訓
- 応答の型は、アプリ内のシンボル `<Method>_result` の `V__success` 型(Ti=i32, T@"NSString"=string, T@"LineXxx"=struct)で判定できる。型が違うと、クライアントは同じ呼び出しを繰り返し画面が進まない
- 認証コードは本物の LINE と同じ4桁を使う

## HTTP 側
- 起動時: GET /m?u=client://iphoneapp.line, GET /app/terms_simple/ja, GET /notice/list.nhn?os=iphone..., GET /products/productVersions_0.meta
- 証明書: iPod に server.crt(/ca.crt で配布)を入れる。TLS1.2 ECDHE-RSA-AES256-SHA384 で成功

## 次
- 起動後の getProfile / getContacts / fetchOperations(/P3) をログで確認 → 友だち・トーク(Windows版と共通)

## 追記 2026-11-05 (v0.27): 友だち追加とトークが動いた
- **友だち追加**: findAndAddContactsByUserid の応答(map<mid, Contact>)だけでは iPod は「追加できませんでした」と判断する。追加した本人に **ADD_CONTACT(OpType 4)** を fetchOperations(/P3)で返すと、iPod が getContact を呼んで一覧に反映する(v0.26)
- Contact: 10 type=1(MID), 11 status=1(FRIEND), 21 relation, 22 displayName, 23 phoneticName, 25 thumbnailUrl, 26 statusMessage, 31〜34 capable(Voice/Video/Myhome/Buddy), 35 attributes, 36 settings
- **メッセージ送信は Thrift ではない**: POST /C2 (gw.line.naver.jp)。独自フレーム
  `01 | int32 cmd(0x20/0x40) | byte 番号 | int32 長さ | "<宛先mid>\t<本文>"`(UTF-8)
- /C2 の応答は 同形式のフレームでメッセージID(数字文字列)を返す推測実装で、iPod は受理した(Echo Bot宛・Windows宛とも配送を確認)
- 受信は /P3 fetchOperations の OpType 26(RECEIVE_MESSAGE)。既読は sendChatChecked(/S3, 戻り値なし)
- 環境変数 LINE_C2_MODE=2/3 で /C2 の応答形式を切り替え可能(既定は1)
- 起動ごとに "handshake FAILED: CERTIFICATE_UNKNOWN" が数回出るが、直後に別接続で成功するため実害なし(一部ホストの証明書を iOS が拒否している様子。未調査)

## 未実装・次の課題
- 画像/スタンプ/位置情報などのメッセージ種別(/C2 の cmd・種別の違いは未解析)
- generateUserTicket、getProfile(iOS は起動時に呼ばない)、グループ
- 再起動時に ADD_CONTACT 等の操作がメモリ上のため失われる(永続化していない)

## 未解決: iOS で送信したメッセージの日付が 12/20(火) になる (2026-11-06, v0.28〜v0.33)
症状: iPod から /C2 で送ったメッセージの吹き出しの日付だけが壊れる(12/25 → 12/20 など、再起動ごとに違う)。受信側(Echo の返信等)は今日の日付で正しい。送受信そのものは動く。
試して効果がなかったこと:
- /C2 応答の中身: 13桁ms / 10桁sec / int64・int32 の2進 / ID / ID\tsec / sec\tID / ID\tsec\tms / sec\tms → 日付は変わらない
  (10桁sec単独・2進・空応答は「送信できませんでした」になり、日付は仮の正しい値のまま。13桁以上の数字かタブ入りは成功扱い+日付が壊れる)
- /C2 応答の先頭 int32(秒, 0, 1, 2001基準秒, 要求と同値) → 変化なし
- SEND_MESSAGE(OpType 25, reqSeq=要求の番号バイト)を即時 / 1.5秒遅れで返す → 即時のときだけ「一瞬だけ正しい日付」になり、その後 12/20 に戻る(遅延は効果なし)
- 数字を秒・ms・µs・32bit切り詰め等で読み違えた場合の日付を計算 → 12/20(火)・12/25 とは一致せず
仮説(未検証): 成功扱いの応答を処理した後で、アプリが別の値(HTTP の Date ヘッダ、サーバー時刻のずれ補正値など)から日付を計算し直している。
アプリ内の関連メソッド: messageSent:withRequestSequence:inContext:, updateMessageSendTime:(int)messageObj:inContext:, updateMessageTimestamp:message: (armv7 imp 0x25511d / 0x254995 / 0x2547e5, llvm-objdump --macho --arch=armv7 で確認可)
次の手: 上記メソッドの逆アセンブル、/C2 応答の HTTP ヘッダ(Date 等)の変更実験

## 解決: 返信がアプリを閉じないと届かない (2026-11-07, v0.34)
- 原因: fetchOperations(/P3 /P4)を、新着がなければ4秒で空返しにしていた。iOS は空の返事のあと約100秒待ってから再確認するため、返信が次の確認まで届かなかった(確認のたびに数通まとめて届く形で観測)。Windows も確認の合間に入った新着は次回まで待たされた
- 対策: 新着が来るまで待たせるロングポーリングにして、来た瞬間に返す(iOS 25秒 / Windows 20秒。環境変数 LINE_HOLD_IOS / LINE_HOLD_WIN)。両方で解消を確認
- 制約: iOS アプリが背景に回っている間(notifySleep 後)は確認自体をやめるため届かない。実機はプッシュ通知で起こしている(未対応)

## 解決: 画像の送受信 (2026-11-08, v0.37〜v0.40)
- **Windows 送信の流れ**: sendMessage(contentType=1, 本文は数字のプレースホルダ, metadata 空)→ サーバーが返したメッセージIDを oid として `POST /talk/m/upload.nhn`(multipart。フィールド `params` に JSON {name, oid, size, type(image|video), ver})。保存名は oid=メッセージID
- **iOS 受信**: `GET /os/m/<oid>/preview` と `GET /os/m/<oid>`(HTTP/80)。Windows は `/os/m/<oid>/preview`, `/os/m/<oid>`, `/talk/m/object_info.nhn`(未実装, 404)
- sendMessage の応答で contentType(15)・contentMetadata(18) を落とすと、クライアントが「文字メッセージ」扱いにして画像アップロードが始まらない(Windows に数字だけ表示される原因)。要求値をそのまま履歴・応答に残す
- **iOS 送信が止まっていた原因**: iPod が自己署名証明書を信頼していなかった(Safari で https を開くと「続行」警告)。通常の Thrift 通信は NSURLConnection で、最初の接続が CERTIFICATE_UNKNOWN で落ち、アプリが警告を自動続行して再接続するため気づかなかった。画像アップロードは ASIHTTPRequest で、続行できずそのまま失敗(`SNI=os.line.naver.jp` の接続だけが失敗していた)
- 対処: 古いプロファイルを削除し、`http://<サーバーIP>/ca.crt` から証明書を入れ直す → 画像が表示された
- 効果がなかったこと: os.line.naver.jp 専用の証明書(CN一致)、os.line.naver.jp だけ TLS1.0+AES-SHA にする(v0.39/v0.40 に残してあるが不要。LINE_OS_TLS=default で通常に戻せる)
- 診断: v0.38 以降、TLS 接続ごとに `[tls ] SNI=...` を表示する
- 教訓: 「Safari で警告が出ない」確認は `https://` を明示しないと HTTP になり無意味。コンソールの `:443` 接続の有無で確認する
