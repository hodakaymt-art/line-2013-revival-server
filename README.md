# LINE 2013 revival server

2013年ごろの古い LINE クライアント(**Windows 3.1.7.10 / iOS 2.5.0**)を、公式サーバーなしで動かすための、LINE 互換の**検証用サーバー**です。Python 標準ライブラリだけで動きます(証明書作成のみ `cryptography` が必要)。

> 非公式の個人プロジェクトです。LINE Corporation / NAVER とは無関係で、LINE のバイナリ・アプリ・画像などは一切含みません。古いクライアントは、各自が正規の手段で入手したものを使ってください。

## できること

| | Windows 3.1.7.10 | iOS 2.5.0 (iOS 5.1.1 で確認) |
|---|---|---|
| ログイン / 登録 | メール+パスワード(何でも通る) | 電話番号+認証コード(何でも通る) |
| 友だち追加(ID検索) | ○ | ○ |
| テキスト送受信 | ○ | ○ |
| スタンプ | ○ | ○ |
| 画像 | ○ | ○ |
| Echo Bot(ID: `echo`) | ○ | ○ |
| 既読・リアルタイム配信 | ○(ロングポーリング) | ○(アプリを開いている間) |

未対応 / 既知の問題: グループ、動画・位置情報などの画像以外のメッセージ、プッシュ通知(iOS がバックグラウンドの間は届かない)、iOS から送ったメッセージの日付表示がずれる、再起動時の一部の通知が失われる。

## ⚠ 安全に関する注意(必ず読む)

- **認証はありません。** どんなメールアドレス・パスワード・認証コードでもログインできます。**LAN 内だけで使い、インターネットに公開しないでください**(ポート開放・公開サーバー禁止)。
- **本物の LINE のアカウント・電話番号・パスワードは入力しないでください。** ダミーの値を使ってください。サーバーはデバッグのため通信内容を `logs/` に保存します。
- `make_cert.py` が作る `cert/server.key` と `cert/rsa_login.json` は**秘密鍵**です。公開・共有しないでください(`.gitignore` で除外済み)。`server.crt` を端末に入れると、その端末は鍵の持ち主が作る「LINE のふりをした HTTPS」を信頼します。検証用の端末だけに入れ、不要になったら削除してください。
- `data/`(アカウント・会話・アップロード画像)と `logs/` も公開しないでください。

## 使い方

1. Python 3.8 以降を用意します(Windows 7 は 3.8 系)。
2. 鍵と証明書を作ります(1回だけ):
   ```
   pip install cryptography
   python make_cert.py
   ```
3. クライアント端末の hosts で、次のホスト名を**サーバーを動かす PC の IP** に向けます。
   ```
   gw.line.naver.jp gd2.line.naver.jp gd.line.naver.jp line.naver.jp os.line.naver.jp t.line.naver.jp
   chgw.line.naver.jp channel.line.naver.jp cafeapi.line.naver.jp line-web.naver.jp static.naver.jp
   appnotice.naver.jp lcs.naver.jp myhome.line.naver.jp timeline.line.naver.jp ndrive1.naver.com
   dl.profile.line.naver.jp dl.stickershop.line.naver.jp dl.desktop.line.naver.jp cdn.line-apps.com
   ```
   (Windows は `C:\Windows\System32\drivers\etc\hosts`、脱獄した iOS は `/etc/hosts`。)
4. サーバーを起動します(80 / 443 を使うので管理者権限が必要):
   ```
   python line_server.py
   ```
5. **iOS のみ**: iPod / iPhone の Safari で `http://<サーバーのIP>/ca.crt` を開き、証明書(プロファイル)をインストールします。入れたあと、Safari で `https://gw.line.naver.jp/` を開き、**警告なしで**開けることを確認してください(警告が出る状態だと、画像アップロードなどが黙って失敗します)。
6. クライアントを起動してログインします。友だち追加は、相手がログインに使った ID(メールの `@` より前、または電話番号)で検索します。

Windows の「アップデートが必要」ダイアログは、`dl.desktop.line.naver.jp` / `cdn.line-apps.com` をサーバーに向けると、サーバーが「最新は 3.1.7.10」と答えて回避します。**更新は実行しないでください**(公式の新しい版で上書きされます)。

## 環境変数

| 変数 | 意味 |
|---|---|
| `LINE_HTTP_PORT` / `LINE_HTTPS_PORT` | 待ち受けポート(既定 80 / 443) |
| `LINE_HOLD_IOS` / `LINE_HOLD_WIN` | 新着を待つ時間(秒、ロングポーリング。既定 25 / 20) |
| `LINE_VERIFY_RESULT` | iOS の認証コード検証の返り値(既定 1) |
| `LINE_C2_MODE` | iOS の `/C2` 応答形式の実験用(既定 1。通常は触らない) |

## 仕組みのメモ

`docs/` に、解析で分かったプロトコルの詳細があります(Thrift Compact / Binary、登録フロー、友だち追加、画像のアップロード、証明書まわりの落とし穴など)。

## ファイル

- `line_server.py` — サーバー本体(1ファイル)
- `make_cert.py` — 鍵・証明書の生成
- `docs/` — 調査メモ
