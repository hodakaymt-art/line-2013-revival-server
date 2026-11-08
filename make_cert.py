#!/usr/bin/env python3
"""cert/ に、このサーバー専用の鍵と証明書を作る(各自で1回だけ実行)。

作るもの:
  cert/server.key / cert/server.crt   HTTPS用の自己署名証明書 (SAN に LINE のホスト名を全部入れる)
  cert/rsa_login.json                 Windows版ログイン用のRSA鍵 (秘密鍵を含む)

必要: pip install cryptography
鍵は絶対に公開・共有しないこと。server.crt を端末に入れると、その端末は
この鍵の持ち主が作る「LINE のふりをした HTTPS」を信頼してしまう。
"""
import datetime, json, os, sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("cryptography が必要です:  pip install cryptography")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "cert")
HOSTS = """gw.line.naver.jp gd2.line.naver.jp gd.line.naver.jp line.naver.jp ndrive1.naver.com os.line.naver.jp
myhome.line.naver.jp timeline.line.naver.jp dl.profile.line.naver.jp dl.stickershop.line.naver.jp
dl.desktop.line.naver.jp cdn.line-apps.com t.line.naver.jp chgw.line.naver.jp channel.line.naver.jp
cafeapi.line.naver.jp line-web.naver.jp static.naver.jp appnotice.naver.jp lcs.naver.jp
*.line.naver.jp *.naver.jp""".split()

if os.path.exists(os.path.join(OUT, "server.key")) and "--force" not in sys.argv:
    sys.exit("cert/server.key が既にあります。作り直すなら --force (端末側の証明書も入れ直しが必要)")
os.makedirs(OUT, exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gw.line.naver.jp")])
now = datetime.datetime.now(datetime.timezone.utc)
crt = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
       .serial_number(x509.random_serial_number())
       .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False)
       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)   # iOS にプロファイルとして入れるため
       .sign(key, hashes.SHA256()))
with open(os.path.join(OUT, "server.key"), "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))
with open(os.path.join(OUT, "server.crt"), "wb") as f:
    f.write(crt.public_bytes(serialization.Encoding.PEM))

rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pn = rk.private_numbers()
with open(os.path.join(OUT, "rsa_login.json"), "w") as f:
    json.dump({"keynm": "1000001", "n": "%x" % pn.public_numbers.n, "e": "%x" % pn.public_numbers.e,
               "d": "%x" % pn.d}, f)
print("作りました:", OUT)
print("  server.crt を iOS に入れる場合は、サーバー起動後に http://<サーバーのIP>/ca.crt を Safari で開く")
