#!/usr/bin/env python3
"""cert/ に、このサーバー専用の鍵と証明書を作る(各自で1回だけ実行)。 標準ライブラリだけで動きます。

作るもの:
  cert/server.key / cert/server.crt   HTTPS用の自己署名証明書 (SAN に LINE のホスト名を全部入れる)
  cert/rsa_login.json                 Windows版ログイン用のRSA鍵 (秘密鍵を含む)

鍵は絶対に公開・共有しないこと。server.crt を端末に入れると、その端末は
この鍵の持ち主が作る「LINE のふりをした HTTPS」を信頼してしまう。
RSA2048 の素数探索を純Pythonで行うので、数秒〜1分ほどかかります。
"""
import base64, datetime, hashlib, json, os, secrets, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "cert")
HOSTS = """gw.line.naver.jp gd2.line.naver.jp gd.line.naver.jp line.naver.jp ndrive1.naver.com os.line.naver.jp
myhome.line.naver.jp timeline.line.naver.jp dl.profile.line.naver.jp dl.stickershop.line.naver.jp
dl.desktop.line.naver.jp cdn.line-apps.com t.line.naver.jp chgw.line.naver.jp channel.line.naver.jp
cafeapi.line.naver.jp line-web.naver.jp static.naver.jp appnotice.naver.jp lcs.naver.jp
*.line.naver.jp *.naver.jp""".split()


# ---------------------------------------------------------------- RSA
def is_prime(n, rounds=40):
    if n < 4: return n in (2, 3)
    if n % 2 == 0: return False
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0: return n == p
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: break
        else:
            return False
    return True


def gen_prime(bits, e):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if (p - 1) % e != 0 and is_prime(p): return p


def gen_rsa(bits=2048, e=65537):
    while True:
        p, q = gen_prime(bits // 2, e), gen_prime(bits // 2, e)
        if p == q: continue
        n = p * q
        if n.bit_length() != bits: continue
        if p < q: p, q = q, p
        d = pow(e, -1, (p - 1) * (q - 1))           # Python 3.8 以降
        return {"n": n, "e": e, "d": d, "p": p, "q": q}


# ---------------------------------------------------------------- DER
def der(tag, content): 
    n = len(content)
    if n < 128: ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big"); ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def d_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")      # 先頭ビットが立たないよう 1 バイト余裕
    return der(0x02, b)


def d_seq(*items): return der(0x30, b"".join(items))
def d_oid(s):
    a = [int(x) for x in s.split(".")]; out = bytes([40 * a[0] + a[1]])
    for x in a[2:]:
        t = [x & 0x7F]; x >>= 7
        while x: t.append(0x80 | (x & 0x7F)); x >>= 7
        out += bytes(reversed(t))
    return der(0x06, out)
def d_null(): return der(0x05, b"")
def d_utf8(s): return der(0x0C, s.encode())
def d_bitstr(b): return der(0x03, b"\0" + b)
def d_octets(b): return der(0x04, b)
def d_bool(v): return der(0x01, b"\xff" if v else b"\x00")
def d_utc(dt): return der(0x17, dt.strftime("%y%m%d%H%M%S").encode() + b"Z")


def pem(label, data):
    b = base64.b64encode(data).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(b[i:i + 64] for i in range(0, len(b), 64)), label)


def main():
    if os.path.exists(os.path.join(OUT, "server.key")) and "--force" not in sys.argv:
        sys.exit("cert/server.key が既にあります。作り直すなら --force (端末側の証明書も入れ直しが必要)")
    os.makedirs(OUT, exist_ok=True)
    print("HTTPS 用の鍵を作っています(数秒〜1分)...")
    k = gen_rsa()
    n, e, d, p, q = k["n"], k["e"], k["d"], k["p"], k["q"]

    # 秘密鍵 (PKCS#1)
    priv = d_seq(d_int(0), d_int(n), d_int(e), d_int(d), d_int(p), d_int(q),
                 d_int(d % (p - 1)), d_int(d % (q - 1)), d_int(pow(q, -1, p)))
    with open(os.path.join(OUT, "server.key"), "w") as f: f.write(pem("RSA PRIVATE KEY", priv))

    # 証明書
    sha256_rsa = d_seq(d_oid("1.2.840.113549.1.1.11"), d_null())
    name = d_seq(der(0x31, d_seq(d_oid("2.5.4.3"), d_utf8("gw.line.naver.jp"))))
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    validity = d_seq(d_utc(now - datetime.timedelta(days=1)), d_utc(now + datetime.timedelta(days=3650)))
    spki = d_seq(d_seq(d_oid("1.2.840.113549.1.1.1"), d_null()), d_bitstr(d_seq(d_int(n), d_int(e))))
    san = d_seq(d_oid("2.5.29.17"), d_octets(d_seq(*[der(0x82, h.encode()) for h in HOSTS])))
    bc = d_seq(d_oid("2.5.29.19"), d_bool(True), d_octets(d_seq(d_bool(True))))       # CA:TRUE (iOS にプロファイルとして入れるため)
    exts = der(0xA3, d_seq(san, bc))
    tbs = d_seq(der(0xA0, d_int(2)), d_int(secrets.randbits(63) + 1), sha256_rsa, name, validity, name, spki, exts)
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")                  # SHA-256 の DigestInfo
    em = b"\x00\x01" + b"\xff" * (256 - 3 - len(prefix) - 32) + b"\x00" + prefix + hashlib.sha256(tbs).digest()
    sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(256, "big")
    crt = d_seq(tbs, sha256_rsa, d_bitstr(sig))
    with open(os.path.join(OUT, "server.crt"), "w") as f: f.write(pem("CERTIFICATE", crt))

    # ログイン(Windows版)用 RSA 鍵
    print("ログイン用の鍵を作っています...")
    r = gen_rsa()
    with open(os.path.join(OUT, "rsa_login.json"), "w") as f:
        json.dump({"keynm": "1000001", "n": "%x" % r["n"], "e": "%x" % r["e"], "d": "%x" % r["d"]}, f)
    print("作りました:", OUT)
    print("  server.crt を iOS に入れる場合は、サーバー起動後に http://<サーバーのIP>/ca.crt を Safari で開く")


if __name__ == "__main__":
    main()
