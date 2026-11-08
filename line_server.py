#!/usr/bin/env python3
"""
LINE 3.1.7.10 (2013, Windows) revival - request logger / stub server  v0.1

  - HTTP(:80) と HTTPS(:443) の両方で待ち受け
  - 全リクエスト(メソッド/パス/ヘッダ/ボディ)を logs/ に保存
  - ボディを Thrift Compact としてデコードし、フィールドIDつきで表示
  - 応答は「空の結果構造体」を返すだけ(クライアントがどこまで進むか観察用)

標準ライブラリのみ。Python 3.8+ (Windows 7 なら 3.8.x)。
使い方は README.md を参照。
"""
import os, sys, ssl, json, time, threading, struct, warnings
warnings.filterwarnings("ignore")
try: sys.stdout.reconfigure(line_buffering=True)
except Exception: pass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(HERE, "logs")
os.makedirs(LOGDIR, exist_ok=True)
_lock = threading.Lock()
_counter = [0]

# ---------------------------------------------------------------- Thrift Compact
T_NAMES = {1: "bool", 2: "bool", 3: "byte", 4: "i16", 5: "i32", 6: "i64",
           7: "double", 8: "binary", 9: "list", 10: "set", 11: "map", 12: "struct"}
MSG_TYPES = {1: "CALL", 2: "REPLY", 3: "EXCEPTION", 4: "ONEWAY"}


class R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def byte(self):
        v = self.b[self.i]; self.i += 1; return v

    def take(self, n):
        v = self.b[self.i:self.i + n]
        if len(v) != n: raise ValueError("eof")
        self.i += n; return v

    def varint(self):
        r = s = 0
        while True:
            c = self.byte(); r |= (c & 0x7F) << s
            if not c & 0x80: return r
            s += 7

    def zz(self):
        n = self.varint(); return (n >> 1) ^ -(n & 1)


def rd_value(r, t, depth=0):
    if depth > 40: raise ValueError("too deep")
    if t == 1: return True
    if t == 2: return False
    if t == 3: return struct.unpack("b", r.take(1))[0]
    if t in (4, 5, 6): return r.zz()
    if t == 7: return struct.unpack("<d", r.take(8))[0]
    if t == 8:
        raw = r.take(r.varint())
        try:
            return raw.decode("utf-8")      # 全角スペース等も含め、正しいUTF-8なら文字列として扱う
        except Exception:
            pass
        return "0x" + raw.hex()
    if t in (9, 10):
        h = r.byte(); n = h >> 4; et = h & 0xF
        if n == 15: n = r.varint()
        out = []
        for _ in range(n):
            if et in (1, 2): out.append(bool(r.byte() == 1))   # bool in list = 1 byte
            else: out.append(rd_value(r, et, depth + 1))
        return {"_": T_NAMES.get(et, et) + "[]", "items": out}
    if t == 11:
        n = r.varint()
        if n == 0: return {"_": "map", "items": []}
        kv = r.byte(); kt, vt = kv >> 4, kv & 0xF
        items = []
        for _ in range(n):
            k = r.byte() == 1 if kt in (1, 2) else rd_value(r, kt, depth + 1)
            v = r.byte() == 1 if vt in (1, 2) else rd_value(r, vt, depth + 1)
            items.append([k, v])
        return {"_": "map<%s,%s>" % (T_NAMES.get(kt, kt), T_NAMES.get(vt, vt)), "items": items}
    if t == 12: return rd_struct(r, depth + 1)
    raise ValueError("bad type %d" % t)


def rd_struct(r, depth=0):
    fields, last = {}, 0
    while True:
        h = r.byte()
        if h == 0: break
        t = h & 0xF; d = h >> 4
        fid = last + d if d else r.zz()
        last = fid
        fields["%d(%s)" % (fid, T_NAMES.get(t, t))] = rd_value(r, t, depth)
    return fields


def decode_compact_message(body):
    r = R(body)
    if r.byte() != 0x82: raise ValueError("not compact (0x82 expected)")
    vt = r.byte(); ver = vt & 0x1F; mt = vt >> 5
    seq = r.varint(); name = r.take(r.varint()).decode("utf-8", "replace")
    args = rd_struct(r)
    return {"name": name, "type": MSG_TYPES.get(mt, mt), "ver": ver, "seq": seq,
            "args": args, "trailing": len(body) - r.i}


# --- encoder (for replies) ---
def _vi(n):
    out = bytearray()
    while True:
        if n < 0x80: out.append(n); return bytes(out)
        out.append((n & 0x7F) | 0x80); n >>= 7


def reply_empty(name, seq):
    """REPLY message whose result struct is empty ( = void success )."""
    nb = name.encode()
    return bytes([0x82, (2 << 5) | 1]) + _vi(seq) + _vi(len(nb)) + nb + b"\x00"



# ---------------------------------------------------------------- Thrift Compact encoder
def _zz(n, bits=64): return ((n << 1) ^ (n >> (bits - 1))) & ((1 << bits) - 1)


def _enc_val(t, v):
    if t == "str":
        b = v.encode() if isinstance(v, str) else v
        return _vi(len(b)) + b
    if t == "i32": return _vi(_zz(v, 32))
    if t == "i64": return _vi(_zz(v, 64))
    if t == "struct": return enc_struct(v)
    if t == "map":
        kt, vt, items = v
        code = {"str": 8, "i32": 5, "i64": 6, "struct": 12}
        if not items: return b"\x00"
        return _vi(len(items)) + bytes([(code[kt] << 4) | code[vt]]) + b"".join(
            _enc_val(kt, k) + _enc_val(vt, x) for k, x in items)
    if t == "list":
        et, items = v
        code = {"str": 8, "i32": 5, "i64": 6, "struct": 12}[et]
        n = len(items)
        h = bytes([(n << 4) | code]) if n < 15 else bytes([0xF0 | code]) + _vi(n)
        return h + b"".join(_enc_val(et, x) for x in items)
    raise ValueError(t)


_CT = {"bool": 1, "i32": 5, "i64": 6, "str": 8, "list": 9, "map": 11, "struct": 12}


def enc_struct(fields):
    """fields: [(field_id, type, value), ...]  type: str/i32/i64/bool/list/struct"""
    out, last = bytearray(), 0
    for fid, t, v in sorted(fields, key=lambda f: f[0]):
        ct = _CT[t] if t != "bool" else (1 if v else 2)
        d = fid - last
        if 0 < d <= 15: out.append((d << 4) | ct)
        else: out.append(ct); out += _vi(_zz(fid, 16))
        last = fid
        if t != "bool": out += _enc_val(t, v)
    out.append(0)
    return bytes(out)


def reply_msg(name, seq, result_fields):
    nb = name.encode()
    return bytes([0x82, (2 << 5) | 1]) + _vi(seq) + _vi(len(nb)) + nb + enc_struct(result_fields)



# ---------------------------------------------------------------- Thrift Binary protocol (iOS版 2.x が使用)
BT_NAMES = {2: "bool", 3: "byte", 4: "double", 6: "i16", 8: "i32", 10: "i64", 11: "binary",
            12: "struct", 13: "map", 14: "set", 15: "list"}


def _bstr(raw):
    try: return raw.decode("utf-8")
    except Exception: return "0x" + raw.hex()


def b_value(r, t, depth=0):
    if depth > 40: raise ValueError("too deep")
    if t == 2: return r.byte() != 0
    if t == 3: return struct.unpack(">b", r.take(1))[0]
    if t == 4: return struct.unpack(">d", r.take(8))[0]
    if t == 6: return struct.unpack(">h", r.take(2))[0]
    if t == 8: return struct.unpack(">i", r.take(4))[0]
    if t == 10: return struct.unpack(">q", r.take(8))[0]
    if t == 11:
        n = struct.unpack(">i", r.take(4))[0]
        return _bstr(r.take(n))
    if t == 12: return b_struct(r, depth + 1)
    if t == 13:
        kt, vt = r.byte(), r.byte(); n = struct.unpack(">i", r.take(4))[0]
        items = [[b_value(r, kt, depth + 1), b_value(r, vt, depth + 1)] for _ in range(n)]
        return {"_": "map<%s,%s>" % (BT_NAMES.get(kt, kt), BT_NAMES.get(vt, vt)), "items": items}
    if t in (14, 15):
        et = r.byte(); n = struct.unpack(">i", r.take(4))[0]
        return {"_": BT_NAMES.get(et, et) + "[]", "items": [b_value(r, et, depth + 1) for _ in range(n)]}
    raise ValueError("bad binary type %d" % t)


def b_struct(r, depth=0):
    fields = {}
    while True:
        t = r.byte()
        if t == 0: break
        fid = struct.unpack(">h", r.take(2))[0]
        fields["%d(%s)" % (fid, BT_NAMES.get(t, t))] = b_value(r, t, depth)
    return fields


def decode_binary_message(body):
    r = R(body)
    w = struct.unpack(">i", r.take(4))[0]
    if w < 0:                                   # strict: 0x8001 | type
        if (w & 0xFFFF0000) != 0x80010000: raise ValueError("bad binary version")
        mt = w & 0xFF
        name = _bstr(r.take(struct.unpack(">i", r.take(4))[0]))
    else:                                       # non-strict: name length first
        name = _bstr(r.take(w)); mt = r.byte()
    seq = struct.unpack(">i", r.take(4))[0]
    args = b_struct(r)
    return {"name": name, "type": MSG_TYPES.get(mt, mt), "ver": 1, "seq": seq, "args": args,
            "trailing": len(body) - r.i, "proto": "binary"}


_BC = {"bool": 2, "i32": 8, "i64": 10, "str": 11, "struct": 12, "map": 13, "list": 15}


def _benc_val(t, v):
    if t == "bool": return b"\x01" if v else b"\x00"
    if t == "i32": return struct.pack(">i", v)
    if t == "i64": return struct.pack(">q", v)
    if t == "str":
        b = v.encode() if isinstance(v, str) else v
        return struct.pack(">i", len(b)) + b
    if t == "struct": return enc_struct_bin(v)
    if t == "list":
        et, items = v
        return bytes([_BC[et]]) + struct.pack(">i", len(items)) + b"".join(_benc_val(et, x) for x in items)
    if t == "map":
        kt, vt, items = v
        return bytes([_BC[kt], _BC[vt]]) + struct.pack(">i", len(items)) + b"".join(
            _benc_val(kt, k) + _benc_val(vt, x) for k, x in items)
    raise ValueError(t)


def enc_struct_bin(fields):
    out = bytearray()
    for fid, t, v in sorted(fields, key=lambda f: f[0]):
        out.append(_BC[t]); out += struct.pack(">h", fid); out += _benc_val(t, v)
    out.append(0)
    return bytes(out)


def reply_msg_bin(name, seq, result_fields):
    nb = name.encode()
    return struct.pack(">I", 0x80010002) + struct.pack(">i", len(nb)) + nb + struct.pack(">i", seq) + enc_struct_bin(result_fields)


def decode_message(body):
    """先頭バイトで Compact(0x82) / Binary(0x80 または 長さ) を判別"""
    if body[:1] == b"\x82":
        m = decode_compact_message(body); m["proto"] = "compact"; return m
    return decode_binary_message(body)


# ---------------------------------------------------------------- RSA login
_RSA = json.load(open(os.path.join(HERE, "cert", "rsa_login.json")))
_SESSIONS = {}   # session_key -> True  (最後に配布したもの)


def rsa_decrypt_credential(hexstr):
    n, d = int(_RSA["n"], 16), int(_RSA["d"], 16)
    x = pow(int(hexstr, 16), d, n).to_bytes(256, "big")
    if x[0] != 0 or x[1] != 2: raise ValueError("bad padding")
    pl = x[x.index(b"\0", 2) + 1:]
    parts, p = [], 0
    while p < len(pl):
        L = pl[p]; parts.append(pl[p + 1:p + 1 + L].decode("utf-8", "replace")); p += 1 + L
    return parts   # [session_key, email, password]


import hashlib, base64


def mid_for(email): return "u" + hashlib.md5(("line-revival:" + email).encode()).hexdigest()


def h_login(args, hdrs):
    try:
        sk, email, pw = rsa_decrypt_credential(args["4(binary)"])
    except Exception as e:
        print("   login: decrypt failed:", e)
        return []
    mid = mid_for(email)
    _ACCOUNTS[mid] = email
    save_state()
    token = mid + ":" + base64.b64encode(os.urandom(24)).decode()
    print("   login: email=%s pw_len=%d -> mid=%s  (全アカウントを受理する検証モード)" % (email, len(pw), mid))
    cert = args.get("9(binary)") or hashlib.sha256(mid.encode()).hexdigest()
    # LoginResult: 1 authToken, 2 certificate, 5 type(1=SUCCESS)   ※フィールドIDは推測。ログで検証する
    return [(0, "struct", [(1, "str", token), (2, "str", cert), (5, "i32", 1)])]


HANDLERS = {
    "loginWithIdentityCredentialForCertificate": h_login,
    "loginWithIdentityCredential": h_login,
}



# ---------------------------------------------------------------- 起動時に呼ばれる基本メソッド
_ACCOUNTS = {}   # mid -> email


def _me(hdrs):
    tok = hdrs.get("X-Line-Access") or ""
    mid = tok.split(":")[0]
    return mid, _ACCOUNTS.get(mid, "user@example.com")


def h_server_time(args, hdrs): return [(0, "i64", int(time.time() * 1000))]
def h_last_rev(args, hdrs):
    me, _ = _me(hdrs)
    return [(0, "i64", max(REV.get(me, 0), REV_BASE))]


def h_profile(args, hdrs):
    mid, email = _me(hdrs)
    name = uid_of(email) or "user"
    # Profile: 1 mid, 3 userid, 11 email, 12 regionCode, 20 displayName, 22 pictureStatus, 24 statusMessage
    return [(0, "struct", [(1, "str", mid), (3, "str", name), (11, "str", email),
                           (12, "str", "JP"), (20, "str", NAMES.get(mid) or name), (24, "str", "")])]


def h_empty_strlist(args, hdrs): return [(0, "list", ("str", []))]
def h_empty_structlist(args, hdrs): return [(0, "list", ("struct", []))]


def h_fetch_ops(args, hdrs):
    time.sleep(10)          # ロングポーリング(新着なし)
    return [(0, "list", ("struct", []))]


def h_wrapup(args, hdrs):
    # TMessageBoxWrapUpResponse: 1 messageBoxWrapUpList, 2 totalSize
    return [(0, "struct", [(1, "list", ("struct", [])), (2, "i32", 0)])]


def h_login_wrap(args, hdrs):
    r = h_login(args, hdrs)
    return r


for _n in ("getAllContactIds", "getBlockedContactIds", "getGroupIdsJoined", "getGroupIdsInvited",
           "getHiddenContactMids", "getFavoriteMids", "getRecommendationIds",
           "getBlockedRecommendationIds", "getBuddyBlockerIds", "getActiveBuddySubscriberIds"):
    HANDLERS[_n] = h_empty_strlist
for _n in ("getContacts", "getGroups", "getCompactContactsModifiedSince", "getActivePurchaseVersions",
           "getActivePurchases", "getMessageBoxCompactWrapUpList_"):
    HANDLERS[_n] = h_empty_structlist
HANDLERS.update({
    "getServerTime": h_server_time,
    "getLastOpRevision": h_last_rev,
    "getProfile": h_profile,
    "fetchOperations": h_fetch_ops,
    "fetchOps": h_fetch_ops,
    "getMessageBoxCompactWrapUpList": h_wrapup,
    "getMessageBoxWrapUpList": h_wrapup,
})



# ---------------------------------------------------------------- 友だち・トーク (v0.9)
import threading as _th
BOT_MID = "u" + "ec" * 16
BOT = {"email": "echo@bot", "userid": "echo", "name": "Echo Bot"}
FRIENDS = {}                 # mid -> [friend mids]
OPS = {}                     # mid -> [operation dict]
REV = {}                     # mid -> last revision
_cv = _th.Condition()
OP_RECEIVE_MESSAGE, OP_SEND_MESSAGE = 26, 25


STATE_FILE = os.path.join(HERE, "data", "state.json")
os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
REV_BASE = int(time.time())          # 再起動しても単調増加するリビジョン基準


def save_state():
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"accounts": _ACCOUNTS, "friends": FRIENDS,
                       "hist": {"%s|%s" % k: v for k, v in HIST.items()}}, f, ensure_ascii=False)
    except Exception as e:
        print("[state] save failed:", e)


def load_state():
    try:
        d = json.load(open(STATE_FILE, encoding="utf-8"))
    except Exception:
        return
    _ACCOUNTS.update(d.get("accounts", {})); FRIENDS.update(d.get("friends", {}))
    for k, v in d.get("hist", {}).items():
        a, b = k.split("|", 1)
        for m in v:
            if not str(m.get("id", "")).isdigit(): m["id"] = new_msg_id()
        HIST[(a, b)] = v
    print("[state] loaded: %d accounts, %d friend lists, %d chats" % (len(_ACCOUNTS), len(FRIENDS), len(HIST)))


def A(args, fid, default=None):
    """field id で引数を取り出す (型表記に依存しない)"""
    pre = "%d(" % fid
    for k, v in args.items():
        if k.startswith(pre): return v
    return default


NAMES = {}      # mid -> 表示名 (updateProfileAttribute で設定)


def uid_of(em):
    return em.split(":", 1)[1] if em.startswith("phone:") else em.split("@")[0]


def account(mid):
    if mid == BOT_MID: return BOT
    em = _ACCOUNTS.get(mid)
    if em: return {"email": em, "userid": uid_of(em), "name": NAMES.get(mid) or uid_of(em)}
    return None


def find_by_userid(uid):
    uid = (uid or "").lower()
    if uid == BOT["userid"]: return BOT_MID
    for mid, em in _ACCOUNTS.items():
        if uid_of(em).lower() == uid or em.lower() == uid: return mid
    return None


def contact_fields(mid, me=None):
    a = account(mid) or {"name": "?", "userid": ""}
    rel = 1 if (me and mid in FRIENDS.get(me, [])) else 0     # 1 = FRIEND(推測)
    return [(1, "str", mid), (2, "i64", int(time.time() * 1000)), (10, "i32", 1), (11, "i32", 1),
            (21, "i32", rel), (22, "str", a["name"]), (23, "str", ""), (24, "str", ""), (25, "str", ""),
            (26, "str", ""), (27, "str", ""), (28, "i64", 0),
            (31, "bool", True), (32, "bool", True), (33, "bool", True), (34, "bool", False),
            (35, "i32", 0), (36, "i64", 0)]


def talk_exception(code, reason):
    # TalkException: 1 code, 2 reason  (result の field 1)
    return [(1, "struct", [(1, "i32", code), (2, "str", reason)])]


def push_op(mid, typ, **kw):
    with _cv:
        REV[mid] = max(REV.get(mid, 0), REV_BASE) + 1
        op = {"rev": REV[mid], "type": typ, "time": int(time.time() * 1000)}; op.update(kw)
        OPS.setdefault(mid, []).append(op); _cv.notify_all()


_idc = [0]


def new_msg_id():
    _idc[0] += 1
    return "%d" % (int(time.time() * 1000) * 1000 + _idc[0] % 1000)


def msg_fields(m):
    f = [(1, "str", m["from"]), (2, "str", m["to"]), (3, "i32", 0), (4, "str", m["id"]),
         (5, "i64", m["time"]), (6, "i64", m["time"]), (10, "str", m.get("text", "")),
         (14, "bool", bool(m.get("ctype", 0))), (15, "i32", m.get("ctype", 0)),
         (18, "map", ("str", "str", [(k, v) for k, v in (m.get("meta") or {}).items()]))]
    return f


def h_find_by_userid(args, hdrs):
    me, _ = _me(hdrs)
    mid = find_by_userid(A(args, 2) or A(args, 1))
    if not mid: return talk_exception(5, "NOT_FOUND")
    return [(0, "struct", contact_fields(mid, me))]


def h_find_and_add(args, hdrs):
    me, _ = _me(hdrs)
    key = A(args, 2)
    mid = key if account(key or "") else find_by_userid(key)
    if not mid: return talk_exception(5, "NOT_FOUND")
    FRIENDS.setdefault(me, [])
    if mid not in FRIENDS[me]: FRIENDS[me].append(mid)
    print("   friend added:", account(mid)["name"], mid)
    if (hdrs.get("X-Line-Application") or "").startswith("IOS"):
        push_op(me, 4, param1=mid)                   # ADD_CONTACT: iOS 版は追加完了をこの操作でも受け取る(推測)
        print("   -> ADD_CONTACT op queued for iOS")
    if mid != BOT_MID and mid in _ACCOUNTS:          # 相手が人間なら相互に友だち化して通知
        FRIENDS.setdefault(mid, [])
        if me not in FRIENDS[mid]:
            FRIENDS[mid].append(me)
            push_op(mid, 5, param1=me)               # NOTIFIED_ADD_CONTACT
    save_state()
    return [(0, "map", ("str", "struct", [(mid, contact_fields(mid, me))]))]


def h_all_contacts(args, hdrs):
    me, _ = _me(hdrs)
    return [(0, "list", ("str", list(FRIENDS.get(me, []))))]


def h_get_contacts(args, hdrs):
    me, _ = _me(hdrs)
    lst = A(args, 2) or A(args, 1) or {"items": []}
    mids = lst["items"] if isinstance(lst, dict) else []
    return [(0, "list", ("struct", [contact_fields(m, me) for m in mids if account(m)]))]


def h_get_contact(args, hdrs):
    me, _ = _me(hdrs)
    m = A(args, 2) or A(args, 1)
    if not account(m or ""): return talk_exception(5, "NOT_FOUND")
    return [(0, "struct", contact_fields(m, me))]


HIST = {}   # (me, other) -> [message dict]  古い順


def record(me, other, m):
    HIST.setdefault((me, other), []).append(m)
    save_state()


def h_recent(args, hdrs):
    me, _ = _me(hdrs)
    box = A(args, 2) or A(args, 1) or ""
    cnt = A(args, 3) or A(args, 2) or 20
    cnt = cnt if isinstance(cnt, int) else 20
    msgs = HIST.get((me, box), [])[-max(cnt, 1):]
    return [(0, "list", ("struct", [msg_fields(m) for m in reversed(msgs)]))]   # 新しい順


def h_send_message(args, hdrs):
    me, _ = _me(hdrs)
    seq = A(args, 1, 0); m = A(args, 2) or {}
    to = None; text = ""; ctype = 0; meta = {}
    for k, v in m.items():
        if k.startswith("2("): to = v
        if k.startswith("10("): text = v
        if k.startswith("15("): ctype = v if isinstance(v, int) else 0
        if k.startswith("18("):
            try:
                for it in (v.get("items") or []):
                    if isinstance(it, dict): meta.update({str(a): str(b) for a, b in it.items()})
                    elif isinstance(it, (list, tuple)) and len(it) == 2: meta[str(it[0])] = str(it[1])
            except Exception: pass
    now = int(time.time() * 1000)
    mid_s = new_msg_id()
    sent = {"from": me, "to": to or "", "id": mid_s, "time": now, "text": text}
    if ctype: sent["ctype"] = ctype; sent["meta"] = meta; print("   [メッセージ種別 contentType=%d metadata=%r]" % (ctype, meta))
    print("   message %s -> %s : %r" % (account(me)["name"] if account(me) else me, to, text))
    record(me, to or "", sent)
    if to and to != BOT_MID and to in _ACCOUNTS and to != me:      # 人間同士
        FRIENDS.setdefault(to, [])
        if me not in FRIENDS[to]:
            FRIENDS[to].append(me); push_op(to, 5, param1=me)
        record(to, me, sent)                                         # 受信者側の履歴
        push_op(to, OP_RECEIVE_MESSAGE, msg=sent)
        print("   delivered to", account(to)["name"])
    if to == BOT_MID:
        rep = {"from": BOT_MID, "to": me, "id": new_msg_id(), "time": now + 1, "text": "echo: " + (text if not ctype else "(contentType=%d)" % ctype)}
        record(me, BOT_MID, rep)
        push_op(me, OP_RECEIVE_MESSAGE, msg=rep)
    return [(0, "struct", msg_fields(sent))]


def h_fetch_ops(args, hdrs):
    me, _ = _me(hdrs)
    rev = next((v for k, v in args.items() if k.endswith("(i64)")), 0) or 0   # 現在のリビジョン(i64)を型で探す
    # ロングポーリング: 新着が来るまで待たせ、来た瞬間に返す。空で返すと iOS は約100秒待ってしまう
    is_ios = (hdrs.get("X-Line-Application") or "").startswith("IOS")
    hold = float(os.environ.get("LINE_HOLD_IOS" if is_ios else "LINE_HOLD_WIN", "25" if is_ios else "20"))
    deadline = time.time() + hold
    with _cv:
        while True:
            new = [o for o in OPS.get(me, []) if o["rev"] > rev]
            if new or time.time() >= deadline: break
            _cv.wait(1.0)
    out = []
    for o in new[:50]:
        f = [(1, "i64", o["rev"]), (2, "i64", o["time"]), (3, "i32", o["type"]), (4, "i32", o.get("reqseq", 0))]
        if "param1" in o:
            f += [(10, "str", o["param1"])]
        if "msg" in o:
            f += [(10, "str", o["msg"]["id"]), (11, "str", o["msg"]["to"]), (20, "struct", msg_fields(o["msg"]))]
        out.append(f)
    return [(0, "list", ("struct", out))]



# ---------------------------------------------------------------- 画像などのオブジェクト置き場 (OBS: os.line.naver.jp)
OBS_DIR = os.path.join(HERE, "data", "obs"); os.makedirs(OBS_DIR, exist_ok=True)


def _qs(path):
    from urllib.parse import urlparse, parse_qs
    return {k: v[0] for k, v in parse_qs(urlparse(path).query).items()}


def obs_parse(body, ctype):
    """multipart/form-data なら (フィールド辞書, ファイルbytes) を返す。そうでなければ ({}, body)"""
    if "multipart" in (ctype or "").lower() and "boundary=" in ctype:
        bd = ("--" + ctype.split("boundary=")[1].split(";")[0].strip().strip('"')).encode()
        fields, data = {}, None
        for part in body.split(bd):
            if b"\r\n\r\n" not in part: continue
            head, _, val = part.partition(b"\r\n\r\n")
            val = val[:-2] if val.endswith(b"\r\n") else val
            h = head.decode("latin1", "replace")
            import re as _re
            nm = _re.search(r'name="([^"]*)"', h)
            if "filename=" in h or (data is None and nm and nm.group(1) in ("file", "upload", "image")): data = val
            elif nm: fields[nm.group(1)] = val.decode("utf-8", "replace")
        return fields, data if data is not None else b""
    return {}, body


def h_obs_upload(self, n, body):
    q = _qs(self.path); f, data = obs_parse(body, self.headers.get("Content-Type", ""))
    oid = q.get("oid") or f.get("oid") or ""
    try:                                   # Windows 版は multipart の params フィールドに JSON で oid(=メッセージID)を入れてくる
        pj = json.loads(f.get("params", "{}")); oid = oid or str(pj.get("oid", ""))
        print("   [OBS params]", {k: (str(v)[:60]) for k, v in pj.items()})
    except Exception: pass
    seg = [x for x in self.path.split("?")[0].split("/") if x]
    if not oid and "m" in seg and seg.index("m") + 1 < len(seg) and seg[-1] != "upload.nhn": oid = seg[seg.index("m") + 1]
    if not oid or oid == "reqseq":
        oid = f.get("oid") or self.headers.get("X-Obs-Oid") or ("obj%d" % n)
    oid = "".join(c for c in oid if c.isalnum() or c in "-_.")[:80] or ("obj%d" % n)
    with open(os.path.join(OBS_DIR, oid), "wb") as fh: fh.write(data)
    print("   [OBS 保存] oid=%s %d bytes fields=%r query=%r" % (oid, len(data), {k: v[:40] for k, v in f.items()}, q))
    print("   [OBS 要求ヘッダ]", {k: v[:60] for k, v in self.headers.items() if k.lower() not in ("host", "content-length")})
    return oid


def obs_download_path(self):
    q = _qs(self.path); seg = [x for x in self.path.split("?")[0].split("/") if x]
    if seg and seg[-1] in ("preview", "thumb"): seg = seg[:-1]
    oid = q.get("oid") or (seg[-1] if seg else "")
    oid = "".join(c for c in oid if c.isalnum() or c in "-_.")
    fp = os.path.join(OBS_DIR, oid)
    return open(fp, "rb").read() if oid and os.path.exists(fp) else None


# ---------------------------------------------------------------- iOS 2.5.0 のメッセージ送信 (/C2: Thrift ではない独自フレーム)
# 要求: 01 | int32(0x20) | byte(番号) | int32(長さ) | "<宛先mid>\t<本文>"     ※ログから解析。応答は推測
C2_COUNT = [0]


def h_c2(body, hdrs):
    import struct as _st
    ver, cmd, typ, ln = body[0], _st.unpack(">i", body[1:5])[0], body[5], _st.unpack(">i", body[6:10])[0]
    payload = body[10:10 + ln].decode("utf-8", "replace")
    to, _, text = payload.partition("\t")
    print("   /C2 送信: ver=%d cmd=0x%x no=%d to=%s text=%r" % (ver, cmd, typ, to, text))
    r = h_send_message({"1(i32)": 0, "2(struct)": {"2(binary)": to, "10(binary)": text}}, hdrs)
    msg_id = next((v for fid, t, v in r[0][2] if fid == 4), "0")
    if (hdrs.get("X-Line-Application") or "").startswith("IOS") and os.environ.get("LINE_SEND_OP", "1") == "1":
        me, _ = _me(hdrs)
        for h in [x for x in HIST.get((me, to), []) if x.get("from") == me][-1:]:     # いま記録した自分の送信メッセージ
            delay = float(os.environ.get("LINE_SEND_OP_DELAY", "1.5"))     # /C2 応答の処理が終わった後に届けて日付を最終確定させる
            _th.Timer(delay, push_op, args=(me, OP_SEND_MESSAGE), kwargs={"msg": h, "reqseq": typ}).start()
            print("   -> SEND_MESSAGE 操作を %.1f 秒後に送り主へ返す (reqSeq=%d, 時刻=%s)" % (delay, typ, time.strftime("%m/%d %H:%M:%S", time.localtime(h["time"] / 1000))))
    ts = next((v for fid, t, v in r[0][2] if fid == 5), int(time.time() * 1000))
    # 応答の中身(推測)。LINE_C2_MODE=auto なら送信ごとに形を変えて、どれが正しいか実機で調べる
    sec = ts // 1000
    variants = {
        "1": ("ms(ASCII)", str(ts).encode()),
        "2": ("empty", b""),
        "3": ("0x01", b"\x01"),
        "4": ("id", str(msg_id).encode()),
        "5": ("id<TAB>ms", ("%s\t%s" % (msg_id, ts)).encode()),
        "6": ("sec(ASCII)", str(sec).encode()),
        "7": ("int64 ms BE", _st.pack(">q", ts)),
        "8": ("int64 sec BE", _st.pack(">q", sec)),
        "9": ("int32 sec BE", _st.pack(">i", sec)),
        "10": ("id<TAB>sec", ("%s\t%s" % (msg_id, sec)).encode()),
        "11": ("sec<TAB>id", ("%s\t%s" % (sec, msg_id)).encode()),
        "12": ("id<TAB>sec<TAB>ms", ("%s\t%s\t%s" % (msg_id, sec, ts)).encode()),
        "13": ("sec<TAB>ms", ("%s\t%s" % (sec, ts)).encode()),
        # 以下は「フレーム先頭のint32」に時刻などを入れる実験(中身はIDのみ)
        "14": ("hdr=sec", str(msg_id).encode()),
        "15": ("hdr=0", str(msg_id).encode()),
        "16": ("hdr=1", str(msg_id).encode()),
        "17": ("hdr=リクエストと同じ(対照)", str(msg_id).encode()),
        "18": ("hdr=sec-2001基準", str(msg_id).encode()),
    }
    hdr_vals = {"14": sec, "15": 0, "16": 1, "18": sec - 978307200}
    mode = os.environ.get("LINE_C2_MODE", "1")
    if mode == "auto":
        C2_COUNT[0] += 1
        mode = ["14", "15", "16", "18", "17", "14"][(C2_COUNT[0] - 1) % 6]
    label, pay = variants.get(mode, variants["1"])
    print("   /C2 応答 [形 %s: %s] 時刻=%s" % (mode, label, time.strftime("%m/%d %H:%M:%S", time.localtime(sec))))
    if mode == "2": return b""
    if mode == "3": return b"\x01"
    h = hdr_vals.get(mode, cmd)
    return bytes([ver]) + _st.pack(">i", h) + bytes([typ]) + _st.pack(">i", len(pay)) + pay


def h_empty_struct(args, hdrs): return [(0, "struct", [])]


HANDLERS.update({
    "findContactByUserid": h_find_by_userid,
    "findAndAddContactsByUserid": h_find_and_add,
    "findAndAddContactsByMid": h_find_and_add,
    "getAllContactIds": h_all_contacts,
    "getContacts": h_get_contacts,
    "getContact": h_get_contact,
    "sendMessage": h_send_message,
    "fetchOperations": h_fetch_ops,
    "fetchOps": h_fetch_ops,
    "getRecentMessages": h_recent,
    "getPreviousMessages": h_recent,
    "getNextMessages": h_recent,
    "getMessagesBySequenceNumber": h_recent,
    "updateSettingsAttributes": h_empty_struct,
    "updateSettings": h_empty_struct,
    "getSettingsAttributes": h_empty_struct,
    "getSettings": h_empty_struct,
    "getActivePurchaseVersions": h_empty_struct,
    "getDownloads": h_empty_struct,
    "getActivePurchases": h_empty_struct,
})



# ---------------------------------------------------------------- iOS版: 電話番号による登録 (推測実装。ログで検証する)
VERIF = {}   # sessionId -> {"phone","region"}


def h_start_verification(args, hdrs):
    region = A(args, 2) or "JP"; phone = A(args, 4) or ""
    sid = os.urandom(8).hex()
    VERIF[sid] = {"phone": phone, "region": region}
    print("   startVerification: region=%s phone=%s -> session %s  (認証コードは何を入れても通ります)" % (region, phone, sid))
    # VerificationSessionData: 1 sessionId, 2 method(1=SMS), 3 callback, 4 normalizedPhone, 5 countryCode,
    #                          6 nationalSignificantNumber, 7 availableVerificationMethods, 8 callerIdMask
    return [(0, "struct", [(1, "str", sid), (2, "i32", 1), (3, "str", ""), (4, "str", phone),
                           (5, "str", "81"), (6, "str", phone.lstrip("0")),
                           (7, "list", ("i32", [1])), (8, "str", "")])]


HANDLERS["startVerification"] = h_start_verification



def _vsess(args):
    sid = A(args, 2) or ""
    return VERIF.setdefault(sid, {"phone": "", "region": "JP"}), sid


def h_verify_phone(args, hdrs):
    v, sid = _vsess(args)
    print("   verifyPhone: session=%s pin=%s -> OK (どのPINも受理)" % (sid, A(args, 3)))
    # アプリ内の型情報: VerifyPhone_result の success は i32 (Ti)。値の意味は推測(環境変数で変更可)
    val = int(os.environ.get("LINE_VERIFY_RESULT", "1"))
    return [(0, "i32", val)]


def _register(args, hdrs, name):
    v, sid = _vsess(args)
    ident = "phone:" + (v.get("phone") or sid)
    mid = mid_for(ident)
    _ACCOUNTS[mid] = ident
    save_state()
    token = mid + ":" + base64.b64encode(os.urandom(24)).decode()
    print("   %s: session=%s -> mid=%s" % (name, sid, mid))
    return [(0, "str", token)]    # 戻り値=authToken(推測)


HANDLERS["verifyPhone"] = h_verify_phone
HANDLERS["registerDevice"] = lambda a, h: _register(a, h, "registerDevice")
HANDLERS["registerDeviceWithoutPhoneNumber"] = lambda a, h: _register(a, h, "registerDeviceWithoutPhoneNumber")
HANDLERS["registerDeviceWithIdentityCredential"] = lambda a, h: _register(a, h, "registerDeviceWithIdentityCredential")



def h_change_method(args, hdrs):
    v, sid = _vsess(args)
    m = A(args, 3) or 1
    phone = v.get("phone", "")
    print("   changeVerificationMethod: session=%s method=%s" % (sid, m))
    return [(0, "struct", [(1, "str", sid), (2, "i32", m), (3, "str", ""), (4, "str", phone),
                           (5, "str", "81"), (6, "str", phone.lstrip("0")),
                           (7, "list", ("i32", [1, 2])), (8, "str", "")])]


HANDLERS["changeVerificationMethod"] = h_change_method



# ---------------------------------------------------------------- iOS 起動時の初期化呼び出し
def _empty_list(args, hdrs): return [(0, "list", ("str", []))]


HANDLERS["getPromotedBuddyContacts"] = _empty_list
HANDLERS["getNewlyReleasedBuddyIds"] = _empty_list
def h_update_profile_attr(args, hdrs):
    mid, _ = _me(hdrs)
    if A(args, 2) == 2 and A(args, 3): NAMES[mid] = A(args, 3); print("   表示名:", NAMES[mid])
    return []


HANDLERS["updateProfileAttribute"] = h_update_profile_attr
for _n in ("updateSettings", "updateProfileAttribute", "updateSettingsAttribute", "updateNotificationTokenWithBytes",
           "updateNotificationToken"):
    HANDLERS.setdefault(_n, lambda a, h: [])      # 戻り値なし(void)


def dispatch(msg, hdrs):
    h = HANDLERS.get(msg["name"])
    if msg["name"] not in ("getServerTime", "fetchOperations", "loginWithIdentityCredentialForCertificate"):
        print("   args:", json.dumps(msg["args"], ensure_ascii=False)[:700], "" if h else " (未実装→空応答)")
    fields = h(msg["args"], hdrs) if h else []
    if msg.get("proto") == "binary":
        return reply_msg_bin(msg["name"], msg["seq"], fields)
    return reply_msg(msg["name"], msg["seq"], fields)


# ---------------------------------------------------------------- HTTP handler
def hexdump(b, n=256):
    b = b[:n]
    return " ".join("%02x" % c for c in b)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"

    def log_message(self, *a): pass

    def _handle(self):
        ln = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(ln) if ln else b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0: self.rfile.readline(); break
                body += self.rfile.read(size); self.rfile.readline()
        with _lock:
            _counter[0] += 1; n = _counter[0]
        scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
        rec = {"n": n, "time": time.strftime("%H:%M:%S"), "scheme": scheme,
               "method": self.command, "path": self.path,
               "headers": dict(self.headers.items()), "body_len": len(body)}
        reply = b"{}"; ctype = "application/json"
        if self.path.startswith("/authct/v1/keys"):
            kj = json.load(open(os.path.join(HERE, "cert", "rsa_login.json")))
            sk = "%08x" % int.from_bytes(os.urandom(4), "big")
            out = json.dumps({"session_key": sk, "rsa_key": "%s,%s,%s" % (kj["keynm"], kj["n"], kj["e"])}).encode()
            rec["note"] = "authct keys -> session_key=" + sk
            with _lock:
                with open(os.path.join(LOGDIR, "requests.log"), "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, indent=2) + "\n")
            print("#%d %s %s %s  -> RSA key reply (session_key=%s)" % (n, scheme, self.command, self.path, sk))
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=UTF-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers(); self.wfile.write(out); return
        if self.path.split("?")[0] in ("/ca.crt", "/ca.cer") and self.command == "GET":
            # iOS 端末に証明書を入れるための配布口 (Safari で開く)
            crt = open(os.path.join(HERE, "cert", "server.crt"), "rb").read()
            print("#%d %s GET %s  -> certificate download" % (n, scheme, self.path))
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Length", str(len(crt)))
            self.end_headers(); self.wfile.write(crt); return
        if self.command == "GET" and (self.path.startswith("/app/terms") or self.path.startswith("/app/authhelp")
                                       or self.path.startswith("/app/iphone/help") or self.path.startswith("/cs/")):
            page = ("<html><head><meta name='viewport' content='width=device-width'><meta charset='utf-8'></head>"
                    "<body style='font-family:sans-serif;padding:12px'><h3>LINE 2013 revival</h3>"
                    "<p>This is a private revival server for testing.</p></body></html>").encode()
            print("#%d %s GET %s  -> static page" % (n, scheme, self.path))
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page))); self.end_headers(); self.wfile.write(page); return
        if self.command == "GET" and (self.path.startswith("/notice/") or self.path.startswith("/products/")):
            page = b'{"notices":[],"result":[],"count":0}' if self.path.startswith("/notice/") else b'{}'
            print("#%d %s GET %s  -> empty json" % (n, scheme, self.path))
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(page))); self.end_headers(); self.wfile.write(page); return
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        if "update_remote_info.xml" in self.path or (host == "dl.desktop.line.naver.jp" and self.command == "GET"):
            # 更新チェック: 「最新版 = 手元と同じ 3.1.7.10」と答えてダイアログを抑止する
            reply = (b'<?xml version="1.0" encoding="utf-8"?>\r\n'
                     b'<description appId="Line" version="3.1.7.10" silent="0" force="0" updateLink="">\r\n'
                     b'</description>\r\n')
            ctype = "text/xml"
            rec["note"] = "update check -> answered 3.1.7.10"
        elif host.startswith("os") and host.endswith("line.naver.jp") and self.command in ("POST", "PUT") and body:
            oid = h_obs_upload(self, n, body)
            reply = json.dumps({"objId": oid, "objHash": oid, "result": "ok"}).encode()
            rec["note"] = "OBS upload oid=" + oid
        elif host.startswith("os") and host.endswith("line.naver.jp") and self.command == "GET":
            data = obs_download_path(self)
            print("   [OBS 配信] %s -> %s" % (self.path, ("%d bytes" % len(data)) if data is not None else "なし(404)"))
            if data is None:
                self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data))); self.end_headers()
            if self.command != "HEAD": self.wfile.write(data)
            print("#%d %s GET %s  -> OBS" % (n, scheme, self.path)); return
        elif self.path.startswith("/C2") and body:
            try:
                reply = h_c2(body, self.headers)
                ctype = "application/x-thrift"
                rec["note"] = "/C2 message send"
            except Exception as e:
                rec["c2_error"] = str(e); rec["body_hex"] = hexdump(body)
                print("   /C2 解析失敗:", e)
        elif body:
            try:
                msg = decode_message(body)
                rec["thrift"] = msg
                if msg["type"] == "CALL":
                    reply = dispatch(msg, self.headers)
                    ctype = "application/x-thrift"
            except Exception as e:
                rec["thrift_error"] = str(e)
                rec["body_hex"] = hexdump(body)
        try:
            if rec.get("thrift"):
                rec["reply_hex"] = bytes(reply[:700]).hex()
                rec["reply_decoded"] = decode_message(reply)
        except Exception as e:
            rec["reply_decode_error"] = str(e)
        # 何も起きていない定期確認(新着なしの fetchOperations / notifySleep)は記録しない(ログが巨大になるため)
        noisy = False
        try:
            if rec.get("thrift", {}).get("name") == "fetchOperations":
                noisy = not (rec.get("reply_decoded", {}).get("args", {}).get("0(list)", {}) or {}).get("items")
            elif rec.get("thrift", {}).get("name") == "notifySleep":
                noisy = True
        except Exception:
            pass
        with _lock:
            line = json.dumps(rec, ensure_ascii=False, indent=2)
            if not noisy:
                with open(os.path.join(LOGDIR, "requests.log"), "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            if body:
                with open(os.path.join(LOGDIR, "%04d.bin" % n), "wb") as f: f.write(body)
        t = rec.get("thrift")
        if body and not rec.get("thrift") and "/C2" not in self.path:
            print("   [非Thrift本文] %s %d bytes  Content-Type=%s  Host=%s" % (self.command, len(body), self.headers.get("Content-Type", "?")[:80], self.headers.get("Host", "?")))
        print("#%d %s %s %s%s" % (n, scheme, self.command, self.path,
              ("  -> " + t["name"]) if t else ("  [%d bytes]" % len(body) if body else "")))
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers(); self.wfile.write(reply)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle


OS_CTX = None


def peek_sni(sock):
    """ClientHello を MSG_PEEK で覗いて SNI のホスト名を返す (読み進めない)"""
    import socket as _sk, struct as _st
    try:
        sock.settimeout(5)
        d = b''
        for _ in range(20):
            d = sock.recv(4096, _sk.MSG_PEEK)
            if len(d) >= 5 and len(d) >= 5 + _st.unpack('>H', d[3:5])[0]: break
            time.sleep(0.02)
        if len(d) < 44 or d[0] != 22: return None
        p = 43; p += 1 + d[p]
        p += 2 + _st.unpack('>H', d[p:p+2])[0]; p += 1 + d[p]
        el = _st.unpack('>H', d[p:p+2])[0]; p += 2; end = p + el
        while p + 4 <= end:
            t, l = _st.unpack('>HH', d[p:p+4]); p += 4
            if t == 0: return d[p+5:p+5+_st.unpack('>H', d[p+3:p+5])[0]].decode('ascii', 'replace')
            p += l
    except Exception:
        return None
    return None


def make_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    # os.line.naver.jp 宛て(画像アップロード)だけ、CN がそのホスト名の専用証明書を使う (iOS アプリが CN を厳密に確認している仮説)
    ctx_os = None
    oc, ok = os.path.join(HERE, "cert", "os_leaf.crt"), os.path.join(HERE, "cert", "os_leaf.key")
    if os.path.exists(oc) and os.path.exists(ok):
        try:
            ctx_os = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx_os.load_cert_chain(oc, ok)
            tlsmode = os.environ.get("LINE_OS_TLS", "old")      # old: TLS1.0 + AES-SHA だけ (iOS 5 の CFStream 向け) / default: 通常
            try: ctx_os.minimum_version = ssl.TLSVersion.TLSv1
            except Exception: pass
            if tlsmode == "old":
                try: ctx_os.maximum_version = ssl.TLSVersion.TLSv1
                except Exception: pass
                try: ctx_os.set_ciphers("AES256-SHA:AES128-SHA:@SECLEVEL=0")
                except Exception: pass
            else:
                try: ctx_os.set_ciphers("ALL:@SECLEVEL=0")
                except Exception: pass
        except Exception as e:
            print("[tls ] os 用証明書の読み込み失敗:", e); ctx_os = None

    global OS_CTX
    OS_CTX = ctx_os
    # 2013年のクライアント(OpenSSL 0.9.8h)は TLS1.0 / 古い暗号スイートのみ
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception: pass
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception:
        try: ctx.set_ciphers("ALL")
        except Exception: pass
    return ctx


class Srv(ThreadingHTTPServer):
    """接続ごとにTLSハンドシェイクし、接続・失敗理由をすべて表示する"""
    daemon_threads = True
    ctx = None

    def get_request(self):
        sock, addr = self.socket.accept()
        print("[conn] %s:%d -> :%d %s" % (addr[0], addr[1], self.server_address[1],
              "TLS" if self.ctx else "plain"))
        return sock, addr

    def finish_request(self, request, client_address):
        if self.ctx:
            try:
                request.settimeout(15)
                name = peek_sni(request); use = self.ctx
                if name == "os.line.naver.jp" and OS_CTX is not None: use = OS_CTX
                print("[tls ] SNI=%s%s" % (name, "  -> os 用(専用証明書+旧TLS)" if use is not self.ctx else ""))
                request.settimeout(15)
                request = use.wrap_socket(request, server_side=True)
                print("[tls ] handshake OK  %s %s" % (request.version(), request.cipher()[0]))
            except Exception as e:
                print("[tls ] handshake FAILED: %r" % (e,))
                return
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        print("[err ] %r" % (sys.exc_info()[1],))


def serve(port, ctx=None, host="0.0.0.0"):
    try:
        srv = Srv((host, port), H)
    except OSError as e:
        print("!! :%d を開けません: %s  (他のプログラムが使用中/管理者権限が必要)" % (port, e))
        return
    srv.ctx = ctx
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("listening %s :%d" % ("https" if ctx else "http", port))


if __name__ == "__main__":
    cert = os.path.join(HERE, "cert", "server.crt")
    key = os.path.join(HERE, "cert", "server.key")
    http_port = int(os.environ.get("LINE_HTTP_PORT", 80))
    https_port = int(os.environ.get("LINE_HTTPS_PORT", 443))
    load_state()
    print("== LINE 2013 revival server (Compact + Binary) (update-check reply: ON) ==")
    serve(http_port)
    if os.path.exists(cert): serve(https_port, make_ctx(cert, key))
    else: print("cert/server.crt が無いので HTTPS は無効です (README 参照)")
    print("logs ->", LOGDIR, "\nCtrl+C で終了")
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        pass
