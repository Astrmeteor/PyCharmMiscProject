# -*- coding: utf-8 -*-
# sm9_trace_demo.py
# 说明：这是一个“可视化/逐步跟踪（trace）版”的演示脚本。
# 依赖你现有的 sm9_algorithm.py（你刚发的那份）已经可以正常 import。
# 运行：python sm9_trace_demo.py
#
# 功能：
#  - 统一打印工具：把函数的输入/输出以 hex 与 binary（可截断）打印
#  - 关键算法的逐步跟踪（KDF/H/MAC/配对/签名/验签/加解密/盲签-追踪）
#  - 提供 TRACE_LEVEL 细粒度开关
#
# 注意：
#  - 本脚本不修改你原文件，只是“调用+打印”。若要“把打印嵌入到每个 def”，
#    可把这里的打印方法和子类直接复制到你的文件中，替换原有方法即可。

import os
from math import ceil

# === 直接从你现有模块导入 ===
from function.sm9_algorithm import (
    q, N, N_SIZE, HASH_SIZE, KEY_LEN, K2_len, hlen,
    P1, P2, fast_kG, get_kP_list, e, e_fast,
    KDF as KDF_orig, H as H_orig, MAC as MAC_orig,
    SM9, BKGC, BDO, BDEP, BDU, ECC_Point, FQ2, FQ, FQ12
)

# =========================
# 可视化/打印工具
# =========================

TRACE_LEVEL = 2  # 0=静默, 1=关键, 2=详细
SHOW_BIN = True
BIN_MAX = 256        # 打印二进制时最多显示的bit数
HEX_MAX_BYTES = 64   # 打印hex时最多显示的字节数

# 按模块独立开关
TRACE_KDF = True
TRACE_H = True
TRACE_MAC = True
TRACE_PAIRING = True
TRACE_SIGN = True
TRACE_VERIFY = True
TRACE_ENC = True
TRACE_DEC = True
TRACE_ENCAPS = True
TRACE_DECAPS = True
TRACE_BLIND_FLOW = True   # BKGC/BDO/BDEP/BDU 全流程

def _clip_hex(b: bytes, max_bytes=HEX_MAX_BYTES) -> str:
    if not isinstance(b, (bytes, bytearray)):
        return str(b)
    if len(b) <= max_bytes:
        return b.hex()
    return (b[:max_bytes].hex() + f"...(+{len(b)-max_bytes} bytes)")

def _to_bytes(x) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, int):
        size = max(1, (x.bit_length() + 7) // 8)
        return x.to_bytes(size, "big")
    if isinstance(x, ECC_Point):
        return bytes(x)
    if isinstance(x, FQ12):
        return bytes(x)  # 你原文件实现了 __bytes__（归一/序列化）
    if isinstance(x, FQ2):
        return bytes(x)
    if isinstance(x, FQ):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    # 兜底
    try:
        return bytes(x)
    except Exception:
        return str(x).encode("utf-8")

def _to_bin(x) -> str:
    b = _to_bytes(x)
    s = "".join(f"{byte:08b}" for byte in b)
    if len(s) <= BIN_MAX:
        return s
    return s[:BIN_MAX] + f"...(+{len(s)-BIN_MAX} bits)"

def _fmt_int(i: int, name: str = None) -> str:
    if not isinstance(i, int):
        return str(i)
    return f"{name or 'int'}(bits={i.bit_length()}): 0x{i:x}"

def _fmt_bytes(b: bytes, name: str = None) -> str:
    b = _to_bytes(b)
    res = f"{name or 'bytes'}(len={len(b)}): 0x{_clip_hex(b)}"
    if SHOW_BIN:
        res += f"\n    bin: { _to_bin(b) }"
    return res

def _fmt_point(P: ECC_Point, name: str = "P") -> str:
    if not isinstance(P, ECC_Point):
        return str(P)
    x, y = P.normalize()
    def _hex_FQ(v):
        if isinstance(v, FQ):
            return f"0x{int(v.n % q):x}"
        if isinstance(v, FQ2):
            fp_list = v.get_fp_list()  # 高位在前
            return "(" + ", ".join(f"0x{ii:x}" for ii in fp_list) + ")"
        return str(v)
    return (f"{name} (on G{'1' if isinstance(x, FQ) else '2'})\n"
            f"    x = {_hex_FQ(x)}\n"
            f"    y = {_hex_FQ(y)}\n"
            f"    bytes = 0x{_clip_hex(bytes(P))}")

def _hdr(title: str):
    print("\n" + "=" * 20 + f" {title} " + "=" * 20)

def _kv(key: str, val):
    if isinstance(val, ECC_Point):
        print(_fmt_point(val, key))
    elif isinstance(val, int):
        print(_fmt_int(val, key))
    else:
        print(_fmt_bytes(val, key))

def _section(title: str, **kwargs):
    if TRACE_LEVEL == 0:
        return
    _hdr(title)
    for k, v in kwargs.items():
        _kv(k, v)

# =========================
# 跟踪版 KDF/H/MAC/配对
# =========================

def KDF(Z: bytes, klen_bits: int):
    if TRACE_KDF and TRACE_LEVEL >= 2:
        _section("KDF(Input)", Z=Z, klen_bits=klen_bits)
    out = KDF_orig(Z, klen_bits)
    if TRACE_KDF and TRACE_LEVEL >= 2:
        _section("KDF(Output)", K=out)
    return out

def H(i: int, Z: bytes):
    if TRACE_H and TRACE_LEVEL >= 2:
        _section("H(Input)", i=i, Z=Z)
    out = H_orig(i, Z)
    if TRACE_H and TRACE_LEVEL >= 2:
        _section("H(Output)", H_val=out)
    return out

def MAC(K2: bytes, Z: bytes):
    if TRACE_MAC and TRACE_LEVEL >= 2:
        _section("MAC(Input)", K2=K2, Z=Z)
    out = MAC_orig(K2, Z)
    if TRACE_MAC and TRACE_LEVEL >= 2:
        _section("MAC(Output)", mac=out)
    return out

def pairing(P: ECC_Point, Q: ECC_Point):
    # 外层简单打印（配对内部步骤很多，这里展示入参与最终结果）
    if TRACE_PAIRING and TRACE_LEVEL >= 1:
        _section("Pairing e(P,Q) Input", P=P, Q=Q)
    out = e(P, Q)
    if TRACE_PAIRING and TRACE_LEVEL >= 1:
        _section("Pairing e(P,Q) Output", ePQ=bytes(out))
    return out

# =========================
# 跟踪版 SM9：重写方法加入日志
# =========================

class SM9Trace(SM9):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # 维持你原来的初始化
        if TRACE_LEVEL >= 1:
            _section("SM9.Init", ID=self.ID_byte, hid_s=self.hid_s_byte, hid_e=self.hid_e_byte)
            if hasattr(self, "ks"):
                _section("SM9.Init(KGC-sign)", ks=self.ks, Ppub_s=self.Ppub_s)
            if hasattr(self, "ke"):
                _section("SM9.Init(KGC-enc)", ke=self.ke, Ppub_e=self.Ppub_e)
            if hasattr(self, "k_ds_list"):
                _section("SM9.Init(User sign)", ds_table_size=len(self.k_ds_list))
            if hasattr(self, "de_a_list"):
                _section("SM9.Init(User enc)", de_a_list_len=len(self.de_a_list))

    # 6.2 签名（加入逐步打印）
    def sign(self, M, r=None, outbytes=True):
        if TRACE_SIGN and TRACE_LEVEL >= 1:
            _section("Sign.Input", M=M, r=r, outbytes=outbytes)
        l = 0
        it = 0
        while l == 0:
            it += 1
            r = r if r else os.urandom(N_SIZE)
            if isinstance(r, (bytes, bytearray)):
                rr = int.from_bytes(r, "big") % N
                rr = rr or 1
            else:
                rr = r
            if TRACE_SIGN and TRACE_LEVEL >= 2:
                _section(f"Sign.Step[{it}] r", r=rr)
            w = bytes(self.gs_pow(rr))  # A3
            if TRACE_SIGN and TRACE_LEVEL >= 2:
                _section("Sign.Step w=bytes(gs^r)", w=w)
            h = H(2, (M if isinstance(M, (bytes, bytearray)) else str(M).encode()) + w)  # A4
            l = (rr - h) % N  # A5
            if TRACE_SIGN and TRACE_LEVEL >= 2:
                _section("Sign.Step h,l", h=h, l=l)
            r = rr
        S = fast_kG(l, self.k_ds_list)  # A6
        out = ( (h, S) if not outbytes else (h.to_bytes(N_SIZE, "big") + bytes(S)) )
        if TRACE_SIGN and TRACE_LEVEL >= 1:
            if outbytes:
                _section("Sign.Output(bytes)", h=h, S=S, sig=out)
            else:
                _section("Sign.Output(tuple)", h=h, S=S)
        return out

    # 6.4 验签
    def verify(self, ID, M_, sig):
        if TRACE_VERIFY and TRACE_LEVEL >= 1:
            _section("Verify.Input", ID=ID, M=M_, sig=sig)
        if isinstance(sig, (bytes, bytearray)):
            h_ = int.from_bytes(sig[:N_SIZE], "big")
            S_ = ECC_Point.from_byte(sig[N_SIZE:])
        else:
            h_, S_ = sig
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.ParseSig", h=h_, S=S_)

        if not 0 < h_ < N or not S_ or not S_.is_on_curve():
            if TRACE_VERIFY:
                _section("Verify.Fail", reason="h not in (0,N) or S invalid/on-curve check failed")
            return False

        t = self.gs_pow(h_)  # e(P1, Ppub_s)^h
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.Step t=gs^h", t=bytes(t))
        h1 = H(1, (ID if isinstance(ID, (bytes, bytearray)) else str(ID).encode()) + self.hid_s_byte)
        P = fast_kG(h1, get_kP_list(P2)) + self.Ppub_s  # Q_ID + Ppub_s
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.Step h1,P", h1=h1, P=P)

        u = pairing(S_, P)  # e(S_, P)
        w_ = bytes(u * t)   # e(S_,P) * e(P1,Ppub_s)^h
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.Step u,w'", u=bytes(u), w_=w_)
        h2 = H(2, (M_ if isinstance(M_, (bytes, bytearray)) else str(M_).encode()) + w_)
        ok = (h_ == h2)
        if TRACE_VERIFY:
            _section("Verify.Output", h2=h2, result=ok)
        return ok

    # 8.2/8.4 密钥封装 & 解封装（打印）
    def encaps(self, IDB, klen, r=None, outbytes=True):
        if TRACE_ENCAPS and TRACE_LEVEL >= 1:
            _section("Encaps.Input", IDB=IDB, klen=klen, r=r, outbytes=outbytes)
        K, C = super().encaps(IDB, klen, r, outbytes)
        if TRACE_ENCAPS and TRACE_LEVEL >= 1:
            _section("Encaps.Output", K=K, C=C)
        return K, C

    def decaps(self, C, klen):
        if TRACE_DECAPS and TRACE_LEVEL >= 1:
            _section("Decaps.Input", C=C, klen=klen)
        ok, K = super().decaps(C, klen)
        if TRACE_DECAPS and TRACE_LEVEL >= 1:
            _section("Decaps.Output", ok=1 if ok else 0, K=K if ok else b"")
        return ok, K

    # 9.2/9.4 加密 & 解密（打印）
    def encrypt(self, IDB, M, r=None, outbytes=True):
        if TRACE_ENC and TRACE_LEVEL >= 1:
            _section("Encrypt.Input", IDB=IDB, M=M, r=r, outbytes=outbytes)
        C = super().encrypt(IDB, M, r, outbytes)
        if TRACE_ENC and TRACE_LEVEL >= 1:
            C1, C3, C2 = C if not isinstance(C, (bytes, bytearray)) else (C[:N_SIZE<<1], C[N_SIZE<<1:(N_SIZE<<1)+HASH_SIZE], C[(N_SIZE<<1)+HASH_SIZE:])
            _section("Encrypt.Output", C1=C1, C3=C3, C2=C2)
        return C

    def decrypt(self, C):
        if TRACE_DEC and TRACE_LEVEL >= 1:
            _section("Decrypt.Input", C=C)
        ok, M = super().decrypt(C)
        if TRACE_DEC and TRACE_LEVEL >= 1:
            _section("Decrypt.Output", ok=1 if ok else 0, M=M if ok else b"")
        return ok, M


# =========================
# 盲签/追踪流程：带打印
# =========================

class BKGCTrace(BKGC):
    def params(self):
        p = super().params()
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BKGC.Params", P1=p.P1, P2=p.P2, Ppub_s=p.Ppub_s, version=p.version)
        return p

    def enroll(self, ID: str):
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BKGC.Enroll.Input", ID=ID)
        keys = super().enroll(ID)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BKGC.Enroll.Output", Q_ID=keys.Q_ID, d_ID=keys.d_ID, T=keys.T, A_open=keys.A_open)
        return keys

    def verify_order(self, order_hash: bytes, pay_proof: bytes):
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BKGC.VerifyOrder.Input", order_hash=order_hash, pay_proof=pay_proof)
        tk = super().verify_order(order_hash, pay_proof)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BKGC.VerifyOrder.Output", ticket=tk)
        return tk

class BDOTrace(BDO):
    def blind(self, M: bytes):
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDO.Blind.Input", M=M)
        M_, B = super().blind(M)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDO.Blind.Output", M_prime=M_, B=B)
        return M_, B

    def sign_blinded(self, M_: bytes):
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDO.SignBlinded.Input", M_prime=M_)
        R, S, T = super().sign_blinded(M_)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDO.SignBlinded.Output", R=R, S=S, T=T)
        return R, S, T

    def release_r_inv(self, approve_ticket: bytes) -> int:
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDO.Release_r_inv.Input", ticket=approve_ticket)
        r_inv = super().release_r_inv(approve_ticket)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDO.Release_r_inv.Output", r_inv=r_inv)
        return r_inv

class BDEPTrace(BDEP):
    def verify_blinded(self, ID: str, Q_ID: ECC_Point, M_prime: bytes, sig):
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDEP.VerifyBlinded.Input", ID=ID, Q_ID=Q_ID, M_prime=M_prime)
        ok = super().verify_blinded(ID, Q_ID, M_prime, sig)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDEP.VerifyBlinded.Output", result=1 if ok else 0)
        return ok

class BDUTrace(BDU):
    def unblind_and_verify(self, ID: str, Q_ID: ECC_Point, M_prime: bytes, B: ECC_Point, r_inv: int, sig):
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDU.UnblindAndVerify.Input", ID=ID, Q_ID=Q_ID, M_prime=M_prime, B=B, r_inv=r_inv)
        pub_ok, resp_ok, M = super().unblind_and_verify(ID, Q_ID, M_prime, B, r_inv, sig)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDU.UnblindAndVerify.Output", pub_ok=1 if pub_ok else 0, resp_ok=1 if resp_ok else 0, M=M)
        return pub_ok, resp_ok, M

    def verify_opening(self, Q_ID: ECC_Point, T: ECC_Point, A_open: ECC_Point) -> bool:
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDU.VerifyOpening.Input", Q_ID=Q_ID, T=T, A_open=A_open)
        ok = super().verify_opening(Q_ID, T, A_open)
        if TRACE_BLIND_FLOW and TRACE_LEVEL >= 1:
            _section("BDU.VerifyOpening.Output", result=1 if ok else 0)
        return ok


# =========================
# 演示：签名/验签 + 加密/解密 + 盲签全流程
# =========================
def demo_sign_verify():
    _hdr("DEMO: Sign / Verify")
    # KGC：生成主密钥并下发给用户
    alice = SM9Trace(ID="Alice", ks=-1, ke=-1)  # ks/ke=-1 表示随机；只用签名部分即可
    user = alice.KGC_gen_user("Bob")
    # 用户侧：拿到 ds、Ppub_s 等参数
    bob = SM9Trace(ID="Bob", ds=user.k_ds_list and fast_kG(1, user.k_ds_list), Ppub_s=user.Ppub_s)

    M = b"hello-sm9-sign"
    sig = bob.sign(M, outbytes=True)
    ok = bob.verify("Bob", M, sig)
    print(f"\n[Verify Result] {ok}\n")

def demo_encrypt_decrypt():
    _hdr("DEMO: Encrypt / Decrypt")
    kgc = SM9Trace(ID="KGC", ke=-1)
    user = kgc.KGC_gen_user("Carol")

    # 🔧 修正处：保存 de, Ppub_e
    de, Ppub_e = getattr(user, "de", None), getattr(user, "Ppub_e", None)
    carol = SM9Trace(ID="Carol", de=de, Ppub_e=Ppub_e)

    plaintext = b"hello-sm9-encrypt"
    cipher = kgc.encrypt("Carol", plaintext, outbytes=True)

    ok, recovered = carol.decrypt(cipher)
    print(f"\n[Decrypt Result] ok={ok}, M={recovered}\n")

def demo_blind_trace():
    _hdr("DEMO: Blind Sign / Trace / Unblind")
    # 1) KGC（带追踪和审核）
    kgc = BKGCTrace()
    params = kgc.params()
    # 2) 注册用户
    keys = kgc.enroll("diana")
    # 3) 签名提供方（BDO）
    bdo = BDOTrace(params, keys, kgc)
    # 4) 平台（验盲签 + 发票据）
    dep = BDEPTrace(params, kgc)
    # 5) 用户（去盲方）
    bdu = BDUTrace(params)

    M = b"blind-message"
    # A) 盲化
    M_prime, B = bdo.blind(M)
    # B) BDO 对 M' 盲签
    R, S, T = bdo.sign_blinded(M_prime)
    # C) 平台验盲签并发票据
    ok = dep.verify_blinded(keys.ID, keys.Q_ID, M_prime, (R, S, T))
    assert ok, "平台验盲签失败"
    ticket = dep.verify_order(b"order#123", b"pay#ok")
    # D) 门控释放 r^{-1}
    r_inv = bdo.release_r_inv(ticket)
    # E) 去盲并验证、恢复 M
    pub_ok, resp_ok, M_out = bdu.unblind_and_verify(keys.ID, keys.Q_ID, M_prime, B, r_inv, (R, S, T))
    print(f"\n[Unblind Result] pub_ok={pub_ok}, resp_ok={resp_ok}, M={M_out}")
    # F) 打开验证（trace）
    A_open, _ = kgc.open_trace(keys.ID)
    opened = bdu.verify_opening(keys.Q_ID, T, A_open)
    print(f"[Open Trace] {opened}\n")


if __name__ == "__main__":
    # 你可以按需注释/启用下面几个 demo
    demo_sign_verify()
    demo_encrypt_decrypt()
    demo_blind_trace()
