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

# 针对每个子模块的开关
TRACE_KDF = True
TRACE_H = True
TRACE_MAC = True
TRACE_PAIRING = True
TRACE_SIGN = True
TRACE_VERIFY = True
TRACE_ENCRYPT = True
TRACE_DECRYPT = True
TRACE_ENCAPS = True
TRACE_DECAPS = True
TRACE_BLIND = True
TRACE_TRACE = True


def _to_bytes(x) -> bytes:
    """尽量把各种对象规范为 bytes，便于统一打印。"""
    if x is None:
        return b"<None>"
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, ECC_Point):
        return bytes(x)  # 你原文件实现了 __bytes__（归一/序列化）
    if isinstance(x, FQ2):
        return bytes(x)
    if isinstance(x, FQ):
        return bytes(x)
    if isinstance(x, FQ12):
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
    return "".join(f"{c:08b}" for c in b)


def _short_hex(x: bytes, max_len=32) -> str:
    h = x.hex()
    if len(h) > max_len:
        return h[:max_len] + "...(%d bytes)" % len(x)
    return h


def _kv(key, value, max_len=48):
    """一行打印 key=value（hex 截断）"""
    b = _to_bytes(value)
    return f"{key}={_short_hex(b, max_len)}"


def _hdr(title: str):
    print("\n" + "=" * 80)
    print("**", title)
    print("=" * 80 + "\n")


def _section(title: str, **kwargs):
    print("\n--- %s ---" % title)
    for k, v in kwargs.items():
        try:
            b = _to_bytes(v)
            print("  - %s: %s" % (k, _short_hex(b)))
        except Exception as e:
            print("  - %s: <print-error: %r>" % (k, e))


# =========================
# 跟踪版 KDF/H/MAC/配对
# =========================

def KDF(Z: bytes, klen_bits: int):
    if TRACE_KDF and TRACE_LEVEL >= 2:
        _section("KDF(Input)", Z=Z, klen_bits=str(klen_bits).encode())
    out = KDF_orig(Z, klen_bits)
    if TRACE_KDF and TRACE_LEVEL >= 2:
        _section("KDF(Output)", K=out)
    return out


def H(i: int, Z: bytes):
    if TRACE_H and TRACE_LEVEL >= 2:
        _section("H(Input)", i=str(i).encode(), Z=Z)
    out = H_orig(i, Z)
    if TRACE_H and TRACE_LEVEL >= 2:
        _section("H(Output)", h=out.to_bytes(hlen, "big"))
    return out


def MAC(K: bytes, M: bytes, t: int = HASH_SIZE):
    if TRACE_MAC and TRACE_LEVEL >= 2:
        _section("MAC(Input)", K=K, M=M, t=str(t).encode())
    out = MAC_orig(K, M, t)
    if TRACE_MAC and TRACE_LEVEL >= 2:
        _section("MAC(Output)", mac=out)
    return out


def pairing(P, Q):
    if TRACE_PAIRING and TRACE_LEVEL >= 2:
        _section("Pairing(Input)", P=_to_bytes(P), Q=_to_bytes(Q))
    out = e_fast(P, Q)
    if TRACE_PAIRING and TRACE_LEVEL >= 2:
        _section("Pairing(Output)", value=bytes(out))
    return out


# =========================
# SM9Trace：对 SM9 类做“打印增强”
# =========================

class SM9Trace(SM9):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # 维持你原来的初始化
        if TRACE_LEVEL >= 1:
            _section("SM9.Init", ID=self.ID_byte, hid_s=self.hid_s_byte, hid_e=self.hid_e_byte)
            if hasattr(self, "ks"):
                _section("SM9.Init(KGC-sign)", ks=str(self.ks).encode(), Ppub_s=_to_bytes(self.Ppub_s))
            if hasattr(self, "ke"):
                _section("SM9.Init(KGC-enc)", ke=str(self.ke).encode(), Ppub_e=_to_bytes(self.Ppub_e))
            if hasattr(self, "k_ds_list"):
                _section("SM9.Init(User sign)", ds_table_size=str(len(self.k_ds_list)).encode())
            if hasattr(self, "de_a_list"):
                _section("SM9.Init(User enc)", de_a_list_len=str(len(self.de_a_list)).encode())

    # 6.2 签名（加入逐步打印）
    def sign(self, M, r=None, outbytes=True):
        if TRACE_SIGN and TRACE_LEVEL >= 1:
            _section("Sign.Input", M=M if isinstance(M, (bytes, bytearray)) else str(M).encode(), r=str(r).encode() if r is not None else b"<rand>", outbytes=str(outbytes).encode())
        # 覆写父类中的 KDF/H/MAC/pairing，可以直接复用逻辑
        M_bytes = M if isinstance(M, (bytes, bytearray)) else str(M).encode()
        # 这里直接复用你原来的签名算法逻辑，只是加上 trace
        # === 以下实现参考 SM9 签名标准流程 ===
        if r is None:
            # 使用原始实现中的随机生成方式
            r = self._rand_1_N()
        if TRACE_SIGN and TRACE_LEVEL >= 2:
            _section("Sign.Step rand r", r=str(r).encode())

        # 计算 w = g^r  (g = e(P1, Ppub_s))
        if not hasattr(self, "gs"):
            self.gs = e(P1, self.Ppub_s)  # 以后可复用
        w = bytes(self.gs_pow(r))
        if TRACE_SIGN and TRACE_LEVEL >= 2:
            _section("Sign.Step w=bytes(gs^r)", w=w)

        # h = H2(M || w)
        h = H(2, M_bytes + w)
        l = (r - h) % N
        if TRACE_SIGN and TRACE_LEVEL >= 2:
            _section("Sign.Step h,l", h=h.to_bytes(N_SIZE, "big"), l=l.to_bytes(N_SIZE, "big"))

        S = fast_kG(l, self.k_ds_list)
        sig = (h.to_bytes(N_SIZE, "big") + bytes(S)) if outbytes else (h, S)
        if TRACE_SIGN and TRACE_LEVEL >= 1:
            _section("Sign.Output", h=h.to_bytes(N_SIZE, "big"), S=bytes(S), sig=sig if isinstance(sig, (bytes, bytearray)) else b"<tuple>")
        return sig

    # 6.3 验证（加入逐步打印）
    def verify(self, ID, M, sig):
        if TRACE_VERIFY and TRACE_LEVEL >= 1:
            _section("Verify.Input", ID=ID if isinstance(ID, (bytes, bytearray)) else str(ID).encode(),
                     M=M if isinstance(M, (bytes, bytearray)) else str(M).encode(),
                     sig=sig if isinstance(sig, (bytes, bytearray)) else b"<tuple>")

        # 解析签名
        if isinstance(sig, (bytes, bytearray)):
            if len(sig) != (N_SIZE + 2 * N_SIZE):
                if TRACE_VERIFY:
                    _section("Verify.Fail", reason=b"bad sig length")
                return False
            h = int(sig[:N_SIZE].hex(), 16)
            S = ECC_Point.from_bytes(sig[N_SIZE:], q)
        else:
            h, S = sig

        # 合法性检查
        if not (1 <= h <= N - 1) or not self._is_on_curve(S):
            if TRACE_VERIFY:
                _section("Verify.Fail", reason=b"h not in (0,N) or S invalid/on-curve check failed")
            return False

        # t = g^h
        if not hasattr(self, "gs"):
            self.gs = e(P1, self.Ppub_s)
        t = self.gs_pow(h)
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.Step t=gs^h", t=bytes(t))

        # 计算 P = Q_ID + Ppub_s
        h1 = H(1, (ID if isinstance(ID, (bytes, bytearray)) else str(ID).encode()) + self.hid_s_byte)
        P = fast_kG(h1, get_kP_list(P2)) + self.Ppub_s
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.Step h1,P", h1=h1.to_bytes(hlen, "big"), P=bytes(P))

        # u = e(S, P)，w' = u * t
        u = pairing(S, P)
        w_ = bytes(u * t)
        if TRACE_VERIFY and TRACE_LEVEL >= 2:
            _section("Verify.Step u,w'", u=bytes(u), w_=w_)

        # h2 = H2(M || w')
        M_bytes = M if isinstance(M, (bytes, bytearray)) else str(M).encode()
        h2 = H(2, M_bytes + w_)
        ok = (h == h2)
        if TRACE_VERIFY:
            _section("Verify.Output", h2=h2.to_bytes(N_SIZE, "big"), result=b"OK" if ok else b"FAIL")
        return ok

    # 8.2/8.4 密钥封装 & 解封装（打印）
    def encaps(self, IDB, klen, r=None, outbytes=True):
        if TRACE_ENCAPS and TRACE_LEVEL >= 1:
            _section("Encaps.Input", IDB=IDB if isinstance(IDB, (bytes, bytearray)) else str(IDB).encode(),
                     klen=str(klen).encode(), r=str(r).encode() if r is not None else b"<rand>",
                     outbytes=str(outbytes).encode())
        K, C = super().encaps(IDB, klen, r, outbytes)
        if TRACE_ENCAPS and TRACE_LEVEL >= 1:
            _section("Encaps.Output", K=K, C=C)
        return K, C

    def decaps(self, IDB, C, outbytes=True):
        if TRACE_DECAPS and TRACE_LEVEL >= 1:
            _section("Decaps.Input", IDB=IDB if isinstance(IDB, (bytes, bytearray)) else str(IDB).encode(),
                     C=C if isinstance(C, (bytes, bytearray)) else b"<C>",
                     outbytes=str(outbytes).encode())
        K = super().decaps(IDB, C, outbytes)
        if TRACE_DECAPS and TRACE_LEVEL >= 1:
            _section("Decaps.Output", K=K)
        return K

    # 8.5 加密/解密（打印）
    def encrypt(self, IDB, M, r=None, outbytes=True):
        if TRACE_ENCRYPT and TRACE_LEVEL >= 1:
            _section("Encrypt.Input", IDB=IDB if isinstance(IDB, (bytes, bytearray)) else str(IDB).encode(),
                     M=M if isinstance(M, (bytes, bytearray)) else str(M).encode(),
                     r=str(r).encode() if r is not None else b"<rand>",
                     outbytes=str(outbytes).encode())
        C = super().encrypt(IDB, M, r, outbytes)
        if TRACE_ENCRYPT and TRACE_LEVEL >= 1:
            _section("Encrypt.Output", C=C if isinstance(C, (bytes, bytearray)) else b"<C>")
        return C

    def decrypt(self, C, outbytes=True):
        if TRACE_DECRYPT and TRACE_LEVEL >= 1:
            _section("Decrypt.Input", C=C if isinstance(C, (bytes, bytearray)) else b"<C>",
                     outbytes=str(outbytes).encode())
        ok, M = super().decrypt(C, outbytes)
        if TRACE_DECRYPT and TRACE_LEVEL >= 1:
            _section("Decrypt.Output", ok=b"OK" if ok else b"FAIL",
                     M=M if isinstance(M, (bytes, bytearray)) else b"<None>")
        return ok, M


# =========================
# BKGC / BDO / BDEP / BDU 的 Trace 版
# =========================

class BKGCTrace(BKGC):
    """带审计输出的 KGC"""

    def __init__(self, *args, **kwargs):
        super(BKGCTrace, self).__init__(*args, **kwargs)
        if TRACE_LEVEL >= 1:
            _section("BKGC.Init", Ppub_s=_to_bytes(self.Ppub_s), Ppub_e=_to_bytes(self.Ppub_e))

    def params(self):
        params = super(BKGCTrace, self).params()
        if TRACE_LEVEL >= 1:
            _section("BKGC.Params", params=str(params).encode())
        return params

    def enroll(self, ID):
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BKGC.Enroll.Input", ID=ID if isinstance(ID, (bytes, bytearray)) else str(ID).encode())
        keys = super(BKGCTrace, self).enroll(ID)
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BKGC.Enroll.Output", ID=keys.ID if isinstance(keys.ID, (bytes, bytearray)) else str(keys.ID).encode())
        return keys

    def open_trace(self, ID):
        if TRACE_TRACE and TRACE_LEVEL >= 1:
            _section("BKGC.OpenTrace.Input", ID=ID if isinstance(ID, (bytes, bytearray)) else str(ID).encode())
        A_open, info = super(BKGCTrace, self).open_trace(ID)
        if TRACE_TRACE and TRACE_LEVEL >= 1:
            _section("BKGC.OpenTrace.Output", A_open=_to_bytes(A_open), info=str(info).encode())
        return A_open, info


class BDOTrace(BDO):
    """带 trace 的签名提供方"""

    def __init__(self, *args, **kwargs):
        super(BDOTrace, self).__init__(*args, **kwargs)
        if TRACE_LEVEL >= 1:
            _section("BDO.Init", ID=self.keys.ID if hasattr(self, "keys") else b"<no-keys>")

    def blind(self, M):
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BDO.Blind.Input", M=M if isinstance(M, (bytes, bytearray)) else str(M).encode())
        M_prime, B, aux = super(BDOTrace, self).blind(M)
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BDO.Blind.Output", M_prime=M_prime, B=B, aux=str(aux).encode())
        return M_prime, B, aux

    def unblind_and_verify(self, ID, Q_ID, M_prime, B, r_inv, sig_tuple):
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BDO.Unblind.Input",
                     ID=ID if isinstance(ID, (bytes, bytearray)) else str(ID).encode(),
                     M_prime=M_prime, B=B)
        pub_ok, resp_ok, M = super(BDOTrace, self).unblind_and_verify(ID, Q_ID, M_prime, B, r_inv, sig_tuple)
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BDO.Unblind.Output", pub_ok=b"OK" if pub_ok else b"FAIL",
                     resp_ok=b"OK" if resp_ok else b"FAIL",
                     M=M if isinstance(M, (bytes, bytearray)) else b"<None>")
        return pub_ok, resp_ok, M


class BDEPTrace(BDEP):
    """带 trace 的平台"""

    def __init__(self, *args, **kwargs):
        super(BDEPTrace, self).__init__(*args, **kwargs)
        if TRACE_LEVEL >= 1:
            _section("BDEP.Init", desc=b"BDEP with trace")

    def verify_blinded(self, M_prime, B, R, S, T):
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BDEP.VerifyBlinded.Input",
                     M_prime=M_prime, B=B, R=_to_bytes(R), S=_to_bytes(S), T=_to_bytes(T))
        ok = super(BDEPTrace, self).verify_blinded(M_prime, B, R, S, T)
        if TRACE_BLIND and TRACE_LEVEL >= 1:
            _section("BDEP.VerifyBlinded.Output", result=b"OK" if ok else b"FAIL")
        return ok


class BDUTrace(BDU):
    """带 trace 的 DU"""

    def __init__(self, *args, **kwargs):
        super(BDUTrace, self).__init__(*args, **kwargs)
        if TRACE_LEVEL >= 1:
            _section("BDU.Init", desc=b"BDU with trace")

    def request_unblind(self, *args, **kwargs):
        if TRACE_BLIND and TRACE_LEVEL >= 2:
            _section("BDU.RequestUnblind.Input", args=str(args).encode(), kwargs=str(kwargs).encode())
        out = super(BDUTrace, self).request_unblind(*args, **kwargs)
        if TRACE_BLIND and TRACE_LEVEL >= 2:
            _section("BDU.RequestUnblind.Output", out=str(out).encode())
        return out

    def verify_opening(self, Q_ID, T, A_open):
        if TRACE_TRACE and TRACE_LEVEL >= 1:
            _section("BDU.VerifyOpening.Input", Q_ID=_to_bytes(Q_ID), T=_to_bytes(T), A_open=_to_bytes(A_open))
        ok = super(BDUTrace, self).verify_opening(Q_ID, T, A_open)
        if TRACE_TRACE and TRACE_LEVEL >= 1:
            _section("BDU.VerifyOpening.Output", result=b"OK" if ok else b"FAIL")
        return ok


# =========================
# DEMO：端到端演示流程
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
    print("\n[Verify Result] %s\n" % ok)


def demo_encrypt_decrypt():
    _hdr("DEMO: Encrypt / Decrypt")
    kgc = SM9Trace(ID="KGC", ke=-1)
    user = kgc.KGC_gen_user("Carol")

    # 保存 de, Ppub_e
    de, Ppub_e = getattr(user, "de", None), getattr(user, "Ppub_e", None)
    carol = SM9Trace(ID="Carol", de=de, Ppub_e=Ppub_e)

    plaintext = b"hello-sm9-encrypt"
    cipher = kgc.encrypt("Carol", plaintext, outbytes=True)

    ok, recovered = carol.decrypt(cipher)
    print("\n[Decrypt Result] ok=%s, M=%r\n" % (ok, recovered))


def demo_blind_trace():
    _hdr("DEMO: Blind Sign / Trace / Unblind")
    # 1) KGC（带追踪和审核）
    kgc = BKGCTrace()
    params = kgc.params()
    # 2) 注册用户
    keys = kgc.enroll("diana")
    # 3) 签名提供方（BDO）
    bdo = BDOTrace(params, keys, kgc)
    # 4) 平台
    bdep = BDEPTrace(params, keys, kgc)
    # 5) DU
    bdu = BDUTrace(params, keys, kgc)

    # 待签消息
    M = b"order-2024-0001"

    # A) 盲化
    M_prime, B, aux = bdo.blind(M)
    # B) 平台验签 + 订单门控，产生 R,S,T
    ok_blind = bdep.verify_blinded(M_prime, B, *aux.sig_tuple)
    print("\n[Platform VerifyBlinded] ok=%s" % ok_blind)

    # C) BDO 请求 r^-1
    r_inv = bdu.request_unblind()
    # D) BDO 计算 R', S'
    R, S, T = aux.sig_tuple
    # E) 去盲并验证、恢复 M
    pub_ok, resp_ok, M_out = bdu.unblind_and_verify(keys.ID, keys.Q_ID, M_prime, B, r_inv, (R, S, T))
    print("\n[Unblind Result] pub_ok=%s, resp_ok=%s, M=%r" % (pub_ok, resp_ok, M_out))
    # F) 打开验证（trace）
    A_open, _ = kgc.open_trace(keys.ID)
    opened = bdu.verify_opening(keys.Q_ID, T, A_open)
    print("[Open Trace] %s\n" % opened)


# ============================================================
# 模块 M4：GUI 场景封装（供 Tk 前端调用）
# ============================================================

def gui_sign_verify(user_id, message):
    """
    GUI 版签名/验签演示：
    - KGC 生成主密钥并为 user_id 派生签名私钥
    - user_id 对给定消息签名并立即验签
    """
    if not user_id:
        user_id = "Bob"
    if isinstance(message, str):
        M = message.encode("utf-8")
    else:
        M = message or b""
    _hdr("GUI DEMO: Sign / Verify (%s)" % user_id)
    # KGC 生成主密钥
    kgc = SM9Trace(ID="KGC", ks=-1, ke=-1)
    user = kgc.KGC_gen_user(user_id)
    # 从注册结果中恢复用户侧对象
    ds = getattr(user, "k_ds_list", None)
    Ppub_s = getattr(user, "Ppub_s", None)
    ds_point = ds and fast_kG(1, ds)
    sm9_user = SM9Trace(ID=user_id, ks=-1, ds=ds_point, Ppub_s=Ppub_s)
    sig = sm9_user.sign(M, outbytes=True)
    ok = sm9_user.verify(user_id, M, sig)
    print("\n[Verify Result] user_id=%r, ok=%s\n" % (user_id, ok))


def gui_encrypt_decrypt(user_id, plaintext):
    """
    GUI 版加密/解密演示：
    - KGC 生成主密钥并为 user_id 派生解密私钥
    - KGC 加密，用户解密
    """
    if not user_id:
        user_id = "Carol"
    if isinstance(plaintext, str):
        M = plaintext.encode("utf-8")
    else:
        M = plaintext or b""
    _hdr("GUI DEMO: Encrypt / Decrypt (%s)" % user_id)
    kgc = SM9Trace(ID="KGC", ke=-1)
    user = kgc.KGC_gen_user(user_id)
    de = getattr(user, "de", None)
    Ppub_e = getattr(user, "Ppub_e", None)
    sm9_user = SM9Trace(ID=user_id, de=de, Ppub_e=Ppub_e)
    cipher = kgc.encrypt(user_id, M, outbytes=True)
    ok, recovered = sm9_user.decrypt(cipher)
    print("\n[Decrypt Result] user_id=%r, ok=%s, M=%r\n" % (user_id, ok, recovered))


def gui_blind_trace_full():
    """
    GUI 版盲签 + 订单门控 + 去盲 + 打开验证一键演示。
    直接复用 demo_blind_trace。
    """
    demo_blind_trace()


# ============================================================
# 模块 M5：Tk 前端可视化界面模块
# ============================================================

import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


class _TextRedirector(object):
    """把 print 输出重定向到 Tk 文本框。"""
    def __init__(self, text_widget, tag="stdout"):
        self.text_widget = text_widget
        self.tag = tag

    def write(self, s):
        if not isinstance(s, str):
            s = str(s)
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, s, (self.tag,))
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")

    def flush(self):
        # 兼容 file-like 接口
        pass


class SM9TraceApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("SM9Trace 可追踪盲签与订单门控可视化系统")
        self.geometry("1100x720")
        self.minsize(900, 600)

        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

        self._build_ui()

        # 将 stdout/stderr 重定向到日志窗口
        redirector = _TextRedirector(self.log_text)
        sys.stdout = redirector
        sys.stderr = redirector

    def destroy(self):
        # 关闭窗口时恢复输出
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        tk.Tk.destroy(self)

    # ---------------- UI 布局 ----------------

    def _build_ui(self):
        # 顶部整体区域：左侧场景选择，右侧输入 + 日志
        top = ttk.Frame(self)
        top.pack(fill="both", expand=True)

        # 左侧：场景按钮
        left = ttk.Frame(top, padding=10)
        left.pack(side="left", fill="y")

        ttk.Label(left, text="场景选择", font=("Microsoft YaHei", 11, "bold")).pack(anchor="w", pady=(0, 10))

        self.current_scene = tk.StringVar(value="sign")

        ttk.Button(
            left, text="签名 / 验签",
            command=lambda: self._show_scene("sign")
        ).pack(fill="x", pady=4)

        ttk.Button(
            left, text="加密 / 解密",
            command=lambda: self._show_scene("encrypt")
        ).pack(fill="x", pady=4)

        ttk.Button(
            left, text="盲签 + 订单门控全流程",
            command=lambda: self._show_scene("blind")
        ).pack(fill="x", pady=4)

        ttk.Label(
            left,
            text="提示：日志区域会展示\nKDF/H/MAC/配对等\n中间量及验证结果。",
            justify="left"
        ).pack(anchor="w", pady=(20, 0))

        # 右侧：输入区 + 日志区
        right = ttk.Frame(top, padding=(5, 10, 10, 10))
        right.pack(side="right", fill="both", expand=True)

        # 输入区容器
        self.scene_container = ttk.Frame(right)
        self.scene_container.pack(side="top", fill="x")

        self.scene_container.columnconfigure(0, weight=1)
        self.scene_container.rowconfigure(0, weight=1)

        # 日志区域
        log_frame = ttk.LabelFrame(right, text="Trace 日志输出", padding=5)
        log_frame.pack(side="bottom", fill="both", expand=True, pady=(8, 0))

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap="word", height=22, state="disabled"
        )
        self.log_text.pack(fill="both", expand=True)

        # 构造三个场景的输入子界面
        self.scenes = {}
        self._build_sign_scene()
        self._build_encrypt_scene()
        self._build_blind_scene()

        self._show_scene("sign")

    # ---------------- 场景子界面 ----------------

    def _build_sign_scene(self):
        frame = ttk.Frame(self.scene_container)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="签名 / 验签演示", font=("Microsoft YaHei", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(frame, text="用户 ID：").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.entry_sign_id = ttk.Entry(frame)
        self.entry_sign_id.insert(0, "Bob")
        self.entry_sign_id.grid(row=1, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(frame, text="消息内容：").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.entry_sign_msg = ttk.Entry(frame)
        self.entry_sign_msg.insert(0, "hello-sm9-sign")
        self.entry_sign_msg.grid(row=2, column=1, sticky="we", padx=4, pady=4)

        ttk.Button(
            frame, text="执行签名 + 验签",
            command=self._on_sign_verify
        ).grid(row=3, column=0, columnspan=2, pady=(10, 4))

        ttk.Button(
            frame, text="清空日志",
            command=self._clear_log
        ).grid(row=4, column=0, columnspan=2, pady=(4, 0))

        frame.columnconfigure(1, weight=1)
        self.scenes["sign"] = frame

    def _build_encrypt_scene(self):
        frame = ttk.Frame(self.scene_container)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="加密 / 解密演示", font=("Microsoft YaHei", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(frame, text="用户 ID：").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.entry_enc_id = ttk.Entry(frame)
        self.entry_enc_id.insert(0, "Carol")
        self.entry_enc_id.grid(row=1, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(frame, text="明文：").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.entry_enc_msg = ttk.Entry(frame)
        self.entry_enc_msg.insert(0, "hello-sm9-encrypt")
        self.entry_enc_msg.grid(row=2, column=1, sticky="we", padx=4, pady=4)

        ttk.Button(
            frame, text="执行加密 + 解密",
            command=self._on_encrypt_decrypt
        ).grid(row=3, column=0, columnspan=2, pady=(10, 4))

        ttk.Button(
            frame, text="清空日志",
            command=self._clear_log
        ).grid(row=4, column=0, columnspan=2, pady=(4, 0))

        frame.columnconfigure(1, weight=1)
        self.scenes["encrypt"] = frame

    def _build_blind_scene(self):
        frame = ttk.Frame(self.scene_container)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="盲签 + 订单门控 + 去盲 + 打开验证", font=("Microsoft YaHei", 11, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )

        ttk.Label(
            frame,
            text="点击下方按钮，一键演示：\n"
                 "1) KGC 注册与追踪材料生成\n"
                 "2) BDO 盲化签名请求\n"
                 "3) BDEP 验签与订单门控\n"
                 "4) BDO/DU 去盲并恢复明文\n"
                 "5) KGC 打开验证",
            justify="left"
        ).grid(row=1, column=0, sticky="w", padx=4, pady=4)

        ttk.Button(
            frame, text="执行完整盲签流程",
            command=self._on_blind_flow
        ).grid(row=2, column=0, pady=(10, 4), padx=4, sticky="w")

        ttk.Button(
            frame, text="清空日志",
            command=self._clear_log
        ).grid(row=3, column=0, pady=(4, 0), padx=4, sticky="w")

        self.scenes["blind"] = frame

    # ---------------- 场景切换 & 日志 ----------------

    def _show_scene(self, name):
        self.current_scene.set(name)
        frame = self.scenes.get(name)
        if frame is not None:
            frame.tkraise()

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    # ---------------- 按钮事件 ----------------

    def _on_sign_verify(self):
        user_id = self.entry_sign_id.get().strip()
        msg = self.entry_sign_msg.get()
        self._clear_log()
        try:
            gui_sign_verify(user_id, msg)
        except Exception as e:
            messagebox.showerror("错误", "签名/验签流程失败：%r" % (e,))

    def _on_encrypt_decrypt(self):
        user_id = self.entry_enc_id.get().strip()
        msg = self.entry_enc_msg.get()
        self._clear_log()
        try:
            gui_encrypt_decrypt(user_id, msg)
        except Exception as e:
            messagebox.showerror("错误", "加密/解密流程失败：%r" % (e,))

    def _on_blind_flow(self):
        self._clear_log()
        try:
            gui_blind_trace_full()
        except Exception as e:
            messagebox.showerror("错误", "盲签流程失败：%r" % (e,))


# ============================================================
# 程序入口
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SM9Trace 可追踪盲签与订单门控可视化系统")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="启动 Tk 前端界面（默认命令行 demo）"
    )
    args = parser.parse_args()

    if args.gui:
        app = SM9TraceApp()
        app.mainloop()
    else:
        # 保留原来的命令行演示方式
        demo_sign_verify()
        demo_encrypt_decrypt()
        demo_blind_trace()
