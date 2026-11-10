# from function.sm9_algorithm import *
# # ---- Demo：端到端流程（覆盖：盲化、点值签名、可复算挑战、配对验签、追踪/打开、去盲校验、订单门控） ----
# def demo_flow_bs():
#     # 0) 初始化
#     kgc = BKGC(hid_s=1, version="v1")
#     params = kgc.params()
#
#     # 1) 注册 DO：发放 (Q_ID, d_ID) 与追踪材料 (T, A_open)
#     do_keys = kgc.enroll("DO-001")
#     do = BDO(params, do_keys, kgc)
#
#     # 2) 平台/用户
#     dep = BDEP(params, kgc)
#     du  = BDU(params)
#
#     # 3) 盲化
#     M = b"example: payload bytes of original data"
#     # M = "这是我的业务消息".encode("utf-8")   # 或者不带中文就直接 b"..."
#
#
#     M_, B = do.blind(M)  # ###(13)-(16)###
#
#     # 4) 点值签名（对 M'）
#     sig = do.sign_blinded(M_)  # (R,S,T)  ###(17)-(21)###
#
#     # 5) 平台验签（对 M'；绑定 T） ——【公式(Verify)】
#     ok_dep = dep.verify_blinded(do_keys.ID, do_keys.Q_ID, M_, sig)  # ###(9)(10)###
#     print("DEP 验证 (对 M')：", ok_dep)
#
#     # 6) 平台验订单 → DO 才释放 r^{-1}（门控）
#     ticket = dep.verify_order(sm3(b"order:123"), sm3(b"paid:tx_abc"))  # ###(23)###
#     r_inv = do.release_r_inv(ticket)  # ###(22)###
#
#     # 7) DU 去盲三步：去盲临时公钥/响应值校验 → 恢复原文 ——【公式(Unblind-Resp)】
#     pub_ok, resp_ok, M_rec = du.unblind_and_verify(do_keys.ID, do_keys.Q_ID, M_, B, r_inv, sig)  # ###(24)-(29)###
#     print("去盲临时公钥校验：", pub_ok)
#     print("去盲响应值校验：", resp_ok)
#     print("恢复原文：", M_rec)
#
#     # 8) KGC 打开：发布 A=α·P2；第三方/DU 校验 ——【公式(Trace)】
#     A_open, _ = kgc.open_trace(do_keys.ID)  # ###(Trace)###
#     R, S, T = sig
#     open_ok = du.verify_opening(do_keys.Q_ID, T, A_open)  # ###(Trace)###
#     print("打开验证 e(T,P2)==e(Q_ID,A)：", open_ok)
#
#
# if __name__ == "__main__":
#     demo_flow_bs()
#     # shuru erjinzhi debind


# sm9_trace.py 片段
import sys, os, argparse, base64, binascii
from function.sm9_algorithm import *  # 你已有的导入

# ------- 输入载入工具：文件 / stdin / hex: / b64: -------
def load_bytes(source: str) -> bytes:
    """
    source:
      - 文件路径: 'path/to/file.bin'
      - 标准输入: '-'  (例如: cat msg.bin | python sm9_trace.py --in -)
      - 直接字面: 'hex:48656c6c6f' 或 'b64:SGVsbG8='
    """
    if source == "-":
        return sys.stdin.buffer.read()

    if source.startswith("hex:"):
        s = source[4:].strip().replace(" ", "")
        try:
            return bytes.fromhex(s)
        except ValueError as e:
            raise ValueError(f"hex 输入非法: {e}")

    if source.startswith("b64:"):
        s = source[4:].strip()
        try:
            return base64.b64decode(s, validate=True)
        except binascii.Error as e:
            raise ValueError(f"base64 输入非法: {e}")

    # 默认按文件读取（以二进制形式）
    if not os.path.exists(source):
        raise FileNotFoundError(f"找不到输入文件: {source}")
    with open(source, "rb") as f:
        return f.read()

def save_bytes(out_path: str, data: bytes):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)

# ------- 原来的 demo_flow_bs：加参数，使用文件载入 -------
def demo_flow_bs(msg_source: str, out_path: str = None, id_str: str = "DO-001", version: str = "v1"):
    # 0) 初始化
    kgc = BKGC(hid_s=1, version=version)
    params = kgc.params()

    # 1) 注册 DO：发放 (Q_ID, d_ID) 与追踪材料 (T, A_open)
    do_keys = kgc.enroll(id_str)
    do = BDO(params, do_keys, kgc)

    # 2) 平台/用户
    dep = BDEP(params, kgc)
    du  = BDU(params)

    # 3) 载入原文（从文件/stdin/hex/b64）
    M = load_bytes(msg_source)
    print(f"[Input] 加载消息 {len(M)} 字节")
    # 可选：预览前 64 字节十六进制
    print(f"[Input.preview] {M[:64].hex()}{'...' if len(M) > 64 else ''}")

    # 4) 盲化
    M_, B = do.blind(M)  # ###(13)-(16)###
    print(f"[Blind] 生成盲化消息 M_（{len(M_)} 字节）")

    # 5) 点值签名（对 M'）
    sig = do.sign_blinded(M_)  # (R,S,T)  ###(17)-(21)###
    print("[Sign_blinded] 完成 (R,S,T)")

    # 6) 平台验签（对 M'；绑定 T）
    ok_dep = dep.verify_blinded(do_keys.ID, do_keys.Q_ID, M_, sig)  # ###(9)(10)###
    print("DEP 验证 (对 M')：", ok_dep)

    # 7) 平台验订单 → DO 才释放 r^{-1}（门控）
    ticket = dep.verify_order(sm3(b"order:123"), sm3(b"paid:tx_abc"))  # ###(23)###
    r_inv = do.release_r_inv(ticket)  # ###(22)###
    print("[Gate] 门控通过，释放 r^{-1}")

    # 8) DU 去盲三步：去盲临时公钥/响应值校验 → 恢复原文
    pub_ok, resp_ok, M_rec = du.unblind_and_verify(do_keys.ID, do_keys.Q_ID, M_, B, r_inv, sig)  # ###(24)-(29)###
    print("去盲临时公钥校验：", pub_ok)
    print("去盲响应值校验：", resp_ok)
    print("恢复原文长度：", len(M_rec))
    same = (M_rec == M)
    print("去盲恢复是否与输入一致：", same)

    # 9) KGC 打开：发布 A=α·P2；第三方/DU 校验
    A_open, _ = kgc.open_trace(do_keys.ID)  # ###(Trace)###
    R, S, T = sig
    open_ok = du.verify_opening(do_keys.Q_ID, T, A_open)  # ###(Trace)###
    print("打开验证 e(T,P2)==e(Q_ID,A)：", open_ok)

    # 10) 如指定 --out，把恢复原文写回磁盘
    if out_path:
        save_bytes(out_path, M_rec)
        print(f"[Output] 已写出恢复原文到: {out_path}")

# ------- 命令行入口（默认都在脚本同目录） -------
# ------- 命令行入口（默认都在脚本同目录） + 运行时统计 -------
if __name__ == "__main__":
    import time, tracemalloc, resource, sys

    # 脚本同目录
    DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
    DEFAULT_IN  = os.path.join(DEMO_DIR, "msg.bin")
    DEFAULT_OUT = os.path.join(DEMO_DIR, "recovered.bin")

    parser = argparse.ArgumentParser(description="SM9 盲签+追踪 Demo（支持文件输入）")
    parser.add_argument(
        "--in", dest="msg_source", default=DEFAULT_IN,
        help=f"消息来源：文件路径，或 '-'(stdin)，或 'hex:..'/'b64:..'（默认：{DEFAULT_IN}）"
    )
    parser.add_argument(
        "--out", dest="out_path", default=DEFAULT_OUT,
        help=f"去盲恢复后的原文输出路径（默认：{DEFAULT_OUT}）"
    )
    parser.add_argument("--id", dest="id_str", default="DO-001", help="身份 ID（默认 DO-001）")
    parser.add_argument("--ver", dest="version", default="v1", help="版本/域分离（默认 v1）")
    args = parser.parse_args()

    # 如果使用默认输入且文件不存在，自动写入一个示例消息，方便开箱即跑
    if args.msg_source == DEFAULT_IN and not os.path.exists(DEFAULT_IN):
        os.makedirs(DEMO_DIR, exist_ok=True)
        with open(DEFAULT_IN, "wb") as f:
            f.write(b"example: payload bytes of original data")
        print(f"[Bootstrap] 已在同目录生成默认输入文件: {DEFAULT_IN}")

    # ---- 运行统计：总耗时 + 内存占用（MaxRSS 与 tracemalloc 峰值） ----
    def _max_rss_mb() -> float:
        """返回 OS 进程层面的最大常驻内存（MB）。
        Linux 上 resource.ru_maxrss 单位是 KB；macOS 是 Bytes。"""
        ru = resource.getrusage(resource.RUSAGE_SELF)
        if sys.platform == "darwin":
            return ru.ru_maxrss / (1024.0 * 1024.0)  # Bytes -> MB
        else:
            return ru.ru_maxrss / 1024.0  # KB -> MB

    t0 = time.perf_counter()
    tracemalloc.start()

    # 你的主流程
    demo_flow_bs(
        msg_source=args.msg_source,
        out_path=args.out_path,
        id_str=args.id_str,
        version=args.version
    )

    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    maxrss_mb = _max_rss_mb()

    print("\n==================== Performance ====================")
    print(f"[Perf] Wall time: {elapsed_ms:,.2f} ms")
    print(f"[Perf] Python heap peak (tracemalloc): {peak_bytes / (1024*1024):.2f} MB "
          f"(current {current_bytes / (1024*1024):.2f} MB)")
    print(f"[Perf] Max RSS (OS): {maxrss_mb:.2f} MB")
    print("=====================================================\n")
