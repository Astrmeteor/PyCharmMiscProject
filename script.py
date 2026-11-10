#
#
# """
# 保持现有盲化流程 + 采用真实 SM2/SM3 签名/验证 的完整示例（Python + Charm + gmssl）
# ---------------------------------------------------------------------
# 用途：教学/原型；签名与验签部分符合国密 SM2/SM3 调用（gmssl），盲化流程保持不变。
# 注意：本示例为最小可运行版本，工程化需增加异常处理、参数校验、审计等。
# """
#
# from __future__ import annotations
# from dataclasses import dataclass
# from typing import Tuple, Optional
#
# # ---------------------------------------------
# # 依赖导入
# # ---------------------------------------------
# from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
# from charm.toolbox.hash_module import Hash
#
# try:
#     from gmssl import sm2, func as gmssl_func
# except Exception as e:
#     raise ImportError(
#         "本示例需要 gmssl（国密 SM2/SM3）。请先安装：pip install gmssl\n"
#         f"原始错误：{e}"
#     )
#
# # ---------------------------------------------
# # 哈希族 H1/H2/H3（H1/H2 用于标量与点映射；H3 生成盲化掩码）
# # ---------------------------------------------
#
# class HashSuite:
#     """协议哈希集合：
#     - H1(ID)->G1：将身份映射为曲线点（用于 SM9 身份模型/标识）
#     - H2(items)->ZR：将上下文映射到群阶内标量（挑战/派生）
#     - H3(element)->bytes：将群元素映射成定长字节串（盲化用）
#     """
#     def __init__(self, group: PairingGroup):
#         self.group = group
#         self.hasher = Hash(group)
#
#     def H1(self, identity: str):
#         # 身份到曲线点（演示用途；本示例的签名/验签用 SM2，与 H1 无强绑定）
#         return self.group.hash(identity, G1)
#
#     def H2(self, *items) -> ZR:
#         concat = "|".join(self._to_str(x) for x in items)
#         return self.group.hash(concat, ZR)
#
#     def H3(self, element) -> bytes:
#         # 域分离前缀可按需加入 b"H3:"
#         s = self._to_str(element).encode()
#         k = self.group.hash(s, ZR)
#         # 32 字节掩码（SM4/对称加密也可；这里用 XOR 简化演示）
#         return int(k).to_bytes(32, byteorder="big")
#
#     def _to_str(self, x) -> str:
#         try:
#             return self.group.serialize(x).hex()
#         except Exception:
#             return str(x)
#
# # ---------------------------------------------
# # 通用字节 XOR（盲化/去盲）
# # ---------------------------------------------
#
# def xor_bytes(a: bytes, b: bytes) -> bytes:
#     if not a or not b:
#         return a or b
#     if len(b) < len(a):
#         b = (b * (len(a) // len(b) + 1))[:len(a)]
#     elif len(a) < len(b):
#         a = (a * (len(b) // len(a) + 1))[:len(b)]
#     return bytes(x ^ y for x, y in zip(a, b))
#
# # ---------------------------------------------
# # SM2/SM3 封装（gmssl，兼容新版/旧版 data_id 参数）
# # ---------------------------------------------
#
# def sm2_user_id_from_id(id_str: str) -> bytes:
#     """把任意 ID 规整为 16 字节 user_id（SM2 ZA 会用到；签名与验签必须一致）"""
#     raw = id_str.encode("utf-8")
#     return (raw + b"\x00" * 16)[:16]
#
# class SM2Suite:
#     """真实 SM2/SM3 调用封装（基于 gmssl）"""
#     DEFAULT_ID = b"1234567812345678"  # 若未显式传入 user_id，使用该默认值
#
#     @staticmethod
#     def gen_keypair() -> Tuple[str, str]:
#         """生成 SM2 私钥/公钥（十六进制字符串）。"""
#         priv_hex = gmssl_func.random_hex(32)
#         # gmssl 构造时 public_key 不能为 None，用空串占位
#         sm2_obj = sm2.CryptSM2(private_key=priv_hex, public_key='')
#         pub_hex = sm2_obj._kg(int(priv_hex, 16), sm2_obj.ecc_table['g'])  # 生成未压缩公钥（去掉 0x04 前缀）
#         return priv_hex, pub_hex
#
#     @staticmethod
#     def sign_sm3(message: bytes, priv_hex: str, user_id: bytes, pub_hex: str = '') -> str:
#         """SM2+SM3 签名：优先使用 data_id= 关键字（新版 gmssl），不支持则回退为单参。"""
#         if user_id is None:
#             user_id = SM2Suite.DEFAULT_ID
#         sm2_obj = sm2.CryptSM2(private_key=priv_hex, public_key=(pub_hex or ''))
#         try:
#             # 新版 gmssl：支持 data_id 关键字
#             return sm2_obj.sign_with_sm3(message, data_id=user_id)
#         except TypeError:
#             # 旧版：不支持 data_id，退化使用默认 ZA（注意：签名与验签两边都需同样处理）
#             return sm2_obj.sign_with_sm3(message)
#
#     @staticmethod
#     def verify_sm3(message: bytes, sign_hex: str, pub_hex: str, user_id: bytes) -> bool:
#         """SM2+SM3 验签：同上，优先 data_id=，旧版回退单参。"""
#         if user_id is None:
#             user_id = SM2Suite.DEFAULT_ID
#         sm2_obj = sm2.CryptSM2(private_key=None, public_key=(pub_hex or ''))
#         try:
#             return sm2_obj.verify_with_sm3(sign_hex, message, data_id=user_id)
#         except TypeError:
#             return sm2_obj.verify_with_sm3(sign_hex, message)
#
# # ---------------------------------------------
# # 公共参数与用户密钥
# # ---------------------------------------------
#
# @dataclass
# class SystemParams:
#     group: PairingGroup
#     P: any           # 生成元
#     s: ZR            # 主密钥（仅 KGC 持有；本 Demo 为简化联调放出）
#     P_pub: any       # 系统公钥 = s·P
#     H: HashSuite     # 哈希族
#
# @dataclass
# class UserKeys:
#     # 身份（可用于绑定/追踪；与 SM2 不强绑定）
#     ID: str
#     Q_ID: any        # H1(ID) -> G1
#     SK_point: any    # s·Q_ID
#     PK: any          # Q_ID
#
#     # SM2/SM3 密钥对（真实签名/验签用）
#     sm2_priv_hex: str
#     sm2_pub_hex: str
#
# # ---------------------------------------------
# # KGC：初始化 + 发放密钥
# # ---------------------------------------------
#
# class KGC:
#     def __init__(self, security_param: str = 'SS512'):
#         # 说明：这里使用对称配对群（SS512）仅为演示 H1/H2/H3 与盲化流程；
#         #      SM2/SM3 独立在 gmssl 内完成，与配对群无依赖。
#         self.group = PairingGroup(security_param)
#         self.H = HashSuite(self.group)
#         self.P = self.group.random(G1)
#         self.s = self.group.random(ZR)
#         self.P_pub = self.s * self.P
#
#     def params(self) -> SystemParams:
#         return SystemParams(group=self.group, P=self.P, s=self.s, P_pub=self.P_pub, H=self.H)
#
#     def keygen(self, ID: str) -> UserKeys:
#         # 身份映射（可用于后续 SM9 拓展/追踪）
#         Q_ID = self.H.H1(ID)
#         SK_point = self.s * Q_ID
#         PK = Q_ID
#         # 生成真实 SM2 密钥
#         sm2_priv_hex, sm2_pub_hex = SM2Suite.gen_keypair()
#         return UserKeys(ID=ID, Q_ID=Q_ID, SK_point=SK_point, PK=PK,
#                         sm2_priv_hex=sm2_priv_hex, sm2_pub_hex=sm2_pub_hex)
#
# # ---------------------------------------------
# # DEP：平台（使用真实 SM2/SM3 验签）
# # ---------------------------------------------
#
# class DEP:
#     def __init__(self, params: SystemParams):
#         self.params = params
#
#     def verify_blind_signature(self, M_blinded: bytes, sigma_hex: str,
#                                sm2_pub_hex: str, user_id: bytes) -> bool:
#         """对盲化数据 M' 的 SM2/SM3 签名进行验证。"""
#         return SM2Suite.verify_sm3(M_blinded, sigma_hex, sm2_pub_hex, user_id)
#
# # ---------------------------------------------
# # DO：数据拥有者（盲化 + 真实 SM2/SM3 签名）
# # ---------------------------------------------
#
# class DO:
#     def __init__(self, params: SystemParams, keys: UserKeys):
#         self.params = params
#         self.keys = keys
#         self._last_r: Optional[ZR] = None
#         self._last_B = None
#
#     def blind(self, M: bytes) -> Tuple[bytes, any]:
#         """盲化：B = r·P；k = H3(B)；M' = M XOR k"""
#         group, P, H = self.params.group, self.params.P, self.params.H
#         r = group.random(ZR)
#         B = r * P
#         k_bytes = H.H3(B)
#         M_blinded = xor_bytes(M, k_bytes)
#         self._last_r = r
#         self._last_B = B
#         return M_blinded, B
#
#     def sign_blinded(self, M_blinded: bytes, user_id: bytes = None) -> str:
#         """对盲化数据 M' 进行真实 SM2/SM3 签名（gmssl）。"""
#         if user_id is None:
#             user_id = sm2_user_id_from_id(self.keys.ID)
#         return SM2Suite.sign_sm3(
#             message=M_blinded,
#             priv_hex=self.keys.sm2_priv_hex,
#             user_id=user_id,
#             pub_hex=self.keys.sm2_pub_hex,  # 传公钥更稳妥（gmssl 构造时不传 None）
#         )
#
#     def issue_unblind_factor(self) -> ZR:
#         """当前盲化方案的去盲不需要 r_inv，这里保留接口以便将来切换 SM9 盲签。"""
#         if self._last_r is None:
#             raise ValueError("未检测到盲化记录，请先执行 blind()。")
#         group = self.params.group
#         return 1 / self._last_r
#
# # ---------------------------------------------
# # DU：数据使用者（去盲 + 真实 SM2/SM3 验签）
# # ---------------------------------------------
#
# class DU:
#     def __init__(self, params: SystemParams):
#         self.params = params
#
#     def unblind_and_recover(self, M_blinded: bytes, B: any) -> bytes:
#         """去盲：k = H3(B)；M = M' XOR k"""
#         k_bytes = self.params.H.H3(B)
#         return xor_bytes(M_blinded, k_bytes)
#
#     def verify_original_signature(self, dep: DEP, M_blinded: bytes,
#                                   sigma_hex: str, sm2_pub_hex: str, user_id: bytes) -> bool:
#         """用户侧复核：真实 SM2/SM3 验签。"""
#         return dep.verify_blind_signature(M_blinded, sigma_hex, sm2_pub_hex, user_id)
#
# # ---------------------------------------------
# # Demo：端到端流程
# # ---------------------------------------------
#
# def demo_flow():
#     # 1) 初始化系统
#     kgc = KGC('SS512')
#     params = kgc.params()
#
#     # 2) 注册 DO
#     do_keys = kgc.keygen(ID="DO-001")
#     do = DO(params, do_keys)
#
#     # 3) 平台 & 使用者
#     dep = DEP(params)
#     du = DU(params)
#
#     # 4) 盲化
#     M = b"example: payload bytes of original data"
#     M_blinded, B = do.blind(M)
#
#     # 5) 真实 SM2/SM3 签名（统一 user_id）
#     uid = sm2_user_id_from_id(do_keys.ID)
#     sigma_hex = do.sign_blinded(M_blinded, user_id=uid)
#
#     # 6) 平台验签（真实 SM2/SM3）
#     ok_dep = dep.verify_blind_signature(M_blinded, sigma_hex, do_keys.sm2_pub_hex, user_id=uid)
#     print("DEP 验证结果:", ok_dep)
#
#     # 7) 去盲恢复
#     M_recovered = du.unblind_and_recover(M_blinded, B)
#     print("恢复的数据:", M_recovered)
#
#     # 8) 用户侧复核签名
#     ok_du = du.verify_original_signature(dep, M_blinded, sigma_hex, do_keys.sm2_pub_hex, user_id=uid)
#     print("DU 验证结果:", ok_du)
#
# if __name__ == "__main__":
#     demo_flow()
"""
保持现有盲化流程 + 采用真实 SM2/SM3 签名/验证 的完整示例（Python + Charm + gmssl）
---------------------------------------------------------------------
用途：教学/原型；签名与验签部分符合国密 SM2/SM3 调用（gmssl），盲化流程保持不变。
注意：本示例为最小可运行版本，工程化需增加异常处理、参数校验、审计等。
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional

# ---------------------------------------------
# 依赖导入
# ---------------------------------------------
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
from charm.toolbox.hash_module import Hash

try:
    from gmssl import sm2, func as gmssl_func
except Exception as e:
    raise ImportError(
        "本示例需要 gmssl（国密 SM2/SM3）。请先安装：pip install gmssl\n"
        f"原始错误：{e}"
    )

# ---------------------------------------------
# 哈希族 H1/H2/H3（H1/H2 用于标量与点映射；H3 生成盲化掩码）
# ---------------------------------------------

class HashSuite:
    """协议哈希集合：
    - H1(ID)->G1：将身份映射为曲线点（用于 SM9 身份模型/标识）
        论文对照：H1 : {0,1}* → G1，用于 Q_ID = H1(ID)          （见“系统初始化/KeyGen”）
    - H2(items)->ZR：将上下文映射到群阶内标量（挑战/派生）
        论文对照：H2 : {0,1}* → Z_q，用于 c = H2( … )、c' = H2( … )（见“签名/验证”）
    - H3(element)->bytes：将群元素映射成定长字节串（盲化用）
        论文对照：H3 : G1 → {0,1}^n，用于 k = H3(B)               （见“数据盲化”）
    """
    def __init__(self, group: PairingGroup):
        self.group = group
        self.hasher = Hash(group)

    def H1(self, identity: str):
        # 论文式（KeyGen）：Q_ID = H1(ID) ∈ G1
        return self.group.hash(identity, G1)

    def H2(self, *items) -> ZR:
        # 论文式：c 或 c' = H2(上下文) ∈ Z_q
        concat = "|".join(self._to_str(x) for x in items)
        return self.group.hash(concat, ZR)

    def H3(self, element) -> bytes:
        # 论文式（盲化）：k = H3(B)，其中 B = r·P
        # 注：SM9 规范中 H3/KDF 以 SM3 为基，且常带域分离与cofactor清理；这里为通用实现
        s = self._to_str(element).encode()
        k = self.group.hash(s, ZR)
        # 论文式（盲化掩码固定长度）：k ∈ {0,1}^n —— 这里取 32 字节
        return int(k).to_bytes(32, byteorder="big")

    def _to_str(self, x) -> str:
        try:
            return self.group.serialize(x).hex()
        except Exception:
            return str(x)

# ---------------------------------------------
# 通用字节 XOR（盲化/去盲）
# ---------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    # 论文式（盲化/去盲的核心）：M' = M ⊕ k，  k = H3(B)
    #                               M  = M'⊕ k
    if not a or not b:
        return a or b
    if len(b) < len(a):
        b = (b * (len(a) // len(b) + 1))[:len(a)]
    elif len(a) < len(b):
        a = (a * (len(b) // len(a) + 1))[:len(b)]
    return bytes(x ^ y for x, y in zip(a, b))

# ---------------------------------------------
# SM2/SM3 封装（gmssl，兼容新版/旧版 data_id 参数）
# ---------------------------------------------

def sm2_user_id_from_id(id_str: str) -> bytes:
    """把任意 ID 规整为 16 字节 user_id（SM2 ZA 会用到；签名与验签必须一致）
    论文里对应的是“身份 ID”，在 SM9 中用于 H1(ID)；在 SM2 中进入 ZA 计算。
    """
    raw = id_str.encode("utf-8")
    return (raw + b"\x00" * 16)[:16]

class SM2Suite:
    """真实 SM2/SM3 调用封装（基于 gmssl）"""
    DEFAULT_ID = b"1234567812345678"  # 若未显式传入 user_id，使用该默认值

    @staticmethod
    def gen_keypair() -> Tuple[str, str]:
        """生成 SM2 私钥/公钥（十六进制字符串）。"""
        # 论文式（SM9侧的KeyGen做法为：Q_ID = H1(ID), SK_ID = s·Q_ID）；
        # 本实现改用 SM2：私钥 d 随机，公钥 P_A = d·G（由 gmssl 内部曲线给出）
        priv_hex = gmssl_func.random_hex(32)
        # gmssl 构造时 public_key 不能为 None，用空串占位
        sm2_obj = sm2.CryptSM2(private_key=priv_hex, public_key='')
        pub_hex = sm2_obj._kg(int(priv_hex, 16), sm2_obj.ecc_table['g'])  # P_A = d·G
        return priv_hex, pub_hex

    @staticmethod
    def sign_sm3(message: bytes, priv_hex: str, user_id: bytes, pub_hex: str = '') -> str:
        """SM2+SM3 签名：优先使用 data_id= 关键字（新版 gmssl），不支持则回退为单参。
        论文对照（SM9签名思想）：c = H2(…)，输出 σ；这里只是改为标准 SM2 的 (r,s)。
        """
        if user_id is None:
            user_id = SM2Suite.DEFAULT_ID
        sm2_obj = sm2.CryptSM2(private_key=priv_hex, public_key=(pub_hex or ''))
        try:
            # 新版 gmssl：支持 data_id 关键字（ZA = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)）
            return sm2_obj.sign_with_sm3(message, data_id=user_id)
        except TypeError:
            # 旧版：不支持 data_id，退化使用默认 ZA（注意：签名与验签两边都需同样处理）
            return sm2_obj.sign_with_sm3(message)

    @staticmethod
    def verify_sm3(message: bytes, sign_hex: str, pub_hex: str, user_id: bytes) -> bool:
        """SM2+SM3 验签：同上，优先 data_id=，旧版回退单参。
        论文对照（SM9验签思想）：计算 c' 并检查“验签等式”；此处由 gmssl 内部完成 SM2 验签。
        """
        if user_id is None:
            user_id = SM2Suite.DEFAULT_ID
        sm2_obj = sm2.CryptSM2(private_key=None, public_key=(pub_hex or ''))
        try:
            return sm2_obj.verify_with_sm3(sign_hex, message, data_id=user_id)
        except TypeError:
            return sm2_obj.verify_with_sm3(sign_hex, message)

# ---------------------------------------------
# 公共参数与用户密钥
# ---------------------------------------------

@dataclass
class SystemParams:
    group: PairingGroup
    P: any           # 生成元
    s: ZR            # 主密钥（仅 KGC 持有；本 Demo 为简化联调放出）
    P_pub: any       # 系统公钥 = s·P
    H: HashSuite     # 哈希族

@dataclass
class UserKeys:
    # 身份（可用于绑定/追踪；与 SM2 不强绑定）
    ID: str
    Q_ID: any        # 论文式：Q_ID = H1(ID) ∈ G1
    SK_point: any    # 论文式：SK_ID = s·Q_ID
    PK: any          # 论文式：PK（身份公钥）= Q_ID

    # SM2/SM3 密钥对（真实签名/验签用）
    sm2_priv_hex: str
    sm2_pub_hex: str

# ---------------------------------------------
# KGC：初始化 + 发放密钥
# ---------------------------------------------

class KGC:
    def __init__(self, security_param: str = 'SS512'):
        # 论文“系统初始化”对应：
        # 1) 定义椭圆曲线群 G1、G2 与双线性对 e（此处用对称群演示），群阶 q，生成元 P
        # 2) 选取主私钥 s ∈ Z_q*，计算系统公钥 P_pub = s·P
        self.group = PairingGroup(security_param)
        self.H = HashSuite(self.group)
        self.P = self.group.random(G1)          # 论文式：生成元 P
        self.s = self.group.random(ZR)          # 论文式：主密钥 s
        self.P_pub = self.s * self.P            # 论文式：P_pub = s·P

    def params(self) -> SystemParams:
        # 论文“公布系统参数”：{G1, G2(示意), e, P, P_pub, H1, H2, H3}
        # 注意：实际工程中 s 不公开；本 Demo 为便于演示装入结构体
        return SystemParams(group=self.group, P=self.P, s=self.s, P_pub=self.P_pub, H=self.H)

    def keygen(self, ID: str) -> UserKeys:
        # 论文“KeyGen（基于身份）”：
        # Q_ID = H1(ID)， SK_ID = s·Q_ID， PK = Q_ID
        Q_ID = self.H.H1(ID)
        SK_point = self.s * Q_ID
        PK = Q_ID
        # 本实现同时生成 SM2/SM3 密钥对，用于真实签名/验签
        sm2_priv_hex, sm2_pub_hex = SM2Suite.gen_keypair()
        return UserKeys(ID=ID, Q_ID=Q_ID, SK_point=SK_point, PK=PK,
                        sm2_priv_hex=sm2_priv_hex, sm2_pub_hex=sm2_pub_hex)

# ---------------------------------------------
# DEP：平台（使用真实 SM2/SM3 验签）
# ---------------------------------------------

class DEP:
    def __init__(self, params: SystemParams):
        self.params = params

    def verify_blind_signature(self, M_blinded: bytes, sigma_hex: str,
                               sm2_pub_hex: str, user_id: bytes) -> bool:
        """对盲化数据 M' 的 SM2/SM3 签名进行验证。
        论文“验证盲签名”的位置（SM9 版）：
           1) 计算挑战值 c' = H1( e(PK_dec^{r_tep}, PK) || M || ID_DO )
           2) 检查验证方程 r_dec · PK_DO ?= PK_dec^{r_tep} + c' · PK_DO
        本实现改用 SM2/SM3：由 gmssl.verify_with_sm3() 完成验签（等价承担“challenge+验证”的逻辑）。
        """
        return SM2Suite.verify_sm3(M_blinded, sigma_hex, sm2_pub_hex, user_id)

# ---------------------------------------------
# DO：数据拥有者（盲化 + 真实 SM2/SM3 签名）
# ---------------------------------------------

class DO:
    def __init__(self, params: SystemParams, keys: UserKeys):
        self.params = params
        self.keys = keys
        self._last_r: Optional[ZR] = None
        self._last_B = None

    def blind(self, M: bytes) -> Tuple[bytes, any]:
        """盲化流程（论文“数据盲化”）：
        1) 选随机数 r ∈ Z_q*；
        2) 计算盲化因子 B = r·P；                           ← 论文式：B = r·P
        3) 计算 k = H3(B)；                                  ← 论文式：k = H3(B)
        4) 计算 M' = M ⊕ k；                                 ← 论文式：M' = M ⊕ H3(B)
        返回 (M', B)。
        """
        group, P, H = self.params.group, self.params.P, self.params.H
        r = group.random(ZR)
        B = r * P
        k_bytes = H.H3(B)
        M_blinded = xor_bytes(M, k_bytes)
        self._last_r = r
        self._last_B = B
        return M_blinded, B

    def sign_blinded(self, M_blinded: bytes, user_id: bytes = None) -> str:
        """对盲化数据 M' 进行真实 SM2/SM3 签名（gmssl）。
        论文“盲签名生成（SM9版）”对应的位置：
           - 生成临时随机数 t，R = t·P；                      ← 论文式：R = t·P
           - 计算挑战值 c = H2( e(P, R) || M' || ID )；        ← 论文式：c = H2( … )
           - 计算响应值 r_dec = t + c·x (或等价结构)；         ← 论文式：r = t + c·x
           - 输出 σ = (R, r_dec)。
        本实现改用 SM2：输出 σ = (r, s) 的十六进制串，由 gmssl 封装完成。
        """
        if user_id is None:
            user_id = sm2_user_id_from_id(self.keys.ID)
        return SM2Suite.sign_sm3(
            message=M_blinded,
            priv_hex=self.keys.sm2_priv_hex,
            user_id=user_id,
            pub_hex=self.keys.sm2_pub_hex,  # 传公钥更稳妥（gmssl 构造时不传 None）
        )

    def issue_unblind_factor(self) -> ZR:
        """当前盲化方案的去盲不需要 r_inv，这里保留接口以便将来切换 SM9 盲签。
        论文里“解盲因子 r^{-1}（mod q）”会参与 BU 去盲：B' = r^{-1}·B，复原 k=H3(B')。
        这里保留 r_inv 以兼容 SM9 方案。
        """
        if self._last_r is None:
            raise ValueError("未检测到盲化记录，请先执行 blind()。")
        group = self.params.group
        return 1 / self._last_r

# ---------------------------------------------
# DU：数据使用者（去盲 + 真实 SM2/SM3 验签）
# ---------------------------------------------

class DU:
    def __init__(self, params: SystemParams):
        self.params = params

    def unblind_and_recover(self, M_blinded: bytes, B: any) -> bytes:
        """去盲（论文“DU 去盲与恢复原文”）：
        - 计算 k = H3(B)；                                     ← 论文式：k = H3(B) 或 k = H3(r^{-1}·B)
        - 恢复 M = M' ⊕ k。                                     ← 论文式：M = M' ⊕ H3(B)
        注：若采用“r^{-1}·B”的变体，请改为 H3(r_inv * B)。
        """
        k_bytes = self.params.H.H3(B)
        return xor_bytes(M_blinded, k_bytes)

    def verify_original_signature(self, dep: DEP, M_blinded: bytes,
                                  sigma_hex: str, sm2_pub_hex: str, user_id: bytes) -> bool:
        """用户侧复核：真实 SM2/SM3 验签。
        论文“验证原始数据签名（BU侧）”对应：
           - 计算 c' = H1( e(PK_dec^{r_tep}, PK) || M || ID_DO )；
           - 检查 r_dec · PK_DO ?= PK_dec^{r_tep} + c' · PK_DO。
        本实现改用 SM2：交给 gmssl.verify_with_sm3() 完成（其内部等价承担 challenge + 验证等式）。
        """
        return dep.verify_blind_signature(M_blinded, sigma_hex, sm2_pub_hex, user_id)

# ---------------------------------------------
# Demo：端到端流程
# ---------------------------------------------

def demo_flow():
    # 1) 初始化系统（论文“系统初始化”）
    #    生成：P, s, P_pub = s·P；定义 H1/H2/H3；公布系统参数（除 s 外）
    kgc = KGC('SS512')
    params = kgc.params()

    # 2) 注册 DO（论文“KeyGen”）
    #    Q_ID = H1(ID)，SK_ID = s·Q_ID，PK = Q_ID；另外生成 SM2 密钥对用于真实签名
    do_keys = kgc.keygen(ID="DO-001")
    do = DO(params, do_keys)

    # 3) 平台 & 使用者
    dep = DEP(params)
    du = DU(params)

    # 4) 盲化（论文“数据盲化”）：B = r·P，k = H3(B)，M' = M ⊕ k
    M = b"example: payload bytes of original data"
    M_blinded, B = do.blind(M)

    # 5) 对 M' 进行真实 SM2/SM3 签名（论文“盲签名生成”的位置，现改为 SM2）
    uid = sm2_user_id_from_id(do_keys.ID)
    sigma_hex = do.sign_blinded(M_blinded, user_id=uid)

    # 6) 平台验签（论文“验证盲签名”的位置，现改为 SM2 验签）
    ok_dep = dep.verify_blind_signature(M_blinded, sigma_hex, do_keys.sm2_pub_hex, user_id=uid)
    print("DEP 验证结果:", ok_dep)

    # 7) 去盲恢复（论文“DU 去盲与原文恢复”）：M = M' ⊕ H3(B)
    M_recovered = du.unblind_and_recover(M_blinded, B)
    print("恢复的数据:", M_recovered)

    # 8) 用户侧复核签名（论文“验证原始数据签名（BU侧）”，现改为 SM2 验签）
    ok_du = du.verify_original_signature(dep, M_blinded, sigma_hex, do_keys.sm2_pub_hex, user_id=uid)
    print("DU 验证结果:", ok_du)

if __name__ == "__main__":
    demo_flow()
