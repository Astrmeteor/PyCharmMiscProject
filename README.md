# PyCharmMiscProject

国密 SM9 算法与可追踪盲签名实验项目 —— 纯 Python 实现的 SM9 密码学底座，以及带「追踪/打开 + 订单门控」的盲签名原型与演示工具。

A collection of cryptographic experiments: a pure-Python implementation of the Chinese national cryptographic standard **SM9** (GB/T 38635.2-2020), plus a **traceable blind signature** prototype with order gating, demos and visualization tools.

---

## 项目简介 / Overview

本仓库包含三部分内容：

1. **SM9 国密算法纯 Python 实现**（`function/`）
   - 完整实现 SM9 底层数学：有限域 `FQ / FQ2 / FQ4 / FQ12`、椭圆曲线点运算、R-ate 双线性对、`KDF / H / MAC`；
   - 标准 SM9 签名、验签、密钥封装、加密、解密流程；
   - 使用 `hggm/SM9_kG.bin` 预计算表加速标量乘法。
2. **可追踪盲签名（Traceable Blind Signature）原型**（`function/sm9_algorithm.py` 后半部分）
   - 角色：KGC（密钥生成中心）、BDO（数据所有者/签名方）、BDEP（验签平台）、BDU（盲签名用户）；
   - 流程：消息盲化 → 点值签名 → 可复算挑战验签 → 订单门控 → 去盲校验 → 恢复原文 → KGC 打开追踪。
3. **演示与可视化工具**
   - `main_251014.py`：命令行端到端演示（支持文件 / stdin / hex / base64 输入，输出运行时性能统计）；
   - `function/sm9_ui.py`：带 Tkinter 图形界面的演示与逐步骤 trace 日志；
   - `function/sm9_trace.py`：命令行逐步跟踪（trace）版本；
   - `script.py`：基于 gmssl（SM2/SM3）+ Charm 的替代方案原型（当前整体注释保留）；
   - `blind_schnorr_implementation-main/`：第三方盲 Schnorr 签名实现。

This repository contains three parts:

1. **A pure-Python implementation of the SM9 national cryptographic standard** (`function/`)
   - Full low-level math: finite fields `FQ / FQ2 / FQ4 / FQ12`, elliptic-curve point arithmetic, R-ate bilinear pairing, `KDF / H / MAC`;
   - Standard SM9 sign / verify / key encapsulation / encryption / decryption;
   - Fast scalar multiplication accelerated by the precomputed table `hggm/SM9_kG.bin`.
2. **A traceable blind signature prototype** (second half of `function/sm9_algorithm.py`)
   - Roles: KGC (Key Generation Center), BDO (Data Owner / signer), BDEP (verification platform), BDU (blind-signature user);
   - Flow: message blinding → point-valued signing → recomputable-challenge verification → order gating → unblinding checks → original-message recovery → KGC trace opening.
3. **Demos and visualization tools**
   - `main_251014.py`: command-line end-to-end demo (file / stdin / hex / base64 input, runtime performance stats);
   - `function/sm9_ui.py`: Tkinter GUI demo with step-by-step trace logging;
   - `function/sm9_trace.py`: command-line step-by-step trace version;
   - `script.py`: an alternative prototype based on gmssl (SM2/SM3) + Charm (currently kept fully commented out);
   - `blind_schnorr_implementation-main/`: a third-party blind Schnorr signature implementation.

---

## 目录结构 / Repository Structure

```
PyCharmMiscProject/
├── function/                  # 核心密码学实现 / Core crypto implementation
│   ├── sm9_algorithm.py       # SM9 全套 + 可追踪盲签扩展（BKGC/BDO/BDEP/BDU）
│   ├── sm9.py                 # SM9 模块（另一入口）
│   ├── sm9_params.py          # SM9 标准参数 / Standard parameters
│   ├── sm3.py                 # SM3 哈希 / SM3 hash
│   ├── sm9_ui.py              # Tkinter 图形界面 + trace 演示 / GUI + trace demo
│   └── sm9_trace.py           # 命令行逐步跟踪演示 / CLI step-trace demo
├── hggm/
│   └── SM9_kG.bin             # 标量乘法预计算表 / Precomputed scalar-mul table
├── main_251014.py             # 盲签+追踪 端到端命令行演示（入口）/ End-to-end CLI demo (entry point)
├── script.py                  # SM2/SM3 + Charm 替代原型（注释保留）/ Alternative prototype (commented out)
├── blind_schnorr_implementation-main/   # 第三方盲 Schnorr 实现 / Third-party blind Schnorr implementation
├── msg.bin                    # 默认演示输入 / Default demo input
└── recovered.bin              # 去盲恢复的默认输出 / Default unblinding output
```

---

## 快速开始 / Quick Start

仅需 Python 3（`function/` 为纯 Python 实现，无第三方依赖）。Only Python 3 is required (`function/` is pure Python with no third-party dependencies).

```bash
# 端到端盲签 + 追踪演示（默认读取 msg.bin，输出 recovered.bin）
# End-to-end blind-signature + trace demo (reads msg.bin, writes recovered.bin)
python3 main_251014.py

# 自定义输入与输出 / Custom input and output
python3 main_251014.py --in mydata.bin --out result.bin

# stdin 输入 / Read from stdin
cat mydata.bin | python3 main_251014.py --in -

# hex / base64 字面量输入 / Literal hex / base64 input
python3 main_251014.py --in hex:48656c6c6f --out result.bin
python3 main_251014.py --in b64:SGVsbG8=

# 指定身份与版本 / Custom identity and version
python3 main_251014.py --id DO-001 --ver v1
```

图形界面演示（需 Tkinter）/ GUI demo (requires Tkinter):

```bash
python3 function/sm9_ui.py --gui
```

命令行动态 trace 演示 / Command-line step-trace demo:

```bash
python3 function/sm9_trace.py
```

---

## 盲签协议角色与流程 / Protocol Roles and Flow

| 角色 / Role | 说明 / Description |
| --- | --- |
| **KGC** | 生成主密钥 s，为用户发放身份点私钥 (Q_ID, d_ID) 与追踪材料 (T, A_open)；可发布 A = α·P2 进行「打开」。Generates master key s, issues identity point keys (Q_ID, d_ID) and trace material (T, A_open); publishes A = α·P2 for opening. |
| **BDO (DO)** | 数据所有者：盲化消息 M → M'，对盲化消息做点值签名 (R, S, T)；仅在平台批准后释放 r⁻¹（门控）。Data owner: blinds M → M', produces point-valued signature (R, S, T); releases r⁻¹ only after platform approval (gating). |
| **BDEP (DEP)** | 平台：对盲化消息验签（重算挑战 + 配对等式），并核验订单发放票据。Platform: verifies the blinded signature (recomputed challenge + pairing equation) and issues approval tickets for orders. |
| **BDU (DU)** | 用户：使用 r⁻¹ 去盲并做双重校验（去盲临时公钥 / 响应值配对），恢复原文；可验证 KGC 的打开凭证 e(T,P2) == e(Q_ID,A)。User: unblinds with r⁻¹, performs dual checks (unblinded ephemeral public key / response pairing), recovers the message; verifies the KGC opening e(T,P2) == e(Q_ID,A). |

核心流程 / Core flow:

```
KGC.enroll(ID) ──► (Q_ID, d_ID, T, A_open)
BDO.blind(M)   ──► M' = M ⊕ H3(B)，B = j·Q_ID + h·P1
BDO.sign_blinded(M') ──► (R, S, T)，挑战 c = H(2, M'‖ID‖ver‖e(R,P2)‖T)
BDEP.verify_blinded ──► e(S,P2) == e(R,P2) · e(Q_ID,Ppub_s)^c
BDEP.verify_order ──► ticket；BDO.release_r_inv(ticket) ──► r⁻¹
BDU.unblind_and_verify ──► 去盲校验 + 恢复原文
KGC.open_trace(ID) ──► A_open；BDU.verify_opening ──► e(T,P2) == e(Q_ID,A)
```

---

## 注意事项 / Notes

- 本项目为**教学与原型用途**，未做工程化加固（如随机数使用 Python 内置随机源、无侧信道防护、异常处理较简），请勿直接用于生产环境。
  This project is for **educational and prototyping purposes** only. It is not hardened for production (e.g. uses Python's built-in randomness, no side-channel protections, minimal exception handling). Do not use it in production as-is.
- `script.py` 依赖 `gmssl` 与 `charm-crypto`；`function/` 部分无第三方依赖。`script.py` requires `gmssl` and `charm-crypto`; the `function/` package has no third-party dependencies.
- `blind_schnorr_implementation-main/` 为第三方代码，版权归原作者所有。`blind_schnorr_implementation-main/` is third-party code; all rights belong to its original authors.

---

## 许可 / License

本仓库未指定许可证。No license is specified in this repository.
