# from array import array
#
# Tj_rl = array('L', ((0x79cc4519 << j | 0x79cc4519 >> 32 - j) & 0xffffffff for j in range(16)))
# Tj_rl.extend((0x7a879d8a << (j & 31) | 0x7a879d8a >> (32 - j & 31)) & 0xffffffff for j in range(16, 64))
# V0 = array('L', [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e])
#
#
# def CF(V, B):
#     W = array('L', B)
#     for j in range(16, 68):
#         X = W[j - 16] ^ W[j - 9] ^ (W[j - 3] << 15 | W[j - 3] >> 17) & 0xffffffff
#         W.append(
#             (X ^ (X << 15 | X >> 17) ^ (X << 23 | X >> 9) ^ (W[j - 13] << 7 | W[j - 13] >> 25) ^ W[j - 6]) & 0xffffffff)
#     W_ = array('L', (W[j] ^ W[j + 4] for j in range(64)))
#     A, B, C, D, E, F, G, H = V
#     for j in range(64):
#         A_rl12 = A << 12 | A >> 20
#         tmp = (A_rl12 + E + Tj_rl[j]) & 0xffffffff
#         SS1 = (tmp << 7 | tmp >> 25)
#         SS2 = SS1 ^ A_rl12
#         if j & 0x30:  # 16 <= j
#             FF, GG = A & B | A & C | B & C, E & F | ~E & G
#         else:
#             FF, GG = A ^ B ^ C, E ^ F ^ G
#         TT1, TT2 = (FF + D + SS2 + W_[j]) & 0xffffffff, (GG + H + SS1 + W[j]) & 0xffffffff
#         C, D, G, H = (B << 9 | B >> 23) & 0xffffffff, C, (F << 19 | F >> 13) & 0xffffffff, G
#         A, B, E, F = TT1, A, (TT2 ^ (TT2 << 9 | TT2 >> 23) ^ (TT2 << 17 | TT2 >> 15)) & 0xffffffff, E
#     return A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3], E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]
#
#
# def digest(data):
#     # 填充
#     pad_num = 64 - (len(data) + 1 & 0x3f)
#     data += b'\x80' + (len(data) << 3).to_bytes(pad_num if pad_num >= 8 else pad_num + 64, 'big')
#     V, B = V0, array('L', data)
#     B.byteswap()
#     # 迭代压缩
#     for i in range(0, len(B), 16):
#         V = CF(V, B[i:i + 16])
#     V = array('L', V)
#     V.byteswap()
#     return V.tobytes()
from array import array
import sys

# 统一的 32 位循环左移
def rotl32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

# P0 与 P1
def P0(x): return (x ^ rotl32(x, 9) ^ rotl32(x, 17)) & 0xffffffff
def P1(x): return (x ^ rotl32(x, 15) ^ rotl32(x, 23)) & 0xffffffff

# 预计算 Tj 左移
Tj_rl = [rotl32(0x79cc4519, j) for j in range(16)] + [rotl32(0x7a879d8a, j) for j in range(16, 64)]

# 初始向量统一用 32 位
V0 = array('I', [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e])

def CF(V, B_words):
    # B_words 必须是 16 个 32 位大端字（array('I')）
    W = array('I', B_words)  # 拷贝
    for j in range(16, 68):
        X = (W[j-16] ^ W[j-9] ^ rotl32(W[j-3], 15)) & 0xffffffff
        W.append((P1(X) ^ rotl32(W[j-13], 7) ^ W[j-6]) & 0xffffffff)
    W_ = array('I', (W[j] ^ W[j+4] for j in range(64)))

    A, B, C, D, E, F, G, H = V
    for j in range(64):
        A_rl12 = rotl32(A, 12)
        tmp    = (A_rl12 + E + Tj_rl[j]) & 0xffffffff
        SS1    = rotl32(tmp, 7)
        SS2    = (SS1 ^ A_rl12) & 0xffffffff

        if j >= 16:  # ←← 修正：不能用 j & 0x30
            FF = (A & B) | (A & C) | (B & C)
            GG = (E & F) | ((~E) & G)
        else:
            FF = (A ^ B ^ C) & 0xffffffff
            GG = (E ^ F ^ G) & 0xffffffff

        TT1 = (FF + D + SS2 + W_[j]) & 0xffffffff
        TT2 = (GG + H + SS1 + W[j]) & 0xffffffff

        D = C
        C = rotl32(B, 9)
        B = A
        H = G
        G = rotl32(F, 19)
        F = E
        E = P0(TT2)
        A = TT1

    return ((A ^ V[0]) & 0xffffffff,
            (B ^ V[1]) & 0xffffffff,
            (C ^ V[2]) & 0xffffffff,
            (D ^ V[3]) & 0xffffffff,
            (E ^ V[4]) & 0xffffffff,
            (F ^ V[5]) & 0xffffffff,
            (G ^ V[6]) & 0xffffffff,
            (H ^ V[7]) & 0xffffffff)

def digest(data: bytes) -> bytes:
    # 标准 SHA/SM3 填充：消息||0x80||0x00...||len(64bit big-endian)
    bitlen = (len(data) * 8) & ((1 << 64) - 1)
    pad_zero_len = (56 - (len(data) + 1) % 64) % 64
    data = data + b'\x80' + (b'\x00' * pad_zero_len) + bitlen.to_bytes(8, 'big')

    V = V0
    for i in range(0, len(data), 64):
        block = data[i:i+64]  # 64 字节
        # 将 64 字节按大端解析为 16 个 32 位字
        W = array('I')
        W.frombytes(block)  # native endian
        if sys.byteorder != 'big':
            W.byteswap()
        V = CF(V, W)

    out = array('I', V)
    if sys.byteorder != 'big':
        out.byteswap()
    return out.tobytes()


from Cryptodome.Hash import MD5, SHA3_256
from pysmx.SM3 import digest as SM3_pysmx
from gmssl.sm3 import sm3_hash
import time, os


def SM3_gmssl(data: bytes) -> bytes:
    return bytes.fromhex(sm3_hash([i for i in data]))


def SM3_my(data: bytes) -> bytes:
    return digest(data)


def sm3_compare_test():
    print('—————————————————————首次Hash测试—————————————————————')
    # 随机生成消息
    long_data = os.urandom(128)

    print('消息长度：%dB  单位：μs' % (len(long_data)))
    print('算法库名\t\t\t首次Hash\t\t再次Hash')
    # Crypto - MD5
    time_1 = time.perf_counter()
    MD5.new(long_data).digest()
    time_2 = time.perf_counter()
    MD5.new(long_data).digest()
    time_3 = time.perf_counter()
    print('Crypto-MD5\t\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    # Crypto - SHA256
    time_1 = time.perf_counter()
    SHA3_256.new(long_data).digest()
    time_2 = time.perf_counter()
    SHA3_256.new(long_data).digest()
    time_3 = time.perf_counter()
    print('Crypto-SHA256\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    # gmssl - SM3
    time_1 = time.perf_counter()
    SM3_gmssl(long_data)
    time_2 = time.perf_counter()
    hash2 = SM3_gmssl(long_data)
    time_3 = time.perf_counter()
    print('gmssl-SM3\t\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    # pysmx - SM3
    time_1 = time.perf_counter()
    SM3_pysmx(long_data)
    time_2 = time.perf_counter()
    hash1 = SM3_pysmx(long_data)
    time_3 = time.perf_counter()
    print('pysmx-SM3\t\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    assert hash1 == hash2
    # my - SM3
    time_1 = time.perf_counter()
    SM3_my(long_data)
    time_2 = time.perf_counter()
    hash2 = SM3_my(long_data)
    time_3 = time.perf_counter()
    print('my-SM3\t\t\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    assert hash1 == hash2

    print('\n—————————————————————连续Hash测试—————————————————————')
    test_num = 100  # 测试次数
    # 随机生成消息
    short_data = [os.urandom(28) for i in range(test_num)]  # 短消息列表
    long_data = [os.urandom(1128) for i in range(test_num)]  # 长消息列表
    hash_data = [b''] * test_num
    hash_data1 = [b''] * test_num
    hash_data2 = [b''] * test_num
    hash_data3 = [b''] * test_num
    hash_data4 = [b''] * test_num

    print('短消息长度：%dB  长消息长度：%dB  测试次数：%d  单位：ms' % (len(short_data[0]), len(long_data[0]), test_num))
    print('算法库名\t\t\t短消息Hash\t长消息Hash')

    # Crypto - MD5
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data[i] = MD5.new(short_data[i]).digest()  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data[i] = MD5.new(long_data[i]).digest()  # 长消息Hash
    time_3 = time.perf_counter()
    print('Crypto-MD5\t\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))

    # Crypto - SHA256
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data[i] = SHA3_256.new(short_data[i]).digest()  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data[i] = SHA3_256.new(long_data[i]).digest()  # 长消息Hash
    time_3 = time.perf_counter()
    print('Crypto-SHA256\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))

    # gmssl - SM3
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data1[i] = SM3_gmssl(short_data[i])  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data2[i] = SM3_gmssl(long_data[i])  # 长消息Hash
    time_3 = time.perf_counter()
    print('gmssl-SM3\t\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))
    time_aim1 = time_3 - time_1

    # pysmx - SM3
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data3[i] = SM3_pysmx(short_data[i])  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data4[i] = SM3_pysmx(long_data[i])  # 长消息Hash
    time_3 = time.perf_counter()
    print('pysmx-SM3\t\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))
    time_aim2 = time_3 - time_1
    assert hash_data1 == hash_data3 and hash_data2 == hash_data4

    # my - SM3
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data1[i] = SM3_my(short_data[i])  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data2[i] = SM3_my(long_data[i])  # 长消息Hash
    time_3 = time.perf_counter()
    print('my-SM3\t\t\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))
    time_my = time_3 - time_1
    print('总耗时为pysmx的%.2f%%、gmssl的%.2f%%' % (time_my / time_aim2 * 100, time_my / time_aim1 * 100))
    assert hash_data1 == hash_data3 and hash_data2 == hash_data4


if __name__ == "__main__":
    sm3_compare_test()