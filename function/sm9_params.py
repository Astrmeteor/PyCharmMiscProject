# SM9总则(GB_T 38635.1-2020) A.1 系统参数
q = 0XB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D  # 基域特征
N = 0XB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25  # 群的阶
# 群G1的生成元 P1=(x_p1, y_p1)
x_p1 = 0X93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
y_p1 = 0X21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
# 群G2的生成元 P2=(x_p2, y_p2)
x_p2 = (0X85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141,
        0X3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B)
y_p2 = (0X17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96,
        0XA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7)

# 常量定义
HASH_SIZE = 32  # sm3输出256位（32字节）
N_SIZE = 32  # 阶的字节数
KEY_LEN = 128  # 默认密钥位数
K2_len = 256  # MAC函数中密钥K2的位数
hlen = 320  # 8 * ceil(5 * log(N, 2) / 32)

# 曲线常数与 Frobenius 常数
_b1, _b2 = 5, (0, 5)  # b2=βb=(1,0)*5
alpha1 = 0X3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B  # -2^((q - 1)/12)
alpha2 = 0XF300000002A3A6F2780272354F8B78F4D5FC11967BE65334  # -2^((q - 1)/6)
alpha3 = 0X6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D011  # -2^((q - 1)/4)
alpha4 = 0XF300000002A3A6F2780272354F8B78F4D5FC11967BE65333  # -2^((q - 1)/3)
alpha5 = 0X2D40A38CF6983351711E5F99520347CC57D778A9F8FF4C8A4C949C7FA2A96686
_2_inv = 0X5B2000000151D378EB01D5A7FAC763A290F949A58D3D776DF2B7CD93F1A8A2BF  # 1/2
_3div2 = 0X5B2000000151D378EB01D5A7FAC763A290F949A58D3D776DF2B7CD93F1A8A2C0  # 3/2

# 非相邻表示（2-NAF）
R_ate_a_NAF = '0100000000000000000000000000000000000010001020200020200101000020'  # a=6t+2的二进制非相邻表示(2-NAF)

# 预计算的模数
_t, _6t, _6t_3 = 0x600000000058F98A, 0X2400000000215D93C, 0X2400000000215D93F


from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR

# 你的“不可随机”的参数（原样保留，仅做占位/记录）
SM9_FIXED = {
    "q":  "0XB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D",
    "N":  "0XB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25",
    "HASH_SIZE": 32,
    "N_SIZE": 32,
    "KEY_LEN": 128,
    "K2_len": 256,
    "hlen": 320,
}

def gen_random_generators(param='SS512'):
    """
    在指定的双线性群参数下随机生成 G1/G2 的生成元。
    param 可选：'SS512', 'BN254' 等；与 SM9 推荐域不同，仅用于实验。
    """
    group = PairingGroup(param)
    r = group.order()

    one_g1 = group.init(G1, 1)
    one_g2 = group.init(G2, 1)

    # 从 G1/G2 随机取非单位元；在素数阶群里，非单位元就是生成元
    g1 = group.random(G1)
    while g1 == one_g1:
        g1 = group.random(G1)
    g2 = group.random(G2)
    while g2 == one_g2:
        g2 = group.random(G2)

    # 可选：再用随机标量“重映射”一次，仍为生成元
    t1 = group.random(ZR)
    t2 = group.random(ZR)
    P1 = g1 ** t1
    P2 = g2 ** t2

    # 一些健全性检查：g^r == 1
    assert P1 ** r == one_g1
    assert P2 ** r == one_g2

    def to_hex_bytes(elem):
        return group.serialize(elem).hex()

    print("随机生成的 P1 (G1) =", to_hex_bytes(P1))
    print("随机生成的 P2 (G2) =", to_hex_bytes(P2))
    return {
        **SM9_FIXED,
        "PAIRING_PARAM": param,
        "P1_bytes_hex": to_hex_bytes(P1),
        "P2_bytes_hex": to_hex_bytes(P2),
    }

if __name__ == "__main__":
    params = gen_random_generators("BN254")   # 或者 "BN254"
    # # 这里你可以把 params 保存成 JSON，供你的程序使用
    # # import json; open('my_params.json','w').write(json.dumps(params, indent=2))
