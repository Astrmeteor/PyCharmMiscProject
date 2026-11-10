# sm9_algorithm.py
import os
from random import randrange
from math import ceil
from function.sm3 import digest as sm3
from function.sm9_params import _6t,_t,_6t_3
from function.sm9_params import q, N, x_p1, y_p1, x_p2, y_p2, HASH_SIZE, N_SIZE, KEY_LEN, K2_len, _b1, _b2, alpha1, alpha2, alpha3, alpha4, alpha5, _2_inv, _3div2, R_ate_a_NAF, hlen

def to_byte(x, size=None):
    if type(x) is int:
        return x.to_bytes(size if size else ceil(x.bit_length() / 8), byteorder='big')
    elif type(x) in (str, bytes):
        x = x.encode() if type(x) is str else x
        return x[:size] if size and len(x) > size else x  # 超过指定长度，则截取左侧字符
    elif type(x) in (tuple, list):
        return b''.join(to_byte(c, size) for c in x)
    return bytes(x)[:size] if size else bytes(x)


# 将字节转换为int
def to_int(byte):
    return int.from_bytes(byte, byteorder='big')


# 广义的欧几里得除法求模逆（耗时约为slow/SM2代码内get_inverse函数的43%）
def mod_inv(a, mod=q):
    if a == 0:
        return 0
    lm, low, hm, high = 1, a % mod, 0, mod
    while low > 1:
        r = high // low
        lm, low, hm, high = hm - lm * r, high - low * r, lm, low
    return lm % mod


class FQ:
    def __init__(self, n):
        self.n = n

    def __add__(self, other):
        return FQ(self.n + other.n)

    def __sub__(self, other):
        return FQ(self.n - other.n)

    def __mul__(self, other):  # 右操作数可为int
        return FQ(self.n * (other.n if type(other) is FQ else other) % q)

    def __truediv__(self, other):  # 右操作数可为int
        return FQ(self.n * mod_inv(other.n if type(other) is FQ else other) % q)

    def __pow__(self, other):  # 操作数应为int
        return FQ(pow(self.n, other, q) if other else 1)

    def __eq__(self, other):  # 右操作数可为int
        return self.n % q == (other.n if type(other) is FQ else other) % q

    def __neg__(self):
        return FQ(-self.n)

    def __repr__(self):
        return 'FQ(%064X)' % (self.n % q)

    def __bytes__(self):
        return to_byte(self.n % q, N_SIZE)

    def is_zero(self):
        return self.n % q == 0

    def inv(self):
        return FQ(mod_inv(self.n))

    def sqr(self):
        return FQ(self.n * self.n % q)

    @classmethod
    def one(cls):
        return cls(1)

    @classmethod
    def zero(cls):
        return cls(0)


class FQ2:
    def __init__(self, *coeffs):  # 国标中的表示是高位在前，而此处coeffs是低位在前
        self.coeffs = coeffs

    def __add__(self, other):
        (a0, a1), (b0, b1) = self.coeffs, other.coeffs
        return FQ2(a0 + b0, a1 + b1)

    def __sub__(self, other):
        (a0, a1), (b0, b1) = self.coeffs, other.coeffs
        return FQ2(a0 - b0, a1 - b1)

    def sqr(self):
        a0, a1 = self.coeffs
        return FQ2((a0 * a0 - (a1 * a1 << 1)) % q, (a0 * a1 << 1) % q)  # (a0^2 - 2 * a1^2, 2 * a0 * a1)

    def sqr_u(self):
        a0, a1 = self.coeffs
        return FQ2(-(a0 * a1 << 2) % q, (a0 * a0 - (a1 * a1 << 1)) % q)  # (-4 * a0 * a1, a0^2 - 2 * a1^2)

    def mul_b_u(self, b):  # 带参数乘法
        (a0, a1), (b0, b1) = self.coeffs, b.coeffs
        return FQ2(-(a0 * b1 + a1 * b0 << 1) % q, (a0 * b0 - (a1 * b1 << 1)) % q)  # (-2*(a0*b1+a1*b0), a0*b0-2*a1*b1)

    def __mul__(self, other):
        if type(other) is int:
            a0, a1 = self.coeffs
            return FQ2(a0 << 1, a1 << 1) if other == 2 else FQ2(a0 * other % q, a1 * other % q)
        (a0, a1), (b0, b1) = self.coeffs, other.coeffs
        a0b0, a1b1 = a0 * b0, a1 * b1  # Karatsuba 思想方法（节约一次乘法），实测此处约有5%提升，用在其他地方未见性能提升
        return FQ2((a0b0 - (a1b1 << 1)) % q, ((a0 + a1) * (b0 + b1) - (a0b0 + a1b1)) % q)  # (a0*b0-2*a1*b1,a0*b1+a1*b0)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        if type(other) is int:
            other_inv = mod_inv(other)
            return FQ2([c * other_inv % q for c in self.coeffs])
        return self * other.inv()

    def inv(self):
        a0, a1 = self.coeffs
        if a0 == 0:
            return FQ2(0, -mod_inv(a1 << 1))  # (0, -(2 * a1)^-1)
        if a1 == 0:
            return FQ2(mod_inv(a0), 0)  # (a0^-1, 0)
        k = mod_inv(a0 * a0 + (a1 * a1 << 1))  # k = (a0^2 + 2 * a1^2)^-1
        return FQ2(a0 * k % q, -a1 * k % q)  # (a0 * k, -a1 * k)

    def conjugate(self):  # 共轭
        a0, a1 = self.coeffs
        return self.__class__(a0, -a1)

    def get_fp_list(self):  # 返回所有基域元素（高位在前）
        if type(self) is FQ2:
            return [i % q for i in self[::-1]]
        return [y for x in self[::-1] for y in x.get_fp_list()] if self.coeffs else [0] * 4  # 注意FQ4对象零值的处理

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ', '.join('%064X' % i for i in self.get_fp_list()))

    def __bytes__(self):  # 字节串高位在前
        return to_byte(self.get_fp_list(), N_SIZE)

    def __eq__(self, other):
        return self.get_fp_list() == other.get_fp_list()

    def __neg__(self):
        return self.__class__(*[-c for c in self.coeffs])

    def __getitem__(self, item):
        return self.coeffs[item]

    def is_zero(self):
        return all(c % q == 0 for c in self.coeffs) if type(self) is FQ2 else all(c.is_zero() for c in self.coeffs)

    @classmethod
    def one(cls):
        return FQ2_one if cls is FQ2 else (FQ12_one if cls is FQ12 else FQ4_one)

    @classmethod
    def zero(cls):
        return FQ2_zero if cls is FQ2 else ()

# leibeizhu
class FQ4(FQ2):  # 零元的coeffs为空，可优化FQ12稀疏乘法运算
    def __add__(self, other):
        if not self.coeffs:
            return other
        if not other.coeffs:
            return self
        (a0, a1), (b0, b1) = self.coeffs, other.coeffs
        return FQ4(a0 + b0, a1 + b1)

    def __sub__(self, other):
        if not self.coeffs:
            return -other
        if not other.coeffs:
            return self
        (a0, a1), (b0, b1) = self.coeffs, other.coeffs
        return FQ4(a0 - b0, a1 - b1)

    def sqr(self):
        if not self.coeffs:
            return FQ4_zero
        a0, a1 = self.coeffs
        return FQ4(a0.sqr() + a1.sqr_u(), a0 * a1 * 2)  # (a0^2 + a1^2 * u, 2 * a0 * a1)

    def sqr_v(self):
        if not self.coeffs:
            return FQ4_zero
        a0, a1 = self.coeffs
        return FQ4(a0.mul_b_u(a1) * 2, a0.sqr() + a1.sqr_u())  # (2 * a0 * a1 * u, a0^2 + a1^2 * u)

    def mul_b_v(self, b):  # 带参数乘法
        if not self.coeffs or not b.coeffs:
            return FQ4_zero
        (a0, a1), (b0, b1) = self.coeffs, b.coeffs
        return FQ4(a0.mul_b_u(b1) + a1.mul_b_u(b0), a0 * b0 + a1.mul_b_u(b1))  # (a0*b1*u+a1*b0*u, a0*b0+a1*b1*u)

    def __mul__(self, other):
        if not self.coeffs:
            return FQ4_zero
        if type(other) is int:
            a0, a1 = self.coeffs
            return FQ4(a0 * other, a1 * other)
        if not other.coeffs:
            return FQ4_zero
        (a0, a1), (b0, b1) = self.coeffs, other.coeffs
        return FQ4(a0 * b0 + a1.mul_b_u(b1), a0 * b1 + a1 * b0)  # (a0*b0+a1*b1*u, a0*b1+a1*b0)

    def inv(self):
        if not self.coeffs:
            return FQ4_zero
        a0, a1 = self.coeffs
        k = (a1.sqr_u() - a0.sqr()).inv()
        return FQ4((-a0 * k), a1 * k)


class FQ12(FQ2):
    def __add__(self, other):
        (a0, a1, a2), (b0, b1, b2) = self.coeffs, other.coeffs
        return FQ12(a0 + b0, a1 + b1, a2 + b2)

    def __sub__(self, other):
        (a0, a1, a2), (b0, b1, b2) = self.coeffs, other.coeffs
        return FQ12(a0 - b0, a1 - b1, a2 - b2)

    def sqr(self):
        a0, a1, a2 = self.coeffs
        return FQ12(a0.sqr() + a1.mul_b_v(a2) * 2, a0 * a1 * 2 + a2.sqr_v(), a0 * a2 * 2 + a1.sqr())

    def __mul__(self, other):
        (a0, a1, a2), (b0, b1, b2) = self.coeffs, other.coeffs
        return FQ12(a0 * b0 + a1.mul_b_v(b2) + a2.mul_b_v(b1), a0 * b1 + a1 * b0 + a2.mul_b_v(b2),
                    a0 * b2 + a1 * b1 + a2 * b0)

    def sqr2(self):  # 分圆循环子群Gϕ6(Fp2)中的元素平方
        a, b, c = self.coeffs
        a2, b2, c2v = a.sqr(), b.sqr(), c.sqr_v()
        return FQ12(a2 + (a2 - a.conjugate()) * 2, c2v + (c2v + b.conjugate()) * 2, b2 + (b2 - c.conjugate()) * 2)

    def __pow__(self, other):  # 实际运行此函数的对象都是分圆循环子群Gϕ6(Fp2)中的元素
        if other > 10:  # 加减法
            h, k = bin(3 * other)[2:], bin(other)[2:]
            k, t, nf = '0' * (len(h) - len(k)) + k, self, self.frobenius6()
            for i in range(1, len(h) - 1):
                t = t.sqr2()
                if h[i] == '1' and k[i] == '0':
                    t = t * self
                elif h[i] == '0' and k[i] == '1':
                    t = t * nf
        else:
            t = self
            for ri in bin(other)[3:]:
                t = t.sqr2() * self if ri == '1' else t.sqr2()
        return t

    def inv(self):
        a0, a1, a2 = self.coeffs
        a0_2, a1_2 = a0.sqr(), a1.sqr()
        if a2.is_zero():
            k = (a0 * a0_2 + a1.mul_b_v(a1_2)).inv()
            return FQ12(a0_2 * k, (-a0 * a1 * k), a1_2 * k)
        t0, t1, t2 = a1_2 - a0 * a2, a0 * a1 - a2.sqr_v(), a0_2 - a1.mul_b_v(a2)
        t3 = a2 * (t1.sqr() - t0 * t2).inv()
        return FQ12(t2 * t3, (-t1 * t3), t0 * t3)

    def frobenius(self):
        (a0, a1), (b0, b1), (c0, c1) = self.coeffs
        a = FQ4(a0.conjugate(), a1.conjugate() * alpha3)
        b = FQ4(b0.conjugate() * alpha1, b1.conjugate() * alpha4)
        return FQ12(a, b, FQ4(c0.conjugate() * alpha2, c1.conjugate() * alpha5))

    def frobenius2(self):
        a, b, c = self.coeffs
        return FQ12(a.conjugate(), b.conjugate() * alpha2, c.conjugate() * alpha4)

    def frobenius3(self):
        (a0, a1), (b0, b1), (c0, c1) = self.coeffs
        a = FQ4(a0.conjugate(), -a1.conjugate() * alpha3)
        b = FQ4(b0.conjugate() * alpha3, b1.conjugate())
        c = FQ4(-c0.conjugate(), c1.conjugate() * alpha3)
        return FQ12(a, b, c)

    def frobenius6(self):
        a, b, c = self.coeffs
        return FQ12(a.conjugate(), -b.conjugate(), c.conjugate())


class ECC_Point:
    def __init__(self, *pt):  # 采用Jacobian射影坐标计算，输入仿射坐标后会转换为Jacobian射影坐标
        self.pt = pt if len(pt) == 3 else (*pt, pt[0].one())

    @classmethod
    def from_byte(cls, byte):  # 输入bytes类型仿射坐标，构建点对象
        fp_num = len(byte) // (N_SIZE << 1)  # 单个坐标包含的域元素个数
        if fp_num in (1, 2) and len(byte) % N_SIZE == 0:
            fp_list = [to_int(byte[i:i + N_SIZE]) for i in range(0, len(byte), N_SIZE)]  # 将bytes转换为域元素列表
            if fp_num == 1:
                return cls(FQ(fp_list[0]), FQ(fp_list[1]))
            x_list, y_list = fp_list[fp_num - 1::-1], fp_list[:fp_num - 1:-1]  # 从bytes到FQ2对象保存的域元素，需翻转高低位顺序
            return cls(FQ2(*x_list), FQ2(*y_list))
        return False

    def is_inf(self):
        return self[2].is_zero()

    def is_on_curve(self):  # 检查点是否满足曲线方程 y^2 == x^3 + b
        x, y, z = self.pt
        return y ** 2 == x ** 3 + (_b1 if type(x) is FQ else _b2) * z ** 6

    def double(self):
        x, y, z = self.pt
        _3x2, _2y = x.sqr() * 3, y * 2
        _4y2 = _2y.sqr()
        _4xy2 = x * _4y2
        x3 = _3x2.sqr() - _4xy2 * 2
        return ECC_Point(x3, _3x2 * (_4xy2 - x3) - _4y2.sqr() * _2_inv, _2y * z)

    def zero(self):
        cls = self[0].__class__
        return ECC_Point(cls.one(), cls.one(), cls.zero())

    def __sub__(self, p2):
        # 点减法等价于加上对方的相反元
        return self.__add__(-p2)


    def __add__(self, p2):
        if self.is_inf():
            return p2
        if p2.is_inf():
            return self
        (x1, y1, z1), (x2, y2, z2) = self.pt, p2.pt
        z1_2, z2_2 = z1.sqr(), z2.sqr()
        T1, T2 = x1 * z2_2, x2 * z1_2
        T3, T4, T5 = T1 - T2, y1 * z2_2 * z2, y2 * z1_2 * z1
        T6, T7, T3_2 = T4 - T5, T1 + T2, T3.sqr()
        T8, T9 = T4 + T5, T7 * T3_2
        x3 = T6.sqr() - T9
        T10 = T9 - x3 * 2
        y3 = (T10 * T6 - T8 * T3_2 * T3) * _2_inv
        z3 = z1 * z2 * T3
        return ECC_Point(x3, y3, z3)

    def multiply(self, n):  # 算法一：二进制展开法
        if n in (0, 1):
            return self if n else self.zero()
        Q = self
        for i in bin(n)[3:]:
            Q = Q.double() + self if i == '1' else Q.double()
        return Q

    def __mul__(self, n):  # 算法三：滑动窗法
        k = bin(n)[2:]
        l, r = len(k), 5  # 滑动窗口为5效果较好
        if r >= l:  # 如果窗口大于k的二进制位数，则本算法无意义
            return self.multiply(n)
        P_ = {1: self, 2: self.double()}  # 保存P[j]值的字典
        for i in range(1, 1 << (r - 1)):
            P_[(i << 1) + 1] = P_[(i << 1) - 1] + P_[2]
        t = r
        while k[t - 1] != '1':
            t -= 1
        hj = int(k[:t], 2)
        Q, j = P_[hj], t
        while j < l:
            if k[j] == '0':
                Q = Q.double()
                j += 1
            else:
                t = min(r, l - j)
                while k[j + t - 1] != '1':
                    t -= 1
                hj = int(k[j:j + t], 2)
                Q = Q.multiply(1 << t) + P_[hj]
                j += t
        return Q

    def __rmul__(self, n):
        return self.__mul__(n)

    def __eq__(self, p2):
        (x1, y1, z1), (x2, y2, z2) = self.pt, p2.pt
        z1_2, z2_2 = z1.sqr(), z2.sqr()
        return x1 * z2_2 == x2 * z1_2 and y1 * z2_2 * z2 == y2 * z1_2 * z1

    def __neg__(self):
        x, y, z = self.pt
        return ECC_Point(x, -y, z)

    def __getitem__(self, item):
        return self.pt[item]

    def __repr__(self):
        return '%s%s' % (self.__class__.__name__, self.normalize())

    def __bytes__(self):
        return to_byte(self.normalize(), N_SIZE if type(self[0]) is FQ else None)

    def normalize(self):
        x, y, z = self.pt
        if not hasattr(self, 'normalize_tuple'):
            if z != z.one():
                z_inv = z.inv()
                z_inv_2 = z_inv.sqr()
                x, y = x * z_inv_2, y * z_inv_2 * z_inv
            self.normalize_tuple = (x.n, y.n) if type(x) is FQ else (x, y)
        return self.normalize_tuple

    def frobenius(self):
        x, y, z = self.pt
        return ECC_Point(x.conjugate(), y.conjugate(), z.conjugate() * alpha1)

    def frobenius2_neg(self):
        x, y, z = self.pt
        return ECC_Point(x, -y, z * alpha2)


FQ2_one, FQ2_zero = FQ2(1, 0), FQ2(0, 0)  # FQ2单位元、零元
FQ4_one, FQ4_zero = FQ4(FQ2_one, FQ2_zero), FQ4()  # FQ4单位元、零元
FQ12_one = FQ12(FQ4_one, FQ4_zero, FQ4_zero)  # FQ12单位元

P1 = ECC_Point(FQ(x_p1), FQ(y_p1))  # 群G1的生成元

P2 = ECC_Point(FQ2(*x_p2[::-1]), FQ2(*y_p2[::-1]))  # 群G2的生成元

_b1, _b2 = FQ(5), FQ2(0, 5)  # b2=βb=(1,0)*5



# 输入系数值和点P，求线函数值
def g_value(a_tuple, P):
    (a0, a1, a4), (xP, yP) = a_tuple, P
    return FQ12(FQ4(a0, a1 * yP), FQ4_zero, FQ4(a4 * xP, FQ2_zero))


# 获取线函数g T,Q(P)的系数值（分母在最终模幂时值为1，可消去）(T:zhuizong Q_ID)
def get_g_a_tuple(T, Q):
    (xT, yT, zT), (xQ, yQ, zQ) = T, Q
    zT_2, zQ_2 = zT.sqr(), zQ.sqr()
    zQ_3, t1 = zQ * zQ_2, (xT * zQ_2 - xQ * zT_2) * zT * zQ
    a1, t2 = t1 * zQ_3, (yT * zQ_3 - yQ * zT * zT_2) * zQ
    a0, a4 = t1 * yQ - t2 * xQ, t2 * zQ_2
    return a0, a1, a4


# 线函数g T,Q(P)，求过点T和Q的直线在P上的值
def g(T, Q, nP):
    return g_value(get_g_a_tuple(T, Q), nP)


# 获取线函数g T,T(P)的系数值（分母在最终模幂时值为1，可消去），利用中间值完成倍点计算
def get_g2_a_tuple(T):
    x, y, z = T
    _z2, _3x2, _2y = z.sqr(), x.sqr() * 3, y * 2
    _4y2, _2yz = _2y.sqr(), _2y * z
    a1, a0, a4, _4xy2 = _z2 * _2yz, _4y2 * _2_inv - _3x2 * x, _3x2 * _z2, x * _4y2
    x3 = _3x2.sqr() - _4xy2 * 2
    y3 = _3x2 * (_4xy2 - x3) - _4y2.sqr() * _2_inv
    return (a0, a1, a4), ECC_Point(x3, y3, _2yz)


# 线函数g T,T(P)，求过点T的切线在P上的值，利用中间值完成倍点计算
def g2(T, nP):
    a_tuple, double_T = get_g2_a_tuple(T)
    return g_value(a_tuple, nP), double_T


# BN曲线上R_ate对的计算
def e(P, Q):
    nQ, nP_xy = -Q, (-P).normalize()
    f, T = g2(Q, nP_xy)
    for ai in R_ate_a_NAF:
        new_g, T = g2(T, nP_xy)
        f = f.sqr() * new_g
        if ai == '1':
            f, T = f * g(T, Q, nP_xy), T + Q
        elif ai == '2':  # 用2代替-1
            f, T = f * g(T, nQ, nP_xy), T + nQ
    Q1, nQ2 = Q.frobenius(), Q.frobenius2_neg()
    return final_exp(f * g(T, Q1, nP_xy) * g(T + Q1, nQ2, nP_xy))


# 最终模幂
def final_exp(f):
    m = f.frobenius6() * f.inv()  # f^(p^6 - 1)
    s = m.frobenius2() * m  # m^(p^2 + 1)
    # 困难部分 s^(p^3 + (6t^2+1)p^2 + (-36t^3-18t^2-12t+1)p + (-36t^3-30t^2-18t-2))
    s_6t = s ** _6t
    s_6t2 = s_6t ** _t
    s_36t3_18t2_12t, a2 = s_6t2 ** _6t_3 * s_6t.sqr2(), s_6t2 * s
    a1, a0 = s_36t3_18t2_12t.frobenius6() * s, (s_36t3_18t2_12t * s_6t * a2.sqr2()).frobenius6()
    return s.frobenius3() * a2.frobenius2() * a1.frobenius() * a0


# 获取线函数的系数值序列
def get_a_list(Q):
    a_tuple, T = get_g2_a_tuple(Q)
    a_list, nQ = [a_tuple], -Q
    for ai in R_ate_a_NAF:
        a_tuple, T = get_g2_a_tuple(T)
        a_list.append(a_tuple)
        if ai != '0':
            a_list.append(get_g_a_tuple(T, nQ if ai == '2' else Q))
            T = T + (nQ if ai == '2' else Q)
    Q1, nQ2 = Q.frobenius(), Q.frobenius2_neg()
    return a_list + [get_g_a_tuple(T, Q1), get_g_a_tuple(T + Q1, nQ2)]


def e_fast(P, a_list):
    nP_xy = (-P).normalize()
    f, i = g_value(a_list[0], nP_xy), 1
    for ai in R_ate_a_NAF:
        f, i = f.sqr() * g_value(a_list[i], nP_xy), i + 1
        if ai != '0':
            f, i = f * g_value(a_list[i], nP_xy), i + 1
    return final_exp(f * g_value(a_list[i], nP_xy) * g_value(a_list[-1], nP_xy))


# 获取Comb固定基的预计算表（256个FQ12的列表）
def get_comb_list(n):
    comb_list = [FQ12_one, n]
    for i in range(7):
        tmp = comb_list[2 ** i]
        for _ in range(32):
            tmp = tmp.sqr2()
        comb_list += [tmp * c for c in comb_list]
    return comb_list


# Comb固定基的幂运算
def comb_pow(r, comb_list):
    r_bin, res = '0' * (256 - r.bit_length()) + bin(r)[2:], FQ12_one
    for i in range(32):
        a = int(''.join(r_bin[j] for j in range(i, 256, 32)), 2)
        res = comb_list[a] if res is FQ12_one else res.sqr2() * comb_list[a]
    return res


# 获取固定点乘的预计算表（32行256列的椭圆曲线点矩阵）
def get_kP_list(P):
    one, kP_list = P, []
    for i in range(32):
        line_list = [0, one]  # O, P
        for j in range(1, 128):
            line_list.append(line_list[j].double())  # 2j·P
            line_list.append(line_list[-1] + one)  # (2j+1)·P
        kP_list.append(line_list)
        one = line_list[128].double() if i < 31 else 0
    return kP_list


# 使用预计算表的快速点乘
def fast_kG(k, kP_list):
    P_list = [kP_list[i][byte] for i, byte in enumerate(k.to_bytes(32, byteorder='little')) if byte]
    return sum(P_list[1:], P_list[0])


# SM9算法(GB_T 38635.2-2020) 5.3.6定义的密钥派生函数
# Z为bytes类型，klen表示输出密钥比特长度（8的倍数）；输出为bytes类型
def KDF(Z, klen=KEY_LEN):
    ksize, K = klen >> 3, bytearray()
    for ct in range(1, ceil(ksize / HASH_SIZE) + 1):
        K.extend(sm3(Z + to_byte(ct, 4)))
    return K[:ksize]


# SM9算法(GB_T 38635.2-2020) 5.3.2.2和5.3.2.3定义的密码函数
def H(i, Z):
    Ha = to_int(KDF(to_byte(i, 1) + Z, hlen))
    return Ha % (N - 1) + 1


# SM9算法(GB_T 38635.2-2020) 5.3.5定义的消息认证码函数
def MAC(K2, Z):
    return sm3(Z + K2)


class SM9:  # SM9算法(GB_T 38635.2-2020)
    # def __init__(self, ID='', ds=None, Ppub_s=None, de=None, Ppub_e=None, hid_s=1, hid_e=3, ks=None, ke=None):
    #     self.ID, self.ID_byte, self.hid_s_byte, self.hid_e_byte = ID, to_byte(ID), to_byte(hid_s, 1), to_byte(hid_e, 1)

    def __init__(self, ID='', ds=None, Ppub_s=None, de=None, Ppub_e=None, hid_s=1, hid_e=3, ks=None, ke=None):
        self.ID, self.ID_byte, self.hid_s_byte, self.hid_e_byte = ID, to_byte(ID), to_byte(hid_s, 1), to_byte(hid_e,
                                                                                                              1)

        # ✅ 新增：保存用户侧私钥句柄（即便暂时不用，也先留着，供懒初始化）
        if ds is not None:
            self.ds = ds
        if de is not None:
            self.de = de

        if ks:  # 作为密钥生成中心，给定签名主私钥（若要随机生成，可指定ks=-1）
            self.ks = ks if 0 < ks < N else randrange(1, N)
            self.Ppub_s = fast_kG(self.ks, _kP2)
        if ke:  # 作为密钥生成中心，给定加密主私钥（若要随机生成，可指定ke=-1）
            self.ke = ke if 0 < ke < N else randrange(1, N)
            self.Ppub_e = fast_kG(self.ke, _kP1)
        if ds and Ppub_s:  # 作为用户，给定用户签名私钥和签名主公钥
            self.k_ds_list, self.Ppub_s, self.gs = get_kP_list(ds), Ppub_s, e(P1, Ppub_s)
            self.gs_comb_list = get_comb_list(self.gs)
        if de and Ppub_e:  # 作为用户，给定用户加密私钥和加密主公钥
            self.de_a_list, self.Ppub_e, self.ge = get_a_list(de), Ppub_e, e(Ppub_e, P2)
            self.ge_comb_list = get_comb_list(self.ge)

    def KGC_gen_user(self, ID):
        ID_byte, ds, Ppub_s, de, Ppub_e = to_byte(ID), None, None, None, None
        if hasattr(self, 'ks'):
            t1 = (H(1, ID_byte + self.hid_s_byte) + self.ks) % N
            if t1 == 0:  # 需重新产生签名主密钥，并更新所有用户的签名密钥
                return False
            t2 = self.ks * mod_inv(t1, N) % N
            ds, Ppub_s = fast_kG(t2, _kP1), self.Ppub_s  # 用户签名私钥和签名主公钥
        if hasattr(self, 'ke'):
            t1 = (H(1, ID_byte + self.hid_e_byte) + self.ke) % N
            if t1 == 0:  # 需重新产生加密主密钥，并更新所有用户的加密密钥
                return False
            t2 = self.ke * mod_inv(t1, N) % N
            de, Ppub_e = fast_kG(t2, _kP2), self.Ppub_e  # 用户加密私钥和加密主公钥
        return SM9(ID, ds, Ppub_s, de, Ppub_e, self.hid_s_byte, self.hid_e_byte)

    # 6.2 数字签名生成算法
    def sign(self, M, r=None, outbytes=True):
        l = 0
        while l == 0:
            r = r if r else randrange(1, N)  # A2
            w = bytes(self.gs_pow(r))  # A3
            h = H(2, to_byte(M) + w)  # A4
            l = (r - h) % N  # A5
        S = fast_kG(l, self.k_ds_list)  # A6
        return to_byte([h, S]) if outbytes else (h, S)

    # 6.4 数字签名验证算法
    def verify(self, ID, M_, sig):
        h_, S_ = (to_int(sig[:N_SIZE]), ECC_Point.from_byte(sig[N_SIZE:])) if type(sig) is bytes else sig
        if not 0 < h_ < N or not S_ or not S_.is_on_curve():  # B1、B2
            return False
        t = self.gs_pow(h_)  # B4
        h1 = H(1, to_byte(ID) + self.hid_s_byte)  # B5
        P = fast_kG(h1, _kP2) + self.Ppub_s  # B6
        u = e(S_, P)  # B7
        w_ = bytes(u * t)  # B8
        h2 = H(2, to_byte(M_) + w_)  # B9
        return h_ == h2

    # A 发起协商（也可用作B生成rB、RB；outbytes=True时输出bytes）
    # 7.2 密钥交换协议 A1-A3
    def agreement_initiate(self, IDB, r=None, outbytes=True):
        QB = fast_kG(H(1, to_byte(IDB) + self.hid_e_byte), _kP1) + self.Ppub_e  # A1
        rA = r if r else randrange(1, N)  # A2
        RA = QB * rA  # A3
        return rA, bytes(RA) if outbytes else RA

    # B 响应协商（option=True时计算选项部分）
    # 7.2 密钥交换协议 B1-B6
    def agreement_response(self, RA, IDA, option=False, rB=None, klen=KEY_LEN, outbytes=True):
        RA = ECC_Point.from_byte(RA) if type(RA) is bytes else RA
        if not RA or not RA.is_on_curve():  # B4
            return False, 'RA不属于椭圆曲线群G1'
        rB, RB = self.agreement_initiate(IDA, rB, outbytes)  # B1-B3
        g1, g2 = self.e_de(RA), bytes(self.ge_pow(rB))  # B4
        g1, g3 = bytes(g1), bytes(g1 ** rB)  # B4
        tmp_byte = to_byte([IDA, self.ID_byte, RA, RB])
        SKB = KDF(tmp_byte + g1 + g2 + g3, klen)  # B5
        if not option:
            return True, (RB, SKB)
        self.tmp_byte2 = g1 + sm3(g2 + g3 + tmp_byte)
        SB = sm3(to_byte(0x82, 1) + self.tmp_byte2)  # B6（可选部分）
        return True, (RB, SKB, SB)

    # A 协商确认
    # 7.2 密钥交换协议 A5-A8
    def agreement_confirm(self, rA, RA, RB, IDB, SB=None, option=False, klen=KEY_LEN):
        RB = ECC_Point.from_byte(RB) if type(RB) is bytes else RB
        if not RB or not RB.is_on_curve():  # A5
            return False, 'RB不属于椭圆曲线群G1'
        g1_, g2_ = bytes(self.ge_pow(rA)), self.e_de(RB)  # A5
        g2_, g3_ = bytes(g2_), bytes(g2_ ** rA)  # A5
        tmp_byte = to_byte([self.ID_byte, IDB, RA, RB])
        if option and SB:  # A6（可选部分）
            tmp_byte2 = g1_ + sm3(g2_ + g3_ + tmp_byte)
            S1 = sm3(to_byte(0x82, 1) + tmp_byte2)
            if S1 != SB:
                return False, 'S1 != SB'
        SKA = KDF(tmp_byte + g1_ + g2_ + g3_, klen)  # A7
        if not option or not SB:
            return True, SKA
        SA = sm3(to_byte(0x83, 1) + tmp_byte2)  # A8
        return True, (SKA, SA)

    # B 协商确认（可选部分）
    # 7.2 密钥交换协议 B8
    def agreement_confirm2(self, SA):
        if not hasattr(self, 'tmp_byte2'):
            return False, 'step error'
        S2 = sm3(to_byte(0x83, 1) + self.tmp_byte2)
        if S2 == SA:
            del self.tmp_byte2
            return True, ''
        return False, 'S2 != SA'

    # 8.2 密钥封装算法
    def encaps(self, IDB, klen, r=None, outbytes=True):
        K = bytes()
        while K == bytes(len(K)):
            r, C = self.agreement_initiate(IDB, r, outbytes)  # A1-A3
            w = bytes(self.ge_pow(r))  # A5
            K = KDF(to_byte([C, w, IDB]), klen)
        return K, C

    # 8.4 密钥封装算法
    def decaps(self, C, klen):
        C = ECC_Point.from_byte(C) if type(C) is bytes else C
        if not C or not C.is_on_curve():  # B1
            return False, 'C不属于椭圆曲线群G1'
        w_ = bytes(self.e_de(C))  # B2
        K_ = KDF(to_byte([C, w_, self.ID_byte]), klen)  # B3
        return (True, K_) if K_ != bytes(len(K_)) else (False, 'K为全0比特串')

    # 9.2 加密算法
    def encrypt(self, IDB, M, r=None, outbytes=True):
        M = to_byte(M)
        K, C1 = self.encaps(IDB, (len(M) << 3) + K2_len, r, outbytes)  # A1-A6.a.1
        K1, K2 = K[:len(M)], K[len(M):]  # A6.a.1
        C2 = bytes(M[i] ^ K1[i] for i in range(len(M)))  # A6.a.2
        C3 = MAC(K2, C2)  # A7
        return to_byte([C1, C3, C2]) if outbytes else (C1, C3, C2)

    # 9.4 解密算法
    def decrypt(self, C):
        C3_start, C3_end = N_SIZE << 1, (N_SIZE << 1) + HASH_SIZE
        C1, C3, C2 = (C[:C3_start], C[C3_start:C3_end], C[C3_end:]) if type(C) is bytes else C
        res, K_ = self.decaps(C1, (len(C2) << 3) + K2_len)  # B1-B3.a.1
        if not res:
            return False, K_.replace('C', 'C1')
        K1_, K2_ = K_[:len(C2)], K_[len(C2):]  # B3.a.1
        if K1_ == bytes(len(K_)):
            return False, 'K1\'为全0比特串'
        u = MAC(K2_, C2)  # B4
        if u != C3:
            return False, 'u != C3'
        return True, bytes(C2[i] ^ K1_[i] for i in range(len(C2)))  # B3.a.2

    def e_de(self, P):
        return e_fast(P, self.de_a_list)

    def gs_pow(self, r):
        return comb_pow(r, self.gs_comb_list)

    def ge_pow(self, r):
        # 懒初始化：若不存在 ge/ge_comb_list，则只要有 Ppub_e 就可以现算
        if not hasattr(self, 'ge_comb_list'):
            if not hasattr(self, 'Ppub_e') or self.Ppub_e is None:
                raise ValueError("Ppub_e not initialized for ge_pow()")
            self.ge = e(self.Ppub_e, P2)
            self.ge_comb_list = get_comb_list(self.ge)
        return comb_pow(r, self.ge_comb_list)


_SM9kG_file = '../hggm/SM9_kG.bin'  # 预计算数据文件的位置
_kP1, _kP2 = [], []  # P1、P2点的预计算表
if os.path.exists(_SM9kG_file):
    with open(_SM9kG_file, 'rb') as f:  # 读取预计算数据文件
        data = f.read()
        G1_size, G2_size = N_SIZE << 1, N_SIZE << 2  # G1点坐标字节数、G2点坐标字节数
        P1_line, line = 255 * G1_size, 255 * (G1_size + G2_size)  # 一行G1点坐标字节数、一行总字节数
        for i in range(0, N_SIZE * line, line):
            _kP1.append([0] + [ECC_Point.from_byte(data[j:j + G1_size]) for j in range(i, i + P1_line, G1_size)])
            _kP2.append([0] + [ECC_Point.from_byte(data[j:j + G2_size]) for j in range(i + P1_line, i + line, G2_size)])
else:  # 预计算数据文件不存在
    _kP1, _kP2 = get_kP_list(P1), get_kP_list(P2)  # 生成P1、P2点的预计算表
    os.makedirs(os.path.dirname(_SM9kG_file), exist_ok=True)
    with open(_SM9kG_file, 'wb') as f:  # 将预计算表写入二进制文件
        f.write(b''.join(map(bytes, [P for x, y in zip(_kP1, _kP2) for P in x[1:] + y[1:]])))

# ======================= 你提供的“标准 SM9 底座”结束 =======================


# ======================= 盲签 + 追踪 + 去盲校验 + 订单门控：补全部分 =======================

from dataclasses import dataclass
from typing import Tuple, Optional

# ---- 底层辅助：将输入统一打包给 H(2, ·) 以生成可复算挑战 c ----
def _b(x) -> bytes:
    if isinstance(x, bytes): return x
    if isinstance(x, str):   return x.encode('utf-8')
    if isinstance(x, int):   return to_byte(x)
    return bytes(x)  # ECC_Point / FQ12 均实现 __bytes__

# def H2_bind(*items) -> int:
#     """  ###(9)/(19)###
#     复算挑战 c：c = H(2, M' || ID || ver || e(R,P2) || T)
#     —— 与原文“可复算挑战进入验证签名方程”一致
#     """
#     blob = b'|'.join(_b(it) for it in items)
#     return H(2, blob)  # 返回 [1, N-1]+1 范围内整数
# —— 替换 sm9z.txt 里的 H2_bind，实现稳定的串行化与域分离 ——

# charm h1
# h2

def H2_bind(M_prime: bytes, ID: str, ver: bytes, eRP2: 'FQ12', T: 'ECC_Point') -> int:
    """
    c = H(2,  M' || ID || ver || bytes(e(R,P2)) || bytes(T) )
    - ID: UTF-8
    - ver: 固定版本字节（域分离）
    - eRP2/T: 使用 bytes() 的规范串行化
    """
    blob = b'|SM9|c|' + M_prime + b'|' + ID.encode('utf-8') + b'|' + ver + b'|' + bytes(eRP2) + b'|' + bytes(T)
    return H(2, blob)

def H3_mask(B: ECC_Point) -> bytes:
    """
    盲化掩码：k = KDF(b"H3|" || bytes(B), 256)[:32]
    —— 与原文保持 H3/KDF 风格的“消息盲化/去盲”
    """
    return KDF(b'H3|' + bytes(B), 256)[:32]


# ---- 系统参数 / 用户密钥（SM9 点值私钥为“点”，与原文一致） ----
# p1p2file
@dataclass
class BSysParams:
    P1: ECC_Point
    P2: ECC_Point
    Ppub_s: ECC_Point      # = s * P2（签名主公钥）
    version: bytes         # 版本/域分离

@dataclass
class BUserKeys:
    ID: str
    Q_ID: ECC_Point       # = H1(ID||hid_s) * P1  （G1 身份点）
    d_ID: ECC_Point       # = s * Q_ID           （G1 身份私钥为点）
    T: ECC_Point          # = α * Q_ID           （G1 追踪标签，随签名发布）
    A_open: ECC_Point     # = α * P2             （G2 打开凭证，由 KGC 发布用于打开验证）


# ---- 审计 & 订单门控（极简） ----
class Audit:
    def __init__(self): self.events = []
    def log(self, ev, **kv): self.events.append((ev, kv))


# ---- KGC：产生 s、派发 (Q_ID, d_ID)、生成追踪材料 (T, A)，订单核验/票据 ----
class BKGC:
    def __init__(self, hid_s: int = 1, version: str = "v1"):
        self.version = to_byte(version)
        self.hid_s_byte = to_byte(hid_s, 1)
        self.s = randrange(1, N)
        self.Ppub_s = fast_kG(self.s, _kP2)  # ###(3)###
        self._alpha = {}            # ID -> α
        self._tickets = set()       # 准入票据
        self.audit = Audit()

    def params(self) -> BSysParams:
        return BSysParams(P1=P1, P2=P2, Ppub_s=self.Ppub_s, version=self.version)

    def enroll(self, ID: str) -> BUserKeys:
        # H1(ID||hid_s) → Z_N*，再乘 P1 得到 G1 身份点 Q_ID
        h1 = H(1, to_byte(ID) + self.hid_s_byte)
        Q_ID = fast_kG(h1, _kP1)         # Q_ID ∈ G1  ###(8)###
        d_ID = self.s * Q_ID             # d_ID = s * Q_ID（点私钥）——与原文一致  ###(12)###
        alpha = randrange(1, N)
        self._alpha[ID] = alpha
        T = alpha * Q_ID                 # 追踪标签 T = α·Q_ID（发布）  ###(Trace)###
        A = fast_kG(alpha, _kP2)         # 打开凭证 A = α·P2  （KGC掌握，打开时发布）  ###(Trace)###
        self.audit.log("enroll", ID=ID)
        return BUserKeys(ID=ID, Q_ID=Q_ID, d_ID=d_ID, T=T, A_open=A)
    # du

    # 打开：发布 A = α·P2，供任何人验证 e(T,P2) == e(Q_ID,A)   ——【公式(Trace)】
    def open_trace(self, ID: str) -> Tuple[ECC_Point, bytes]:
        if ID not in self._alpha: raise ValueError("unknown ID")
        A = fast_kG(self._alpha[ID], _kP2)
        self.audit.log("open", ID=ID)
        return A, self.version  # ###(Trace)###

    # 订单验证（占位）：返回批准票据
    def verify_order(self, order_hash: bytes, pay_proof: bytes) -> bytes:
        tk = sm3(order_hash + pay_proof + b"|OK|" + self.version)
        self._tickets.add(tk)
        self.audit.log("order_ok", ticket=tk.hex())
        return tk

    def check_ticket(self, tk: bytes) -> bool:
        return tk in self._tickets


# ---- DO：盲化 + 点值签名 + 门控释放 r^{-1} ----
class BDO:
    def __init__(self, params: BSysParams, keys: BUserKeys, kgc: BKGC):
        self.par, self.keys, self.kgc = params, keys, kgc
        self._last_r: Optional[int] = None
        self._last_B: Optional[ECC_Point] = None
        self._last_h_bar: Optional[ECC_Point] = None


    # 盲化：B = r·P1；k = H3(B)；M' = M ⊕ k    —— 保持原文的盲化流程
    def blind(self, M: bytes) -> Tuple[bytes, ECC_Point]:
        # (13) 数据指纹：h = H1(M)
        h = H(1, M)  # ###(13)###
        # (14) 哈希到点：\bar h = h * P1
        h_bar = fast_kG(h, _kP1)  # ###(14)###
        # (15) 盲化因子：j ← Z_n^*, B = j * Q_ID + \bar h
        j = randrange(1, N)  # ###(15)/(22)###
        B = j * self.keys.Q_ID + h_bar  # ###(15)###
        # (16) 盲化：M' = M XOR H3(B)
        k = H3_mask(B)  # ###(16)###
        if len(k) < len(M):
            k = (k * (len(M)//len(k) + 1))[:len(M)]
        M_ = bytes(mi ^ ki for mi, ki in zip(M, k))  # ###(16)###
        # 记录以便 release_r_inv() 释放 j^{-1}，并可选提供 \bar h
        self._last_r, self._last_B, self._last_h_bar = j, B, h_bar
        return M_, B

    # （可选）取出 \bar h（若论文流程需要由 DO 发送给 BU）
    def last_h_bar(self) -> Optional['ECC_Point']:
        return self._last_h_bar
    def sign_blinded(self, M_: bytes) -> Tuple[ECC_Point, ECC_Point, ECC_Point]:
        k = randrange(1, N)  # ###(17)###
        R = k * self.par.P1  # ###(18)###
        c = H2_bind(M_, self.keys.ID, self.par.version, e(R, self.par.P2), self.keys.T)  # ###(19)###
        S = R + c * self.keys.d_ID  # ###(20)###
        return R, S, self.keys.T  # 携带追踪标签 T  ###(21)###

    # 只有在 DEP 批准后，才释放 r^{-1}（门控）
    def release_r_inv(self, approve_ticket: bytes) -> int:
        if self._last_r is None or self._last_B is None:
            raise ValueError("no blind session")
        if not self.kgc.check_ticket(approve_ticket):
            raise PermissionError("ticket invalid")
        r_inv = mod_inv(self._last_r, N)  # ###(22)###
        self._last_r = None  # 单次释放，避免重放
        return r_inv


# ---- DEP：平台验签（对 M'） + 订单票据 ----
# class BDEP:
#     def __init__(self, params: BSysParams, kgc: BKGC):
#         self.par, self.kgc = params, kgc
#
#     def verify_blinded(self, ID: str, Q_ID: ECC_Point, M_prime: bytes,
#                        sig: Tuple[ECC_Point, ECC_Point, ECC_Point]) -> bool:
#         R, S, T = sig
#         # 1) 重算挑战
#         eRP2 = e(R, self.par.P2)
#         c = H2_bind(M_prime, ID, self.par.version, eRP2, T)  # (9)/(19)
#         # 2) 配对等式（两边在 GT）
#         left  = e(S, self.par.P2)
#         right = eRP2 * (e(Q_ID, self.par.Ppub_s) ** c)       # (10)
#         return left == right
class BDEP:
    def __init__(self, params: BSysParams, kgc: BKGC):
        self.par, self.kgc = params, kgc

    def verify_blinded(self, ID: str, Q_ID: ECC_Point, M_prime: bytes,
                       sig: Tuple[ECC_Point, ECC_Point, ECC_Point]) -> bool:
        R, S, T = sig
        # 1) 重算挑战
        eRP2 = e(R, self.par.P2)
        c = H2_bind(M_prime, ID, self.par.version, eRP2, T)  # (9)/(19)
        # 2) 配对等式（两边在 GT）
        left = e(S, self.par.P2)
        right = eRP2 * (e(Q_ID, self.par.Ppub_s) ** c)  # (10)
        return left == right

    def verify_order(self, order_hash: bytes, pay_proof: bytes) -> bytes:
        return self.kgc.verify_order(order_hash, pay_proof)


# ---- DU：去盲 + “去盲临时公钥/响应值”校验 + 打开验证 ----
# class BDU:
#     def __init__(self, params: BSysParams):
#         self.par = params
#
#     # 去盲三步：
#     #  (1) 去盲临时公钥：P* = r^{-1}·B ?= P1
#     #  (2) 去盲响应值：Ŝ = r^{-1}(S - R)，验 e(Ŝ,P2) == e(Q_ID,Ppub_s)^{c·r^{-1}} ——【公式(Unblind-Resp)】
#     #  (3) 恢复原文：M = M' ⊕ H3(B)
#     def unblind_and_verify(self, ID: str, Q_ID: ECC_Point, M_: bytes, B: ECC_Point, r_inv: int,
#                            sig: Tuple[ECC_Point, ECC_Point, ECC_Point]) -> Tuple[bool, bool, bytes]:
#         R, S, T = sig
#         # (1)
#         P_star = r_inv * B  # ###(25)###
#         pub_ok = (P_star == self.par.P1)
#         # (2)
#         c = H2_bind(M_, ID, self.par.version, e(R, self.par.P2), T)  # ###(28)###
#         S_hat = r_inv * (S - R)  # ###(24)###
#         left  = e(S_hat, self.par.P2)
#         right = e(Q_ID, self.par.Ppub_s) ** ((c * r_inv) % N)  # ###(29)###
#         resp_ok = (left == right)
#         # (3)
#         k = H3_mask(B)  # ###(16)###
#         if len(k) < len(M_):
#             k = (k * (len(M_)//len(k) + 1))[:len(M_)]
#         M = bytes(mi ^ ki for mi, ki in zip(M_, k))  # ###(26)/(27)###
#         return pub_ok, resp_ok, M
# class BDU:
#     def __init__(self, params: BSysParams):
#         self.par = params
#
#     def unblind_and_verify(self, ID: str, Q_ID: ECC_Point, M_prime: bytes,
#                            B: ECC_Point, r_inv: int,
#                            sig: Tuple[ECC_Point, ECC_Point, ECC_Point]) -> Tuple[bool, bool, bytes]:
#         R, S, T = sig
#         # (25) 去盲临时公钥
#         P_star = r_inv * B
#         pub_ok = (P_star == self.par.P1)
#
#         # (24)(28)(29) 去盲响应式验证
#         eRP2 = e(R, self.par.P2)
#         c = H2_bind(M_prime, ID, self.par.version, eRP2, T)
#         S_hat = r_inv * (S - R)  # (24)
#         left = e(S_hat, self.par.P2)
#         right = (e(Q_ID, self.par.Ppub_s) ** ((c * r_inv) % N))
#         resp_ok = (left == right)  # (29)
#
#         # (26)(27) 恢复原文
#         k = H3_mask(B)
#         if len(k) < len(M_prime):
#             k = (k * (len(M_prime) // len(k) + 1))[:len(M_prime)]
#         M = bytes(mi ^ ki for mi, ki in zip(M_prime, k))
#
#         return pub_ok, resp_ok, M
class BDU:
    def __init__(self, params: BSysParams):
        self.par = params

    def unblind_and_verify(self, ID: str, Q_ID: ECC_Point, M_prime: bytes,
                           B: ECC_Point, r_inv: int,
                           sig: Tuple[ECC_Point, ECC_Point, ECC_Point]):
        R, S, T = sig

        # (28) 复算挑战，用于响应式校验（保持不变）
        eRP2 = e(R, self.par.P2)
        c = H2_bind(M_prime, ID, self.par.version, eRP2, T)

        # (24) 去盲“响应值”并验配对（保持不变）
        S_hat = r_inv * (S - R)
        left = e(S_hat, self.par.P2)
        right = (e(Q_ID, self.par.Ppub_s) ** ((c * r_inv) % N))
        resp_ok = (left == right)

        # (26)(27) 恢复原文（保持不变）
        k = H3_mask(B)
        if len(k) < len(M_prime):
            k = (k * (len(M_prime) // len(k) + 1))[:len(M_prime)]
        M = bytes(mi ^ ki for mi, ki in zip(M_prime, k))

        # ✅ 正确的“去盲临时公钥校验”，适配 B = j*Q_ID + h*P1
        h = H(1, M)  # H1(M)
        h_bar = fast_kG(h, _kP1)  # \bar h = h * P1
        Q_ID_rec = r_inv * (B - h_bar)  # 应还原出 Q_ID
        pub_ok = (Q_ID_rec == Q_ID)

        return pub_ok, resp_ok, M

    # 打开验证：给定 KGC 发布的 A=α·P2，检查 e(T,P2)==e(Q_ID,A)  ——【公式(Trace)】
    def verify_opening(self, Q_ID: ECC_Point, T: ECC_Point, A_open: ECC_Point) -> bool:
        return e(T, self.par.P2) == e(Q_ID, A_open)  # ###(Trace)###

