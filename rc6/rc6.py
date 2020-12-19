MAX_UINT32 = 0xFFFFFFFF
progress = 0

class RC6:
    def __init__(self, key):
        '''
        Q = Odd((f-1)*2^w)
        P = Odd((e-2)*2^w)
        '''
        if len(key) not in [16, 24, 32]:
            raise ValueError('Incorrect key size')

        self.Q = 0x9E3779B9
        self.P = 0xB7E15163

        self.w = 32
        self.r = 20
        self.b = len(key)

        self.S = self.key_schedule(
            [int.from_bytes(key[i: i + 4], byteorder='little') for i in range(0, self.b, 4)])

    def key_schedule(self, L):
        size = 2 * self.r + 4
        c = len(L)
        S = [0 for _ in range(size)]
        S[0] = self.P

        for i in range(1, size):
            S[i] = (S[i - 1] + self.Q) & MAX_UINT32

        A = B = i = j = 0
        v = 3 * max(c, size)

        for _ in range(1, v + 1):
            A = S[i] = self.shift(S[i] + A + B, 3)
            B = L[j] = self.shift(L[j] + A + B, (A + B))
            i = (i + 1) % size
            j = (j + 1) % c

        return S

    def encode_block(self, block):
        block = int.from_bytes(block, byteorder='little')
        A, B, C, D = [(block >> shift) & MAX_UINT32 for shift in range(96, -1, -32)]

        B = (B + self.S[0]) & MAX_UINT32
        D = (D + self.S[1]) & MAX_UINT32

        for i in range(1, self.r + 1):
            t = self.shift(B * (2 * B + 1), 5)
            u = self.shift(D * (2 * D + 1), 5)
            A = (self.shift(A ^ t, u) + self.S[2 * i]) & MAX_UINT32
            C = (self.shift(C ^ u, t) + self.S[2 * i + 1]) & MAX_UINT32
            A, B, C, D = B, C, D, A

        A = (A + self.S[2 * self.r + 2]) & MAX_UINT32
        C = (C + self.S[2 * self.r + 3]) & MAX_UINT32

        return ((A << 96) | (B << 64) | (C << 32) | D).to_bytes(16, byteorder='little')

    def decode_block(self, block):
        block = int.from_bytes(block, byteorder='little')
        A, B, C, D = [(block >> shift) & MAX_UINT32 for shift in range(96, -1, -32)]

        C = (C - self.S[2 * self.r + 3]) & MAX_UINT32
        A = (A - self.S[2 * self.r + 2]) & MAX_UINT32

        for i in range(self.r, 0, -1):
            A, B, C, D = D, A, B, C
            u = self.shift(D * (2 * D + 1), 5)
            t = self.shift(B * (2 * B + 1), 5)
            C = (self.shift(C - self.S[2 * i + 1], -t) ^ u) & MAX_UINT32
            A = (self.shift(A - self.S[2 * i], -u) ^ t) & MAX_UINT32

        D = (D - self.S[1]) & MAX_UINT32
        B = (B - self.S[0]) & MAX_UINT32

        return ((A << 96) | (B << 64) | (C << 32) | D).to_bytes(16, byteorder='little')

    def shift(self, num, shift):
        num &= MAX_UINT32
        shift %= self.w

        return ((num << shift) | (num >> (self.w - shift))) & MAX_UINT32


class ECB():
    def __init__(self, rc6):
        self.rc6 = rc6
        self.bs = 16

    def encode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]

        for block in blocks:
            yield self.rc6.encode_block(block)

    def decode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]

        for block in blocks:
            yield self.rc6.decode_block(block)


class CBC():
    def __init__(self, rc6, c0):
        self.rc6 = rc6
        self.c0 = c0
        self.bs = 16

    def encode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]
        prev = self.c0

        for block in blocks:
            prev = self.rc6.encode_block(xor_bytes(block, prev, self.bs))
            yield prev

    def decode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]
        prev = self.c0

        for block in blocks:
            yield xor_bytes(self.rc6.decode_block(block), prev, self.bs)
            prev = block


class OFB():
    def __init__(self, rc6, c0):
        self.rc6 = rc6
        self.c0 = c0
        self.bs = 16

    def encode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]
        prev = self.c0

        for block in blocks:
            prev = self.rc6.encode_block(prev)
            yield xor_bytes(prev, block, self.bs)

    def decode(self, b_arr):
        return self.encode(b_arr)


class CFB():
    def __init__(self, rc6, c0):
        self.rc6 = rc6
        self.c0 = c0
        self.bs = 16

    def encode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]
        prev = self.c0

        for block in blocks:
            prev = xor_bytes(self.rc6.encode_block(prev), block, self.bs)
            yield prev

    def decode(self, b_arr):
        blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]
        prev = self.c0

        for block in blocks:
            yield xor_bytes(self.rc6.encode_block(prev), block, self.bs)
            prev = block


def xor_bytes(a, b, size):
    return (int.from_bytes(a, byteorder='little') ^ int.from_bytes(b, byteorder='little')).to_bytes(size, byteorder='little')