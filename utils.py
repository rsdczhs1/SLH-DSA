class ADRS():
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6

    def __init__(self, value: bytes):
        self.ADRS = value

    def copy(self):
        return ADRS(self.ADRS)

    def setLayerAddress(self, l: int):
        self.ADRS = toByte(l, 4)+self.ADRS[4:32]

    def setTreeAddress(self, t: int):
        self.ADRS = self.ADRS[0:4]+toByte(t, 12)+self.ADRS[16:32]

    def setTypeAndClear(self, Y: int):
        self.ADRS = self.ADRS[0:16]+toByte(Y, 4)+toByte(0, 12)

    def setKeyPairAddress(self, i: int):
        self.ADRS = self.ADRS[0:20]+toByte(i, 4)+self.ADRS[24:32]

    def setChainAddress(self, i: int):
        self.ADRS = self.ADRS[0:24]+toByte(i, 4)+self.ADRS[28:32]

    def setTreeHeight(self, i: int):
        self.ADRS = self.ADRS[0:24]+toByte(i, 4)+self.ADRS[28:32]

    def setHashAddress(self, i: int):
        self.ADRS = self.ADRS[0:28]+toByte(i, 4)

    def setTreeIndex(self, i: int):
        self.ADRS = self.ADRS[0:28]+toByte(i, 4)

    def getKeyPairAddress(self) -> int:
        return toInt(self.ADRS[20:24], 4)

    def getTreeIndex(self) -> int:
        return toInt(self.ADRS[28:32], 4)

    def adrsc(self):
        return self.ADRS[3:4] + self.ADRS[8: 16] + self.ADRS[19:20] + self.ADRS[20:32]


def toByte(x: int, n: int) -> bytes:
    """ Algorithm 2: toByte(x, n). Convert an integer to ADRS byte string."""
    total = x
    S = [0]*n
    for i in range(n):
        S[n - 1 - i] = total & 0xFF
        total >>= 8
    return bytes(S)


def toInt(X: bytes, n: int) -> int:
    """ Algorithm 1: toInt(X, n). Convert ADRS byte string to an integer."""
    total = 0
    for i in range(n):
        total = (total << 8) + int(X[i])
    return total


def base_2b(X: bytes, b: int, out_len: int) -> list:
    """_summary_

    Args:
        X (bytes): _description_
        b (int): _description_
        out_len (int): _description_

    Returns:
        list: _description_
    """
    i = 0
    bits = 0
    total = 0
    baseb = [0]*out_len
    for out in range(out_len):
        while bits < b:
            total = (total << 8) + int(X[i])
            i += 1
            bits += 8
        bits -= b
        baseb[out] = (total >> bits) % (2**b)
    return baseb
