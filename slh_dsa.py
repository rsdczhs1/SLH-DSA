import os
from utils import *
import time
from hashlib import sha256, sha512, shake_128, shake_256


def random(n) -> bytes:
    return os.urandom(n)


class SLH_DSA():
    """
    python implementation of SLH-DSA according to FIPS-205 published on August.
    main function API:
        slh_keyGen, slh_sign, slh_verify
        slh_keyGen_internal, slh_sign_internal, slh_verify_internal
    the standard SLH-DSA can be created by:
        SLH_DSA.SLH_DSA_SHA2_128f(),  
        SLH_DSA.SLH_DSA_SHA2_128s(),
        SLH_DSA.SLH_DSA_SHA2_192f(), 
        ...
    """

    def __init__(self,  hashname='SHAKE', paramid='f', n=16, h=66,
                 d=22, hp=3, a=6, k=33, lg_w=4, m=34, randomizer=random, deterministic=False):
        """initial the SLH-DSA case

        Args:
            hashname (str, optional): "SHAKE" or "SHA2". Defaults to 'SHAKE'.
            paramid (str, optional): 'f' or 's'. Defaults to 'f'.
            n (int, optional): length of unit signature. Defaults to 16.
            h (int, optional): total height of xmss trees. Defaults to 66.
            d (int, optional): xmss tree nums. Defaults to 22.
            hp (int, optional): height of one xmss tree. Defaults to 3.
            a (int, optional): one FORS tree height-1. Defaults to 6.
            k (int, optional): FORS tree nums. Defaults to 33.
            lg_w (int, optional): 4. Defaults to 4.
            m (int, optional): data blocking. Defaults to 34.
            randomizer (function, optional): random function. Defaults to random.
            deterministic (bool, optional): Defaults to False.
        """
        self.hashname = hashname
        self.paramid = paramid
        self.n = n
        self.h = h
        self.d = d
        self.hp = hp
        self.a = a
        self.k = k
        self.lg_w = lg_w
        self.m = m
        self.randomizer = randomizer
        self.deterministic = deterministic
        self.stdname = f'SLH-DSA-{self.hashname}-{8*self.n}{self.paramid}'

        if hashname == 'SHAKE':
            self.h_msg = self.shake_h_msg
            self.prf = self.shake_prf
            self.prf_msg = self.shake_prf_msg
            self.f = self.shake_f
            self.hh = self.shake_f
            self.tl = self.shake_f
        elif hashname == 'SHA2' and self.n == 16:
            self.h_msg = self.sha256_h_msg
            self.prf = self.sha256_prf
            self.prf_msg = self.sha256_prf_msg
            self.f = self.sha256_f
            self.hh = self.sha256_f
            self.tl = self.sha256_f
        elif hashname == 'SHA2' and self.n > 16:
            self.h_msg = self.sha512_h_msg
            self.prf = self.sha256_prf
            self.prf_msg = self.sha512_prf_msg
            self.f = self.sha256_f
            self.hh = self.sha512_h
            self.tl = self.sha512_h

        self.w = 2**self.lg_w
        self.len1 = (8 * self.n + (self.lg_w - 1)) // self.lg_w
        self.len2 = (self.len1 *
                     (self.w - 1)).bit_length() // self.lg_w + 1
        self.len = self.len1 + self.len2

    def shake_h_msg(self, R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
        hash = shake_256(R + pk_seed + pk_root + M)
        return hash.digest(self.m)

    def shake_prf(self, pk_seed: bytes, sk_seed: bytes, ADRS: ADRS) -> bytes:
        hash = shake_256(pk_seed + ADRS.ADRS + sk_seed)
        return hash.digest(self.n)

    def shake_prf_msg(self, sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
        hash = shake_256(sk_prf + opt_rand + M, self.n)
        return hash.digest(self.n)

    def shake_f(self, pk_seed: bytes, ADRS: ADRS, M: bytes) -> bytes:
        hash = shake_256(pk_seed + ADRS.ADRS + M, self.n)
        return hash.digest(self.n)

    def sha_256(self, x, n=32):
        """Tranc_n(SHA2-256(x))."""
        return sha256(x).digest()[0:n]

    def sha_512(self, x, n=64):
        """Tranc_n(SHA2-512(x))."""
        return sha512(x).digest()[0:n]

    def mgf(self, hash_f, hash_l, mgf_seed, mask_len):
        """NIST SP 800-56B REV. 2 / The Mask Generation Function (MGF)."""
        t = bytes()
        for c in range((mask_len + hash_l - 1) // hash_l):
            t += hash_f(mgf_seed + c.to_bytes(4, byteorder='big'))
        return t[0:mask_len]

    def mgf_sha256(self, mgf_seed, mask_len):
        """MGF1-SHA1-256(mgfSeed, maskLen)."""
        return self.mgf(self.sha_256, 32, mgf_seed, mask_len)

    def mgf_sha512(self, mgf_seed, mask_len):
        """MGF1-SHA1-512(mgfSeed, maskLen)."""
        return self.mgf(self.sha_512, 64, mgf_seed, mask_len)

    def hmac(self, hash_f, hash_l, hash_b, k, text):
        """FIPS PUB 198-1 HMAC."""
        if len(k) > hash_b:
            k = hash_f(k)
        ipad = bytearray(hash_b)
        ipad[0:len(k)] = k
        opad = bytearray(ipad)
        for i in range(hash_b):
            ipad[i] ^= 0x36
            opad[i] ^= 0x5C
        return hash_f(opad + hash_f(ipad + text))

    def hmac_sha256(self, k, text, n=32):
        """Trunc_n(HMAC-SHA-256())"""
        return self.hmac(self.sha_256, 32, 64, k, text)[0:n]

    def hmac_sha512(self, k, text, n=64):
        """Trunc_n(HMAC-SHA-512())"""
        return self.hmac(self.sha_512, 64, 128, k, text)[0:n]

    def sha256_h_msg(self, R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes):
        return self.mgf_sha256(R + pk_seed +
                               self.sha_256(R + pk_seed + pk_root + M), self.m)

    def sha256_prf(self, pk_seed: bytes, sk_seed: bytes, ADRS: ADRS):
        return self.sha_256(pk_seed + bytes(64 - self.n) +
                            ADRS.adrsc() + sk_seed, self.n)

    def sha256_prf_msg(self, sk_prf, opt_rand, M):
        return self.hmac_sha256(sk_prf, opt_rand + M, self.n)

    def sha256_f(self, pk_seed, ADRS, m1):
        return self.sha_256(pk_seed + bytes(64 - self.n) +
                            ADRS.adrsc() + m1, self.n)

    def sha512_h_msg(self, r, pk_seed, pk_root, M):
        return self.mgf_sha512(r + pk_seed +
                               self.sha_512(r + pk_seed + pk_root + M), self.m)

    def sha512_prf_msg(self, sk_prf, opt_rand, M):
        return self.hmac_sha512(sk_prf, opt_rand + M, self.n)

    def sha512_h(self, pk_seed, ADRS, m2):
        return self.sha_512(pk_seed + bytes(128 - self.n) +
                            ADRS.adrsc() + m2, self.n)

    def chain(self, X: bytes, i: int, s: int, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Chaining function used in WOTS+.

        Args:
            X (bytes): _description_
            i (int): _description_
            s (int): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: Value of F interated s times on X
        """
        tmp = X
        for j in range(i, i + s):
            ADRS.setHashAddress(j)
            tmp = self.f(pk_seed, ADRS, tmp)
        return tmp

    def wots_pkGen(self, sk_seed: bytes, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Generates a WOTS+ public key.

        Args:
            sk_seed (bytes): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: _description_
        """
        skADRS = ADRS.copy()
        skADRS.setTypeAndClear(skADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        tmp = bytes()
        for i in range(self.len):
            skADRS.setChainAddress(i)
            sk = self.prf(pk_seed, sk_seed, skADRS)
            ADRS.setChainAddress(i)
            tmp += self.chain(sk, 0, self.w - 1, pk_seed, ADRS)
        wotspkADRS = ADRS.copy()
        wotspkADRS.setTypeAndClear(wotspkADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk = self.tl(pk_seed, wotspkADRS, tmp)
        return pk

    def wots_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Generates a WOTS+ signature on an n-byte message.

        Args:
            M (bytes): _description_
            sk_seed (bytes): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: WOTS+ signature
        """
        csum = 0
        msg = base_2b(M, self.lg_w, self.len1)
        for i in range(self.len1):
            csum += self.w - 1 - msg[i]
        csum <<= ((8 - ((self.len2 * self.lg_w) % 8)) % 8)
        msg = msg + base_2b(toByte(csum,
                                   (self.len2 * self.lg_w + 7) // 8), self.lg_w, self.len2)
        skADRS = ADRS.copy()
        skADRS.setTypeAndClear(skADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        sig = bytes()
        for i in range(self.len):
            skADRS.setChainAddress(i)
            sk = self.prf(pk_seed, sk_seed, skADRS)
            ADRS.setChainAddress(i)
            sig += self.chain(sk, 0, msg[i], pk_seed, ADRS)
        return sig

    def wots_pkFromSig(self, sig: bytes, M: bytes, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Computes a WOTS+ public key from a message and its signature.

        Args:
            sig (bytes): _description_
            M (bytes): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: _description_
        """
        csum = 0
        msg = base_2b(M, self.lg_w, self.len1)
        for i in range(self.len1):
            csum += self.w - 1 - msg[i]
        csum <<= ((8 - ((self.len2 * self.lg_w) % 8)) % 8)
        msg += base_2b(toByte(csum,
                              (self.len2 * self.lg_w + 7) // 8), self.lg_w, self.len2)
        tmp = bytes()
        for i in range(self.len):
            ADRS.setChainAddress(i)
            tmp += self.chain(sig[i*self.n:(i+1)*self.n],
                              msg[i], self.w - 1 - msg[i],
                              pk_seed, ADRS)
        wotspkADRS = ADRS.copy()
        wotspkADRS.setTypeAndClear(wotspkADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk_sig = self.tl(pk_seed, wotspkADRS, tmp)
        return pk_sig

    def xmss_sign(self, M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Generates an XMSS signature

        Args:
            M (bytes): _description_
            sk_seed (bytes): _description_
            idx (int): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: _description_
        """
        AUTH = bytes()
        for j in range(self.hp):
            k = (idx >> j) ^ 1
            AUTH += self.xmss_node(sk_seed, k, j, pk_seed, ADRS)
        ADRS.setTypeAndClear(ADRS.WOTS_HASH)
        ADRS.setKeyPairAddress(idx)
        sig = self.wots_sign(M, sk_seed, pk_seed, ADRS)
        SIG_XMSS = sig + AUTH
        return SIG_XMSS

    def xmss_node(self, sk_seed: bytes, i: int, z: int, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Computes the root of a Merkle subtree of WOTS+ public keys

        Args:
            sk_seed (bytes): _description_
            i (int): target node index
            z (int): target node height
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: _description_
        """
        if z == 0:
            ADRS.setTypeAndClear(ADRS.WOTS_HASH)
            ADRS.setKeyPairAddress(i)
            node = self.wots_pkGen(sk_seed, pk_seed, ADRS)
        else:
            lnode = self.xmss_node(sk_seed, 2 * i, z - 1, pk_seed, ADRS)
            rnode = self.xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, ADRS)
            ADRS.setTypeAndClear(ADRS.TREE)
            ADRS.setTreeHeight(z)
            ADRS.setTreeIndex(i)
            node = self.hh(pk_seed, ADRS, lnode + rnode)
        return node

    def xmss_pkFromSig(self, idx: int, SIG_XMSS: bytes, M: bytes, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Computes an XMSS public key from an XMSS signature.

        Args:
            idx (int): _description_
            SIG_XMSS (bytes): _description_
            M (bytes): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_

        Returns:
            bytes: _description_
        """
        ADRS.setTypeAndClear(ADRS.WOTS_HASH)
        ADRS.setKeyPairAddress(idx)
        sig = SIG_XMSS[0:self.len*self.n]
        AUTH = SIG_XMSS[self.len*self.n: (self.len+self.hp)*self.n]
        node0 = self.wots_pkFromSig(sig, M, pk_seed, ADRS)
        ADRS.setTypeAndClear(ADRS.TREE)
        ADRS.setTreeIndex(idx)
        for k in range(self.hp):
            ADRS.setTreeHeight(k + 1)
            if (idx >> k) & 1 == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
                node1 = self.hh(pk_seed, ADRS, node0 +
                                AUTH[k*self.n:(k+1)*self.n])
            else:
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
                node1 = self.hh(
                    pk_seed, ADRS, AUTH[k*self.n:(k+1)*self.n] + node0)
            node0 = node1
        return node0

    def ht_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int) -> bytes:
        """Generates a hypertree signature

        Args:
            M (bytes): _description_
            sk_seed (bytes): _description_
            pk_seed (bytes): _description_
            idx_tree (int): _description_
            idx_leaf (int): _description_

        Returns:
            bytes: _description_
        """
        htADRS = ADRS(toByte(0, 32))
        htADRS.setTreeAddress(idx_tree)
        SIG_tmp = self.xmss_sign(M, sk_seed, idx_leaf, pk_seed, htADRS)
        SIG_HT = SIG_tmp
        root = self.xmss_pkFromSig(idx_leaf, SIG_tmp, M, pk_seed, htADRS)
        hp_m = ((1 << self.hp) - 1)
        for j in range(1, self.d):
            idx_leaf = idx_tree & hp_m
            idx_tree = idx_tree >> self.hp
            htADRS.setLayerAddress(j)
            htADRS.setTreeAddress(idx_tree)
            SIG_tmp = self.xmss_sign(root, sk_seed, idx_leaf, pk_seed, htADRS)
            SIG_HT += SIG_tmp
            if j < self.d - 1:
                root = self.xmss_pkFromSig(idx_leaf, SIG_tmp, root,
                                           pk_seed, htADRS)
        return SIG_HT

    def ht_verify(self, M: bytes, SIG_HT: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes) -> bool:
        """Verifies a hypertree signature

        Args:
            M (bytes): message
            SIG_HT (bytes): _description_
            pk_seed (bytes): _description_
            idx_tree (int): tree index
            idx_leaf (int): leaf index
            pk_root (bytes): _description_

        Returns:
            bool: _description_
        """
        htADRS = ADRS(toByte(0, 32))
        htADRS.setTreeAddress(idx_tree)
        SIG_tmp = SIG_HT[0:(self.hp + self.len)*self.n]
        node = self.xmss_pkFromSig(idx_leaf, SIG_tmp, M, pk_seed, htADRS)
        for j in range(1, self.d):
            idx_leaf = idx_tree & ((1 << self.hp) - 1)
            idx_tree = idx_tree >> self.hp
            htADRS.setLayerAddress(j)
            htADRS.setTreeAddress(idx_tree)
            SIG_tmp = SIG_HT[j*(self.hp + self.len)*self.n:
                             (j+1)*(self.hp + self.len)*self.n]
            node = self.xmss_pkFromSig(idx_leaf, SIG_tmp, node,
                                       pk_seed, htADRS)
        if node == pk_root:
            return True
        else:
            return False

    def fors_skGen(self, sk_seed: bytes, pk_seed: bytes, ADRS: ADRS, idx: int) -> bytes:
        """Generates a FORS private-key value.

        Args:
            sk_seed (bytes): _description_
            pk_seed (bytes): _description_
            ADRS (ADRS): _description_
            idx (int): secret key index

        Returns:
            bytes: FORS private key
        """
        skADRS = ADRS.copy()
        skADRS.setTypeAndClear(skADRS.FORS_PRF)
        skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        skADRS.setTreeIndex(idx)
        return self.prf(pk_seed, sk_seed, skADRS)

    def fors_node(self, sk_seed: bytes, i: int, z: int, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Computes the root of a Merkle subtree of FORS public values.

        Args:
            sk_seed (bytes): secret seed
            i (int): traget noded index
            z (int): target node height
            pk_seed (bytes): public seed
            ADRS (ADRS): address

        Returns:
            bytes: n-byte root node
        """
        if z == 0:
            sk = self.fors_skGen(sk_seed, pk_seed, ADRS, i)
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex(i)
            node = self.f(pk_seed, ADRS, sk)
        else:
            lnode = self.fors_node(sk_seed, 2 * i, z - 1, pk_seed, ADRS)
            rnode = self.fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, ADRS)
            ADRS.setTreeHeight(z)
            ADRS.setTreeIndex(i)
            node = self.hh(pk_seed, ADRS, lnode + rnode)
        return node

    def fors_sign(self, md: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Generates a FORS signature

        Args:
            md (bytes): message digest
            sk_seed (bytes): secret seed
            pk_seed (bytes): public seed
            ADRS (ADRS): address

        Returns:
            bytes: FORS signature
        """
        SIG_FORS = bytes()
        indices = base_2b(md, self.a, self.k)

        for i in range(self.k):
            SIG_FORS = SIG_FORS+self.fors_skGen(sk_seed, pk_seed, ADRS,
                                                (i << self.a) + indices[i])
            AUTH = bytes()
            for j in range(self.a):
                s = (indices[i] >> j) ^ 1
                AUTH += self.fors_node(sk_seed,
                                       (i << (self.a - j)) + s, j,
                                       pk_seed, ADRS)
            SIG_FORS = SIG_FORS + AUTH
        return SIG_FORS

    def fors_pkFromSig(self, SIG_FORS: bytes, md: bytes, pk_seed: bytes, ADRS: ADRS) -> bytes:
        """Computes a FORS public key from a FORS signature.

        Args:
            SIG_FORS (bytes): FORS signature
            md (bytes): message digest
            pk_seed (bytes): public seed
            ADRS (ADRS): address

        Returns:
            bytes: FORS public key
        """
        indices = base_2b(md, self.a, self.k)
        root = bytes()
        for i in range(self.k):
            sk = SIG_FORS[i*(self.a+1)*self.n:(i*(self.a+1)+1)*self.n]
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex((i << self.a) + indices[i])
            node_0 = self.f(pk_seed, ADRS, sk)
            AUTH = SIG_FORS[(i*(self.a+1)+1)*self.n:(i+1)*(self.a+1)*self.n]
            for j in range(self.a):
                ADRS.setTreeHeight(j + 1)
                if (indices[i] >> j) & 1 == 0:
                    ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
                    node_1 = self.hh(pk_seed, ADRS, node_0 +
                                     AUTH[j*self.n:(j+1)*self.n])
                else:
                    ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
                    node_1 = self.hh(
                        pk_seed, ADRS, AUTH[j*self.n:(j+1)*self.n] + node_0)
                node_0 = node_1
            root += node_0

        forspkADRS = ADRS.copy()
        forspkADRS.setTypeAndClear(forspkADRS.FORS_ROOTS)
        forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk = self.tl(pk_seed, forspkADRS, root)
        return pk

    def slh_keygen_internal(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> tuple:
        """Generates an SLH-DSA key pair.

        Args:
            sk_seed (bytes): _description_
            sk_prf (bytes): _description_
            pk_seed (bytes): _description_

        Returns:
            tuple: (sk, pk)
        """
        slhADRS = ADRS(toByte(0, 32))
        slhADRS.setLayerAddress(self.d-1)
        pk_root = self.xmss_node(sk_seed, 0, self.hp, pk_seed, slhADRS)
        return ((sk_seed+sk_prf+pk_seed+pk_root), (pk_seed+pk_root))

    def slh_sign_internal(self, M: bytes, sk: bytes, addrnd: bytes) -> bytes:
        """Generates an SLH-DSA signature.

        Args:
            M (bytes): mesasge
            sk (bytes): secret key
            addrnd (bytes): randomness

        Returns:
            bytes: signature
        """
        sk_seed = sk[0:  self.n]
        sk_prf = sk[self.n:2*self.n]
        pk_seed = sk[2*self.n:3*self.n]
        pk_root = sk[3*self.n:]
        slhADRS = ADRS(toByte(0, 32))
        opt_rand = addrnd
        if self.deterministic:
            opt_rand = pk_seed

        R = self.prf_msg(sk_prf, opt_rand, M)
        SIG = R
        digest = self.h_msg(R, pk_seed, pk_root, M)
        part1 = (self.k * self.a + 7) >> 3
        part2 = (self.h-(self.h//self.d)+7) >> 3
        part3 = (self.h+(self.d << 3)-1)//(self.d << 3)
        md = digest[0:part1]
        tmp_idx_tree = digest[part1:part1+part2]
        tmp_idx_leaf = digest[part1+part2:part1+part2+part3]
        idx_tree = toInt(tmp_idx_tree, part2) % (1 << (self.h-self.h//self.d))
        idx_leaf = toInt(tmp_idx_leaf, part3) % (1 << (self.h//self.d))

        slhADRS.setTreeAddress(idx_tree)
        slhADRS.setTypeAndClear(slhADRS.FORS_TREE)
        slhADRS.setKeyPairAddress(idx_leaf)

        SIG_FORS = self.fors_sign(md, sk_seed, pk_seed, slhADRS)
        SIG = SIG + SIG_FORS
        pk_fors = self.fors_pkFromSig(SIG_FORS, md, pk_seed, slhADRS)
        SIG_HT = self.ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)
        SIG = SIG + SIG_HT

        return SIG

    def slh_verify_internal(self, M: bytes, SIG: bytes, pk: bytes) -> bool:
        """Verifies an SLH-DSA signature

        Args:
            M (bytes): message
            SIG (bytes): signature
            pk (bytes): public key

        Returns:
            bool: result
        """
        if len(SIG) != (1+self.k*(1+self.a)+self.h+self.d*self.len)*self.n:
            return False

        pk_seed = pk[:self.n]
        pk_root = pk[self.n:]

        slhADRS = ADRS(toByte(0, 32))
        R = SIG[0:self.n]
        SIG_FORS = SIG[self.n:(1+self.k*(1+self.a))*self.n]
        SIG_HT = SIG[(1 + self.k*(1 + self.a))*self.n:]

        digest = self.h_msg(R, pk_seed, pk_root, M)
        part1 = (self.k * self.a + 7) >> 3
        part2 = (self.h-(self.h//self.d)+7) >> 3
        part3 = (self.h+(self.d << 3)-1)//(self.d << 3)
        md = digest[0:part1]
        tmp_idx_tree = digest[part1:part1+part2]
        tmp_idx_leaf = digest[part1+part2:part1+part2+part3]
        idx_tree = toInt(tmp_idx_tree, part2) % (1 << (self.h-self.h//self.d))
        idx_leaf = toInt(tmp_idx_leaf, part3) % (1 << (self.h//self.d))

        slhADRS.setTreeAddress(idx_tree)
        slhADRS.setTypeAndClear(slhADRS.FORS_TREE)
        slhADRS.setKeyPairAddress(idx_leaf)

        pk_fors = self.fors_pkFromSig(SIG_FORS, md, pk_seed, slhADRS)
        return self.ht_verify(pk_fors, SIG_HT, pk_seed,
                              idx_tree, idx_leaf, pk_root)

    def slh_keygen(self) -> tuple:
        """Generates an SLH-DSA key pair.

        Raises:
            ValueError: random bit generation failed

        Returns:
            tuple: (sk,pk)
        """
        sk_seed = self.randomizer(self.n)
        sk_prf = self.randomizer(self.n)
        pk_seed = self.randomizer(self.n)

        if sk_seed == None or sk_prf == None or pk_seed == None:
            raise ValueError("random bit generation failed")
        return self.slh_keygen_internal(sk_seed, sk_prf, pk_seed)

    def slh_sign(self, M: bytes, ctx: bytes, sk: bytes) -> bytes:
        """Generates a pure SLH-DSA signature.

        Args:
            M (bytes): message
            ctx (bytes): extre string
            sk (bytes): secret key

        Raises:
            ValueError: the context string is too long
            ValueError: random bit generation failed

        Returns:
            bytes: signature
        """
        if len(ctx) > 255:
            raise ValueError("the context string is too long")
        addrnd = self.randomizer(self.n)
        if addrnd == None:
            raise ValueError("random bit generation failed")
        M1 = toByte(0, 1)+toByte(len(ctx), 1)+ctx+M
        SIG = self.slh_sign_internal(M1, sk, addrnd)
        return SIG

    def hash_slh_sign(self, M: bytes, ctx: bytes, PH: str, sk: bytes) -> bytes:
        """Generates a pre-hash SLH-DSA signature.

        Args:
            M (bytes): message
            ctx (bytes): _description_
            PH (str): pre-hash function."sha-256","sha-512","shake-128","shake-256"
            sk (bytes): secret key

        Raises:
            ValueError: the context string is too long
            ValueError: random bit generation failed

        Returns:
            bytes: signature
        """
        if len(ctx) > 255:
            raise ValueError("the context string is too long")
        addrnd = self.randomizer(self.n)
        if addrnd == None:
            raise ValueError("random bit generation failed")
        if PH == "sha-256":
            OID = toByte(0x0609608648016503040201, 11)
            PH_M = sha256(M).digest()
        elif PH == "sha-512":
            OID = toByte(0x0609608648016503040203, 11)
            PH_M = sha512(M).digest()
        elif PH == "shake-128":
            OID = toByte(0x060960864801650304020B, 11)
            PH_M = shake_128(M).digest(32)
        elif PH == "shake-256":
            OID = toByte(0x060960864801650304020C, 11)
            PH_M = self.sha_256(M)

        M1 = toByte(1, 1)+toByte(len(ctx), 1)+ctx+OID+PH_M
        SIG = self.slh_sign_internal(M1, sk, addrnd)
        return SIG

    def slh_verify(self, M: bytes, SIG: bytes, ctx: bytes, pk: bytes) -> bool:
        """Verifies a pure SLH-DSA signature.

        Args:
            M (bytes): message
            SIG (bytes): signature
            ctx (bytes): extra string
            pk (bytes): public key

        Raises:
            ValueError: the context string is too long

        Returns:
            bool: result
        """
        if len(ctx) > 255:
            raise ValueError("the context string is too long")
        M1 = toByte(0, 1)+toByte(len(ctx), 1)+ctx+M
        return self.slh_verify_internal(M1, SIG, pk)

    def hash_slh_verify(self, M: bytes, SIG: bytes, ctx: bytes, PH: str, pk: bytes) -> bool:
        """Verifies a pre-hash SLH-DSA signature.

        Args:
            M (bytes): message
            ctx (bytes): extra string
            PH (str): pre-hash function."sha-256","sha-512","shake-128","shake-256"
            pk (bytes): public key

        Raises:
            ValueError: the context string is too long
            ValueError: random bit generation failed

        Returns:
            bool: result
        """
        if len(ctx) > 255:
            raise ValueError("the context string is too long")
        addrnd = self.randomizer(self.n)
        if addrnd == None:
            raise ValueError("random bit generation failed")
        if PH == "sha-256":
            OID = toByte(0x0609608648016503040201, 11)
            PH_M = sha256(M).digest()
        elif PH == "sha-512":
            OID = toByte(0x0609608648016503040203, 11)
            PH_M = sha512(M).digest()
        elif PH == "shake-128":
            OID = toByte(0x060960864801650304020B, 11)
            PH_M = shake_128(M).digest(32)
        elif PH == "shake-256":
            OID = toByte(0x060960864801650304020C, 11)
            PH_M = self.sha_256(M)
        M1 = toByte(1, 1)+toByte(len(ctx), 1)+ctx+OID+PH_M
        return self.slh_verify_internal(M1, SIG, pk)

    def SLH_DSA_SHA2_128s():
        return SLH_DSA(hashname='SHA2', paramid='s',
                       n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30)

    def SLH_DSA_SHAKE_128s():
        return SLH_DSA(hashname='SHAKE', paramid='s',
                       n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30)

    def SLH_DSA_SHA2_128f():
        return SLH_DSA(hashname='SHA2', paramid='f',
                       n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34)

    def SLH_DSA_SHAKE_128f():
        return SLH_DSA(hashname='SHAKE', paramid='f',
                       n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34)

    def SLH_DSA_SHA2_192s():
        return SLH_DSA(hashname='SHA2', paramid='s',
                       n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39)

    def SLH_DSA_SHAKE_192s():
        return SLH_DSA(hashname='SHAKE', paramid='s',
                       n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39)

    def SLH_DSA_SHA2_192f():
        return SLH_DSA(hashname='SHA2', paramid='f',
                       n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42)

    def SLH_DSA_SHAKE_192f():
        return SLH_DSA(hashname='SHAKE', paramid='f',
                       n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42)

    def SLH_DSA_SHA2_256s():
        return SLH_DSA(hashname='SHA2', paramid='s',
                       n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47)

    def SLH_DSA_SHAKE_256s():
        return SLH_DSA(hashname='SHAKE', paramid='s',
                       n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47)

    def SLH_DSA_SHA2_256f():
        return SLH_DSA(hashname='SHA2', paramid='f',
                       n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49)

    def SLH_DSA_SHAKE_256f():
        return SLH_DSA(hashname='SHAKE', paramid='f',
                       n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49)


def perforamnce(f: SLH_DSA, n: int = 10):
    M = os.urandom(6)
    ctx = b''
    keyGen_time, sigGen_time, sigVer_time = 0, 0, 0
    for i in range(n):
        time1 = time.time()
        sk, pk = f.slh_keygen()
        time2 = time.time()
        sig = f.slh_sign(M, ctx, sk)
        time3 = time.time()
        f.slh_verify(M, sig, ctx, pk)
        time4 = time.time()
        keyGen_time += time2-time1
        sigGen_time += time3-time2
        sigVer_time += time4-time3
    print("keyGen Cost:", keyGen_time/n)
    print("sigGen Cost:", sigGen_time/n)
    print("sigVer Cost", sigVer_time/n)


def evaluate_all():
    """evaluate the  perfromance of SLH-DSA under different standards
    """
    SLH_DSA_ALL = [SLH_DSA.SLH_DSA_SHA2_128f(),  SLH_DSA.SLH_DSA_SHA2_128s(),
                   SLH_DSA.SLH_DSA_SHA2_192f(),  SLH_DSA.SLH_DSA_SHA2_192s(),
                   SLH_DSA.SLH_DSA_SHA2_256f(),  SLH_DSA.SLH_DSA_SHA2_256s(),
                   SLH_DSA.SLH_DSA_SHAKE_128f(), SLH_DSA.SLH_DSA_SHAKE_128s(),
                   SLH_DSA.SLH_DSA_SHAKE_192f(), SLH_DSA.SLH_DSA_SHAKE_192s(),
                   SLH_DSA.SLH_DSA_SHAKE_256f(), SLH_DSA.SLH_DSA_SHAKE_256s()]
    for f in SLH_DSA_ALL:
        print(f.stdname)
        perforamnce(f)
        print("**********************")


if __name__ == "__main__":
    # evaluate_all()
    M = os.urandom(3)
    ctx = b''
    case = SLH_DSA.SLH_DSA_SHA2_128f()
    sk, pk = case.slh_keygen()
    sig = case.hash_slh_sign(M, ctx, "sha-256", sk)
    print(case.hash_slh_verify(M, sig, ctx, "sha-256", pk))
