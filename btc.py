"""Minimal, offline Bitcoin key→address helper (secp256k1 → P2PKH).
Pure-python RIPEMD-160 fallback so it runs even where OpenSSL dropped it.
No network, no key storage. Used by the educational demo and the authorized recovery tool."""
import hashlib, base58
from ecdsa import SigningKey, SECP256k1

CURVE = SECP256k1
N = CURVE.order
G = CURVE.generator


def _ripemd160(b: bytes) -> bytes:
    try:
        h = hashlib.new("ripemd160"); h.update(b); return h.digest()
    except Exception:
        return _ripemd160_pure(b)


def priv_to_pub(d: int, compressed=True) -> bytes:
    """private int d -> SEC public key bytes."""
    P = d * G
    x, y = P.x(), P.y()
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def hash160(b: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(b).digest())


def pub_to_address(pub: bytes, version=0x00) -> str:
    """SEC pubkey -> base58check P2PKH address (version 0x00 = mainnet '1...')."""
    payload = bytes([version]) + hash160(pub)
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()


def priv_to_address(d: int, compressed=True) -> str:
    return pub_to_address(priv_to_pub(d, compressed))


# ---- pure RIPEMD-160 (reference implementation) ----
def _ripemd160_pure(message: bytes) -> bytes:
    import struct
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    rl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    kl = [0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e]
    kr = [0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000]
    f = [lambda x,y,z: x^y^z, lambda x,y,z:(x&y)|(~x&z), lambda x,y,z:(x|~y)^z,
         lambda x,y,z:(x&z)|(y&~z), lambda x,y,z:x^(y|~z)]
    h0,h1,h2,h3,h4 = 0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0
    msg = bytearray(message); ml = len(message)*8
    msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg += struct.pack("<Q", ml)
    for off in range(0,len(msg),64):
        X = list(struct.unpack("<16I", msg[off:off+64]))
        al,bl,cl,dl,el = h0,h1,h2,h3,h4; ar,br,cr,dr,er = h0,h1,h2,h3,h4
        for j in range(80):
            rnd=j//16
            t=(al+f[rnd](bl,cl,dl)+X[rl[j]]+kl[rnd])&0xffffffff
            t=(rol(t,sl[j])+el)&0xffffffff; al,el,dl,cl,bl=el,dl,rol(cl,10),bl,t
            rnd2=4-rnd
            t=(ar+f[rnd2](br,cr,dr)+X[rr[j]]+kr[rnd])&0xffffffff
            t=(rol(t,sr[j])+er)&0xffffffff; ar,er,dr,cr,br=er,dr,rol(cr,10),br,t
        t=(h1+cl+dr)&0xffffffff
        h1=(h2+dl+er)&0xffffffff; h2=(h3+el+ar)&0xffffffff
        h3=(h4+al+br)&0xffffffff; h4=(h0+bl+cr)&0xffffffff; h0=t
    return struct.pack("<5I", h0,h1,h2,h3,h4)


if __name__ == "__main__":
    # self-test against a known vector: priv=1 -> known pubkey/address
    d = 1
    addr = priv_to_address(d, compressed=True)
    print("priv=1 compressed address:", addr)
    assert addr == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", addr
    print("btc.py self-test OK")
