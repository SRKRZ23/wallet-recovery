"""WEAK-KEY RESEARCH — educational demonstration of two famous vulnerability CLASSES,
run entirely on keys WE generate here. This teaches *why* these bugs are fatal.

It does NOT scan the blockchain, does NOT touch anyone's funds, and holds no real keys.
White-hat use only: understand the failure, then (if ever found in the wild) report it to
the owner — never sweep it. The curve/hash are not broken; broken *randomness* is.
"""
import sys, os, hashlib, secrets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btc import N, G, priv_to_address
from ecdsa.numbertheory import inverse_mod

line = lambda: print("-" * 72)
def H(m: bytes) -> int: return int.from_bytes(hashlib.sha256(m).digest(), "big") % N


# ========== Class 1: ECDSA reused-nonce (PS3 2010, Android SecureRandom 2013) ==========
def reused_nonce_demo():
    print("\n[1] ECDSA reused-nonce  —  'same k twice reveals the private key'")
    line()
    d = secrets.randbelow(N - 1) + 1                 # the victim's secret (we made it)
    k = secrets.randbelow(N - 1) + 1                 # a nonce the buggy RNG REUSES
    def sign(msg):
        z = H(msg); r = (k * G).x() % N
        s = (inverse_mod(k, N) * (z + r * d)) % N
        return r, s, z
    r1, s1, z1 = sign(b"Pay Alice 1 BTC")
    r2, s2, z2 = sign(b"Pay Bob 2 BTC")              # DIFFERENT message, SAME k (the bug)
    print(f"  two signatures share r = {hex(r1)[:26]}…   <- the tell-tale sign of nonce reuse")
    # anyone with the two public signatures can now solve for k, then d:
    k_rec = ((z1 - z2) * inverse_mod((s1 - s2) % N, N)) % N
    d_rec = ((s1 * k_rec - z1) * inverse_mod(r1, N)) % N
    print(f"  recovered private key == victim's key?  {d_rec == d}")
    print(f"  lesson: the nonce k must be unique & unpredictable per signature. One reuse = total loss.")
    print(f"  (In 2013 a broken Android SecureRandom reused nonces and real BTC was stolen this way.)")


# ========== Class 2: weak entropy / brainwallets (low-entropy keys are enumerable) ==========
def brainwallet_demo():
    print("\n[2] Weak entropy / brainwallet  —  'a key from a guessable phrase is findable'")
    line()
    # a victim picks a 'clever' passphrase; the private key = sha256(passphrase). Low entropy.
    victim_phrase = "correct horse battery staple"
    d = int.from_bytes(hashlib.sha256(victim_phrase.encode()).digest(), "big") % N
    victim_addr = priv_to_address(d)
    print(f"  victim brainwallet address: {victim_addr}")
    # an auditor's tiny dictionary (real attackers use billions of phrases + leaks)
    dictionary = ["password", "bitcoin", "hunter2", "letmein",
                  "correct horse battery staple", "satoshi nakamoto", "to the moon"]
    for i, guess in enumerate(dictionary, 1):
        g = int.from_bytes(hashlib.sha256(guess.encode()).digest(), "big") % N
        if priv_to_address(g) == victim_addr:
            print(f"  FOUND after {i} guesses: the key came from {guess!r}")
            break
    print("  lesson: a key is only as strong as its ENTROPY. 256 bits of real randomness is unbreakable;")
    print("  a human-chosen phrase is a few dozen bits — enumerable in seconds. Use a real RNG / a hardware wallet.")


if __name__ == "__main__":
    print("=" * 72)
    print("WEAK-KEY VULNERABILITY CLASSES — educational demo on self-generated keys only")
    print("=" * 72)
    reused_nonce_demo()
    brainwallet_demo()
    print("\nBoth failures are about RANDOMNESS, not the math. secp256k1 and SHA-256 are fine.")
    print("White-hat rule: if you ever detect these in the wild, disclose to the owner — never sweep.")
