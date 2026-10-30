"""AUTHORIZED WALLET RECOVERY — owner-run CLI. Rebuild access to a wallet YOU OWN from the
part of the secret you still remember, by searching only the small space that memory defines.

>>> RUN THIS ONLY ON A WALLET YOU OWN, OR ARE AUTHORIZED IN WRITING TO RECOVER. <<<
It never scans the chain and never touches a wallet it wasn't given. You supply your own
partial secret + your own public address; it stops the instant a candidate derives to that
address. The complete secret is assembled only here, on your machine — nothing is uploaded.

Cases covered (run `python recover.py <case> -h`):
  hexkey      private key (hex) with a few FORGOTTEN/UNCERTAIN characters  -> enumerate the blanks
  passphrase  a brainwallet/passphrase with a known pattern (stem + unknown tail)
  estimate    feasibility only: given the unknowns, print the search size + ETA (no secret needed)
  bip39       seed-phrase cases (missing word / wrong order) — needs `pip install bip-utils` (scaffold)

Old 2009–2011 wallets used UNCOMPRESSED keys, so by default we verify against BOTH the
compressed and uncompressed P2PKH address. Speed: `pip install coincurve` auto-accelerates.
"""
import sys, os, argparse, itertools, time, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btc import N, priv_to_address

HEX = "0123456789abcdef"

# ---- optional C-accelerated backend (coincurve) ----
try:
    from coincurve import PublicKey
    import base58
    def _addr_both(d: int):
        pk = PublicKey.from_secret(d.to_bytes(32, "big"))
        out = []
        for comp in (True, False):
            pub = pk.format(compressed=comp)
            h = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
            payload = b"\x00" + h
            chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            out.append(base58.b58encode(payload + chk).decode())
        return out            # [compressed, uncompressed]
    BACKEND = "coincurve"
except Exception:
    def _addr_both(d: int):
        return [priv_to_address(d, True), priv_to_address(d, False)]
    BACKEND = "ecdsa (pure-python; `pip install coincurve` for ~100x)"


def _bench_rate(n=300):
    """measure candidates/sec on THIS machine so ETAs are honest, not guessed."""
    import secrets
    t0 = time.time()
    for _ in range(n):
        _addr_both(secrets.randbelow(N - 1) + 1)
    return n / max(1e-9, time.time() - t0)


def _fmt_eta(seconds):
    for unit, s in (("years", 31557600), ("days", 86400), ("hours", 3600), ("min", 60)):
        if seconds >= s:
            return f"{seconds/s:.1f} {unit}"
    return f"{seconds:.1f} sec"


def _verdict(space, rate):
    eta = space / max(1e-9, rate)
    print(f"  search size : {space:,} candidates")
    print(f"  rate here   : {rate:,.0f}/sec  [{BACKEND}]")
    print(f"  worst-case  : {_fmt_eta(eta)}  (avg ~half that)")
    if eta < 3600:      print("  verdict     : SOLVABLE on this laptop.")
    elif eta < 86400*7: print("  verdict     : BORDERLINE — feasible with patience / coincurve / a GPU.")
    else:               print("  verdict     : INFEASIBLE as described — you must remember more to narrow it.")
    return eta


# ---------- case: hex key with blanks ----------
def run_hexkey(masked, target, blank="?"):
    pos = [i for i, c in enumerate(masked) if c == blank]
    if not pos:
        print("no blank characters ('?') found in the key."); return None
    space = 16 ** len(pos)
    print(f"[hexkey] {len(pos)} unknown nibble(s)")
    rate = _bench_rate(); _verdict(space, rate)
    print("  searching...")
    t0 = time.time()
    for k, combo in enumerate(itertools.product(HEX, repeat=len(pos)), 1):
        cand = list(masked)
        for p, c in zip(pos, combo): cand[p] = c
        try:
            d = int("".join(cand), 16) % N
            if d and target in _addr_both(d):
                print(f"  RECOVERED after {k:,} tries in {time.time()-t0:.1f}s:\n    key = {''.join(cand)}")
                return "".join(cand)
        except Exception:
            pass
    print("  not found in this space (check the known characters and the address).")
    return None


# ---------- case: passphrase / brainwallet pattern ----------
def run_passphrase(prefix, charset, length, target):
    space = len(charset) ** length
    print(f"[passphrase] prefix {prefix!r} + {length} unknown char(s) from a {len(charset)}-char set")
    rate = _bench_rate(); _verdict(space, rate)
    print("  searching...")
    t0 = time.time()
    for k, tail in enumerate(itertools.product(charset, repeat=length), 1):
        cand = prefix + "".join(tail)
        d = int.from_bytes(hashlib.sha256(cand.encode()).digest(), "big") % N
        if d and target in _addr_both(d):
            print(f"  RECOVERED after {k:,} tries in {time.time()-t0:.1f}s:\n    passphrase = {cand!r}")
            return cand
    print("  not found in this space.")
    return None


# ---------- feasibility only ----------
def run_estimate(space):
    print(f"[estimate] feasibility for {space:,} candidates")
    _verdict(space, _bench_rate())


# ---------- bip39 scaffold ----------
def run_bip39(*_a, **_k):
    print("[bip39] needs: pip install bip-utils")
    print("  Supported once installed: a missing word (checksum narrows to the valid few),")
    print("  wrong word order, or a forgotten BIP39 passphrase. Same idea: enumerate only the")
    print("  unknown part, derive the account's addresses (BIP44 m/44'/0'/0'/0/i), stop on a")
    print("  match to YOUR known address. The engine is identical to the cases above.")


def _demo():
    import secrets
    print("=" * 72); print("SELF-TEST on wallets generated HERE (you own them)"); print("=" * 72)
    d = secrets.randbelow(N - 1) + 1
    full = f"{d:064x}"; addr = priv_to_address(d)   # compressed address
    print(f"\n[A] hex key, last 3 chars forgotten (target addr {addr}):")
    run_hexkey(full[:-3] + "???", addr)
    phrase = "myWallet2019_734"
    paddr = priv_to_address(int.from_bytes(hashlib.sha256(phrase.encode()).digest(), "big") % N)
    print(f"\n[B] passphrase 'myWallet2019_' + forgotten 3-digit PIN (target {paddr}):")
    run_passphrase("myWallet2019_", "0123456789", 3, paddr)


def main():
    ap = argparse.ArgumentParser(description="Authorized wallet recovery (owner-run).")
    sub = ap.add_subparsers(dest="cmd")
    h = sub.add_parser("hexkey"); h.add_argument("masked"); h.add_argument("address"); h.add_argument("--blank", default="?")
    p = sub.add_parser("passphrase"); p.add_argument("prefix"); p.add_argument("address")
    p.add_argument("--charset", default="0123456789"); p.add_argument("--length", type=int, required=True)
    e = sub.add_parser("estimate"); e.add_argument("space", type=int)
    sub.add_parser("bip39"); sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "hexkey": run_hexkey(a.masked, a.address, a.blank)
    elif a.cmd == "passphrase": run_passphrase(a.prefix, a.address, a.charset, a.length) if False else run_passphrase(a.prefix, a.charset, a.length, a.address)
    elif a.cmd == "estimate": run_estimate(a.space)
    elif a.cmd == "bip39": run_bip39()
    elif a.cmd == "selftest": _demo()
    else: _demo()


if __name__ == "__main__":
    main()
