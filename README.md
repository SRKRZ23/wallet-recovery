# wallet-recovery

**Authorized** crypto-wallet recovery — rebuild access to a wallet **you own** from the part of the
secret you still remember. Runs entirely on your own machine, offline; your secret never leaves it.

> Companion to the interactive explainer **[how-bitcoin-crypto-works.netlify.app](https://how-bitcoin-crypto-works.netlify.app)**.

## The one rule (what makes this legal)
✅ Recover a wallet **you own**, or are **authorized in writing** to recover (e.g. an heir/executor).
You supply **your own** partial secret + **your own** public address; the tool searches only the small
space your memory defines and stops when a candidate derives to your address.

❌ It does **not** scan the blockchain, does **not** enumerate strangers' addresses, and will not help
you "open" a wallet that isn't yours. A dormant/old/"lost" coin is not ownerless — it belongs to someone
or their heirs, and taking it is theft. If you ever find a weakness in someone else's wallet: **disclose
it to the owner, never sweep.** Possessing a stranger's key is the crime, published or not.

## Install
```bash
pip install walletrecover             # core (ecdsa, base58)
pip install "walletrecover[fast]"     # + coincurve, ~100x faster search
pip install "walletrecover[bip39]"    # + bip-utils, for seed-phrase cases
```

## Use — owner-run CLI
After `pip install`, the `walletrecover` command is available (from a clone instead, use
`python -m walletrecover.recover ...`):
```bash
# free feasibility check first — honest ETA + verdict, no secret needed
walletrecover estimate 16777216

# a hex private key with a few forgotten characters (mark them with ?)
walletrecover hexkey cdb98e...b353f9?? 1YourOwnAddress...

# a passphrase/brainwallet you remember the stem of (+ a forgotten tail)
walletrecover passphrase "myWallet2019_" 1YourOwnAddress... --charset 0123456789 --length 3

# built-in self-test on a wallet generated locally (proves it works)
walletrecover selftest
```
- Verifies against **both compressed and uncompressed** P2PKH addresses — old 2009–2011 Bitcoin Core
  wallets used uncompressed keys.
- `estimate` benchmarks your machine's real rate and prints **SOLVABLE / BORDERLINE / INFEASIBLE** — it
  won't sell hope on a search larger than the universe.
- BIP39 seed cases (missing word via checksum, wrong order, forgotten passphrase) activate with
  `pip install bip-utils` (scaffolded in `recover.py`).

## Also here
- **`weakkey_research.py`** — educational, white-hat: demonstrates the two famous failure *classes*
  (ECDSA reused-nonce, brainwallet/weak-entropy) on **self-generated** keys only. It teaches *why* weak
  keys fail; it holds no real key and touches nothing on-chain.
- **`AUTHORIZATION.md`** — engagement + written-authorization template (not legal advice).
- **`INTAKE.md`** — how to run an honest free feasibility assessment, with hard decline triggers.

## Why open-source a recovery tool?
So you don't have to trust a black box with your wallet. Read it, run it offline, keep your secret on
your own machine. Same spirit as other open recovery tools — the honesty is the product.

## License
MIT © Sardor Razikov. The cryptography (secp256k1, SHA-256, BIP39) is public and unbroken; recovery
relies on *your* remembered information, not on any weakness in the math.
