# Intake & free feasibility assessment — operator playbook

The free assessment is the whole trust pitch: tell the client **honestly** whether it's solvable
*before* anyone pays or signs. This is how you run it.

## Step 1 — gather (from the lead / form), never the full secret
Ask only for:
1. **Coin + public address** (safe to share; it's on the chain).
2. **Which case** it is, and exactly **what's unknown**:
   - *Hex/WIF private key* — how many characters are forgotten or uncertain, and roughly where.
   - *Passphrase/brainwallet* — the part they remember (stem) + the shape of the unknown part
     (length, character set: digits? letters? symbols?).
   - *BIP39 seed* — how many words are missing / possibly out of order; any BIP39 passphrase.
   - *Encrypted wallet file* (`wallet.dat`, keystore) — what they remember of the password.
3. **Wallet software + era.** 2009–2011 ≈ Bitcoin Core, **uncompressed** keys (the tool checks both).

> ⚠ Never accept a full private key or full seed. If a client pastes one, stop and tell them to rotate.

## Step 2 — compute the search size
| Case | Size |
|------|------|
| Hex key, `b` forgotten nibbles | `16^b` |
| WIF/base58, `b` forgotten chars | `58^b` (prune with the checksum) |
| Passphrase, `L` unknown chars from a `C`-char set | `C^L` |
| BIP39, 1 missing word | ~`2048 / 16` valid by checksum, ×derivation paths |
| BIP39, `w` words wrong order | up to `w!` permutations |
| Wallet password, known pattern | product of the unknown parts |

## Step 3 — get an honest verdict (measured, not guessed)
Run the estimator; it benchmarks this machine's real rate and prints an ETA + verdict:
```
python recovery/recover.py estimate <search_size>
```
Buckets: **SOLVABLE** (< ~1 h on a laptop) · **BORDERLINE** (feasible with `coincurve` / a GPU / patience)
· **INFEASIBLE** (they must remember more to narrow it). Speed levers for borderline cases:
`pip install coincurve` (~100×), run on a GPU box, or narrow the character set with better memory.

## Step 4 — reply honestly
- **Solvable / borderline:** explain the size + ETA, send the engagement + authorization
  (`AUTHORIZATION.md`), agree the success %, then run (ideally on *their* machine):
  `python recovery/recover.py hexkey <masked?key> <address>` or
  `python recovery/recover.py passphrase <stem> <address> --charset <set> --length <n>`.
- **Infeasible:** say so plainly, charge nothing. Do **not** sell hope on a search larger than the
  universe — that's the exact thing the explainer teaches.

## Hard DECLINE triggers (non-negotiable)
- Can't substantiate ownership / authorization → decline.
- Wants a wallet they don't own, or a "found"/"abandoned"/dormant third-party address → decline, it's theft.
- Asks to scan/enumerate many addresses for weak keys → decline.
- Found a live weakness in someone else's wallet → responsible disclosure to the owner, **never** a sweep.
