# flashattack

Target-agnostic toolkit for the flash-accelerator AES timing side channel. The
**exploitation engine is independent of any board or firmware** — those live under
[`../hardware/`](../hardware/) and may move to another project. This package is the
part worth keeping and generalising.

## Layout
```
flashattack/
  aesref.py      reference AES-128/192/256 (enc/dec, key-schedule + inversion), FIPS-197 verified
  sm4.py         SM4 (GM/T 0002) reference + partial leak (Feistel -> top-nibble only; see EXPERIMENTAL.md)
  EXPERIMENTAL.md  partial results & their structural ceilings (known-plaintext-only; SM4)
  bruteforce.py  batched multi-key AES: 2^24 candidate keys in ~26 s (finishes an uneven vote)
  engine.py      unified last-round cache-collision engine + robust assembler; recover_full (192/256)
  modes.py       AES mode -> block the attacker reconstructs (ECB/CBC/CTR/GCM/CMAC, enc+dec)
  capture.py     Capture: target-agnostic OBSERVED data (pt/ct + timing, NO key); save/load npz, from_csv
  sources.py     TraceSource interface (Recorded/Array/SerialModes) -- the extension point for agents
  attack.py      attack(capture, verify=...) -> AttackReport (JSON/summary); unknown-key entry point
  tvla.py        quick check: constant-time detector, key-free exploitability, fixed-vs-random t-test
  stats.py       jitter-robust preprocessing: trim, detrend (drift), min-filter
  transport.py   serial target + timing sources (on-chip batch; host ACK-latency w/ amplify+min-filter)
  feasibility.py trace-count estimate + amplification (K) advice from a pilot capture
  boards.py      board descriptors (L552/G474/F429/F303): part, VCP, cache size, ACR presets
  cli.py         `python -m flashattack {selftest,attack,boot,feasibility,assess,attack-file}`
```

## Working with recorded data / any interface (no key needed)
The engine consumes a **Capture** (observed data + timing, no key). Build one from
a file, from arrays, or from your own interface, and attack it:
```python
from flashattack import Capture, run_attack
cap = Capture(timing=t, mode="ctr", plaintext=pt, ciphertext=ct)   # observed; no key
report = run_attack(cap, verify=(known_pt, known_ct))              # key used only to verify
print(report.summary()); print(report.to_json())
```
To add a **new hardware interface or data format**, implement one method
(`sources.TraceSource.capture() -> Capture`) — nothing else in the tool changes.
CLI on recorded files: `attack-file --file cap.npz [--verify-pt .. --verify-ct ..] [--json]`.

## Quick vulnerability check (before committing to full recovery)
```bash
python -m flashattack assess --file cap.npz        # constant-time? exploitable? ~traces-to-break
```
`tvla.assess` returns a constant-time verdict (std≈0) and, if data-dependent, a
key-free collision-margin strength estimate. (A first-order/Bernstein test is flat
for this channel, so the check measures the *pairwise collision* the attack uses.)

## Engine

```python
from flashattack import engine, modes, aesref
known, direction = modes.known_output("ctr", material, key)   # material = per-trace input bytes
res = engine.recover(known, timing, direction=direction, keysize=128,
                     verify=(pt, ct))          # optional known PT/CT enables verify+brute-force
print(res.summary())                            # -> master key, verified True/False
```

`recover` scans all 120 output-byte pairs (layout-agnostic: S-box or T-table),
assembles each key byte by a **margin-weighted vote** across the 15 pairs that
touch it, then — if a known plaintext/ciphertext pair is given — **verifies the
key and brute-forces the low-confidence bytes** (full 0..255 over the positions
whose confidence gap flags them) until it matches. This turns near-misses
(e.g. 13/16, 15/16) into exact recovery.

- `direction="enc"` (attacker knows the ciphertext / keystream block) → recovers
  the last round key → master via schedule inversion.
- `direction="dec"` (firmware image case; attacker knows the InvCipher output) →
  recovers the first round key, which for AES-128 **is** the master key.
- **`keysize` 128 / 192 / 256 all supported end-to-end on unmodified firmware.**
  For 192/256, `engine.recover_full` also recovers the second-to-last round key
  via a MixColumns-linearity reduction (byte-wise, same traces) and inverts the
  schedule to the master:
  ```python
  r = engine.recover_full(ct, timing, keysize=256, line_shift_last=4,
                          line_shift_prev=2, verify=(pt, ct_known))
  print(r["master"], r["verified"])
  ```
  `line_shift_prev` = the round Nr-1 table granularity (2 = 4-byte T-table,
  4 = S-box). CLI: `attack --full`.

## bruteforce.py -- many keys, one block

`aesref` runs one key over many blocks. `bruteforce` runs **many keys over one
block**, which is the shape the endgame of an uneven attack needs: the vote
leaves a few bytes undetermined, and finishing them key-by-key in Python is
hours where a vectorised search is seconds. Round keys become an `(n, 11, 16)`
array and everything else is the same table lookups and XORs.

Measured at **0.44 M keys/s**, so 2^16 is instant and **2^24 about 26 s**;
verified byte-for-byte against `aesref` for the key schedule, its inversion and
the decryption. `search_positions()` filters candidates on CCM counter-block
structure, which needs no known plaintext -- see `demos/oscore/verify.py`.
It earns its place on the F746 OSCORE victim, where the leak is uneven enough
that the vote stalls three bytes short of the key.

`search_pairs()` is the cheaper and better-behaved endgame: all C(16,2) = 120
position pairs at 2^16 each is 7.9 M candidates -- less than one 2^24 search --
and it recovers **any** vote that is right on 14 of 16 bytes, wherever the wrong
two sit. That matters because escalating to the *least confident* positions
assumes the vote knows which bytes it got wrong, and it often does not: on the
F429 OSCORE capture at 300 k traces the two wrong bytes rank 1st and 4th by
confidence, so the ranked search misses one. Switching to the pair sweep halved
that attack's capture, 600 k traces to 300 k.

## CLI

```bash
python -m flashattack selftest                              # hardware-free smoke test
python -m flashattack attack  --port COM9 --mode ctr --n 150000 --acr 00000705 --verify
python -m flashattack boot    --port COM9 --n 60000 --K 255 --verify   # ACK-latency oracle
python -m flashattack feasibility --port COM9 --mode ecb-dec --n 20000
```

## Tests (two tiers)
```bash
PYTHONPATH=. pytest                 # QUICK CI: fast unit tests only (seconds)
PYTHONPATH=. pytest --runslow       # LONG: + engine scans + replay of captured vectors
```
- **Quick** (`test_flashattack.py`, default): FIPS-197 vectors (128/192/256),
  key-schedule inversion, mode-mapping consistency — no hardware, no big data.
- **Long** (`--runslow`): synthetic recovery (clean + brute-force rescue) and
  **replay of real captured trace vectors** in `tests/vectors/*.npz`
  (S-box + T-table, several key sizes/modes). Capture more with
  `tests/make_vectors.py`. Vectors store only timing (uint16, seed-regenerated
  material) so each is ~100–250 KB compressed and lives in git.
- The same two tiers cover [`demos/oscore/`](../demos/oscore/)
  (`demos/oscore/test_replay.py`), which replays the **over-Ethernet** captures
  and re-derives the OSCORE key and its negative control. `--runslow` there is
  the key recovery itself.
- `conftest.py` lives at the repository root so both test directories share one
  `--runslow` option.
