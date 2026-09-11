# flashattack

Target-agnostic toolkit for the flash-accelerator AES timing side channel. The
**exploitation engine is independent of any board or firmware** — those live under
[`../hardware/`](../hardware/) and may move to another project. This package is the
part worth keeping and generalising.

## Layout
```
flashattack/
  aesref.py      reference AES-128/192/256 (enc/dec, key-schedule + inversion), FIPS-197 verified
  engine.py      unified last-round cache-collision engine + robust key assembler
  modes.py       AES mode -> the block-cipher output the attacker reconstructs (ECB/CBC/CTR/GCM, enc+dec)
  transport.py   serial target + timing sources (on-chip batch; host ACK-latency w/ amplification+min-filter)
  feasibility.py trace-count estimate + amplification (K) advice from a pilot capture
  boards.py      board descriptors (L552/G474/F429/F303): part, VCP, cache size, ACR presets
  cli.py         `python -m flashattack {selftest,attack,boot,feasibility}`
```

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

