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
- `keysize` 128 fully supported end-to-end; 192/256 reference + inversion present,
  full recovery needs multi-round-key extraction (round-1 + last-round) — future.

## CLI

```bash
python -m flashattack selftest                              # hardware-free smoke test
python -m flashattack attack  --port COM9 --mode ctr --n 150000 --acr 00000705 --verify
python -m flashattack boot    --port COM9 --n 60000 --K 255 --verify   # ACK-latency oracle
python -m flashattack feasibility --port COM9 --mode ecb-dec --n 20000
```

## Tests
```bash
PYTHONPATH=. pytest tests/test_flashattack.py
```
FIPS-197 vectors, schedule inversion, mode-mapping consistency, and synthetic
recovery (clean + brute-force rescue) — no hardware required.
