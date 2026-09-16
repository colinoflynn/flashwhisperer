# flashleak — is this black-box target leaking?

A leakage detector for someone who knows almost nothing about the target: bytes
go in or out of something doing crypto, and that is all. Not the mode, not
whether the bytes are plaintext or ciphertext, not whether the device encrypts
or decrypts, not the implementation. Every question is answered by a test whose
*outcome differs* between the possible answers.

It is deliberately separate from [`../flashattack/`](../flashattack/), which is
the key-recovery engine and assumes you already know all of that. flashleak
borrows two things from it — the AES tables and the 2^16 pair search — and
nothing else, so it is easy to lift out.

```bash
python -m flashleak analyse capture.npz          # recorded blocks + timings
python -m flashleak probe  mymod:MyTarget()      # drive a live device
python -m flashleak fwscan firmware.bin          # static triage before any hardware
python -m flashleak selftest                     # check it against known truth
```

## Before the hardware: `fwscan`

Cheapest question first — is this target even in scope? Given a firmware image
(a vendor's download, or a dump), `fwscan` reports whether the head parses as a
Cortex-M vector table (so it executes in place from flash, rather than being a
Linux image running from SDRAM), and then which AES table layout is present:

| what it finds | what it means |
|---|---|
| four T-tables (`Te0..Te3`) | round 2 resists; the last round still falls |
| one T-table + S-box | leaks, and is round-2 recoverable from one side |
| decryption T-tables (`Td0..Td3`) | 1 KB+ of inverse tables — exceeds the F2/F4 128 B **and** the G4/L4 256 B cache, so it leaks on every measured band. A bootloader is often decrypt-only and carries `Td` with no `Te` at all |
| Gladman `sbox`+`gfm2_sb`+`gfm3_sb` | the LoRaMac-node `soft-se` layout, broken here at 16/16 |
| byte S-box only | leaks wherever the data cache is smaller than 256 B |
| nothing | constant-time/bitsliced, or tables built into RAM — not exposed |

It is checked against the four firmware builds in `hardware/fw_f4_lib/` whose
keys were actually recovered on the F429, so the layouts it reports are known
truth rather than a guess (`tests/test_fwscan.py`).

## The two situations

**Observation only** — you can see data and times but cannot control anything.
A bus you are sniffing, a protocol you are watching.

```python
from flashleak import assess, render
print(render(assess(blocks, timing)))            # blocks (n,16) uint8, timing (n,)
```

**Controlled input** — you can send data and time the response. The bootloader
case: write a block, wait for the ACK or the next-packet prompt.

```python
from flashleak import determinism, fixed_vs_random, collect, assess, render

class MyBootloader:
    def measure(self, data: bytes) -> float | None:
        self.port.write(b"\x01" + data)
        t0 = time.perf_counter_ns()
        ok = self.port.read(1)                   # whatever means "ready"
        return (time.perf_counter_ns() - t0) if ok else None

tgt = MyBootloader()
print(determinism(tgt))                          # will averaging help?
print(fixed_vs_random(tgt))                      # model-free: leaking at all?
blocks, t = collect(tgt, 100_000, repeats=3)
print(render(assess(blocks, t)))
```

`measure` is the entire interface. Return anything monotonic in elapsed time.

**Start with `fixed_vs_random`.** It assumes nothing about the cipher, it is the
most sensitive thing here, and it answers "is this target leaking" before any
modelling. The rest tells you *what* the leak is and what it would cost.

## What it can tell you, and how

| question | how it is decided |
|---|---|
| is the timing data-dependent? | 16x256 byte-value means vs a shuffled null; and fixed-vs-random if you have control |
| which **side** of the cipher am I observing? | see below — this is the interesting one |
| encryption or decryption? | which of the two output-side predictors (inverse S-box / forward S-box) fires |
| **table layout** | which byte offsets carry signal: all of them = one shared table; only offsets 0 mod 4 = four separate tables; one family = a restricted access order |
| effective line granularity | an UPPER bound only, and biased coarse — see the caveat below |
| how many traces to be sure | excess over the shuffled floor grows as sqrt(n) |

### Input side vs output side

The collision channel is visible from either side but means different things:

* **output** (the block is the result of a final round with no MixColumns) — the
  key enters *after* the lookup, behind an S-box, so collisions are nonlinear in
  it and absolute key bytes fall out. This is the position that yields a key on
  its own.
* **input** — the index is `block ^ key`, key *before* the lookup and linear, so
  a collision only ever reveals `k[a] ^ k[b]` at line granularity.

Telling them apart is not trivial, because **neither naive test is specific**.
The input-side test responds to output-side leakage too (along a fixed-XOR
diagonal the S-box does not spread collisions evenly), and the output-side 2^16
search can find a partition that partly overlaps input-side leakage. What does
separate them is *concentration*: input-side leakage is a function of
`B[a] ^ B[b]` alone, so exactly one bucket is fast and stands well clear;
anything else smears across buckets.

Two statistics are needed, not one. The median over all 120 pairs identifies an
input side when every pair can collide, but reads ~0 when the layout
**partitions** the channel — in a 4-table implementation only 24 pairs can
collide and the other 96 drown them. The best-offset-family statistic rescues
that case, but partitioning raises it on *either* side, so it needs a higher bar.

| capture | truth | pooled | family |
|---|---|---:|---:|
| tiny-AES decrypt, observed ciphertext | input | 2.78 | 3.39 |
| mbedTLS compact decrypt, observed ct | input | 7.73 | 8.93 |
| mbedTLS 4-table decrypt, observed ct | input | 0.56 | **10.05** |
| SNMPv3 CFB keystream | output | 0.38 | 0.53 |
| simulated single-table, observe input | input | 10.45 | 11.34 |
| simulated 4-table, observe input | input | 0.56 | 24.92 |
| simulated single-table, observe output | output | 0.50 | 0.85 |
| simulated 4-table, observe output | output | 0.45 | **2.11** |

Input-side is called if **either** bar is cleared (pooled ≥ 1.0, family ≥ 5.0).
The narrow case is a partitioned layout seen from the output side (2.11) against
a partitioned input-side capture (10.05) — about 5×, where unpartitioned cases
separate by 20×. A 4-table call is the least certain thing this tool says.

The 4-table row was a **hold-out**: it set neither threshold, and the first
version of this rule got it wrong. Calibration uses only captures with no
runtime `FLASH_ACR` change.

When neither identifies the side, the tool says **UNDETERMINED** rather than
guessing. An early version fell through to an "input" verdict whenever the cheap
test fired, which produced a confidently wrong headline on output-side targets.

### The granularity figure is an upper bound

`assess` reports the width at which the XOR bucketing concentrates most, and that
is biased toward coarse widths because wider buckets hold more traces and dip
harder. On the tiny-AES decrypt capture it peaks at 16 bytes, while the round-1
difference sweep — which asks whether the recovered *differences* are correct at
each assumed width — resolves 4 bytes on the same data. The difference matters,
because the round-1 residual is `16*shift + (8-shift)` bits: 2^38 at 4 bytes
against 2^68 at 16.

Use this figure to bound the answer, then get the real one by sweeping
`line_shift` against recovered differences
([`research/round2/round2_decrypt.py`](../research/round2/round2_decrypt.py)).

## Mode does not matter for detection (mostly)

A fixed unknown XOR mask on the observed data does not hide the output side: for
a guess `g`, `tbl[B[j] ^ g]` with `B = out ^ m` is `tbl[out ^ (m ^ g)]`, so the
mask is absorbed into the recovered bytes. A CTR keystream, a raw ciphertext and
a ciphertext XOR some constant header therefore all look alike — which is why
you do not need to know the mode to detect the channel.

What *does* break it is a mask that **varies** per block and is unknown, which
is exactly CBC decryption seen as plaintext only. If you have both sides, XOR
them back together first:

```python
from flashleak import combine_cbc
raw = combine_cbc(plaintexts, ciphertexts)   # ciphertexts includes the IV
```

## Reading a negative honestly

Three ways this tool can say "nothing" about a target that is in fact broken:

1. **Not enough traces.** The key-free tests are strictly weaker than a
   key-known attack on the same data. This repo's own SNMPv3 capture yields a
   full key at 100 k traces, and flashleak rates it only *suggestive* at 250 k.
   That is expected: a detector that does not know the key is searching, not
   confirming. Its trace estimate is an **upper bound** on an attacker's cost.
2. **Unconditioned timing.** Raw round trips carry outliers and discrete
   transport modes. On that same SNMPv3 capture, raw sigma is 8.6 million and
   every test reads zero; conditioned it is 108 and the data-dependence z goes
   from +0.1 to +522. `assess` conditions automatically and says what it did —
   but if your measurement has structure it cannot model, look at that first.
3. **A flat model-free result.** Cache-collision leakage lives in *pairs* of
   bytes and is normally invisible to any single-byte test. A clean
   `data_dependence` means very little on its own.

The tool tries to say all of this in the report rather than leaving it here.

## Self-test

`python -m flashleak selftest` runs the detector against simulated targets whose
answers are known, including two negative controls. The simulator is the part
worth trusting or not:

* it leaks from **every round**, as a real cipher does. A one-round simulator
  reads ~6 on the concentration statistic where hardware reads ~1.4, and would
  have put the threshold about four times too high.
* its decryption walks a **real InvCipher**, verified against `aesref`. Walking
  the encryption from the plaintext instead — the obvious shortcut — makes the
  simulated decryption's first round linear in the observed block, i.e. it
  looks input-side when it is not.

Both of those were bugs here first, found because the selftest disagreed with
hardware. If you extend the simulator, keep the selftest honest the same way.

## Files

| file | what |
|---|---|
| `probe.py` | the statistics: conditioning, data-dependence, the two pair tests, the shuffled floor |
| `hypotheses.py` | turning statistics into statements; the input/output discriminator and its calibration |
| `target.py` | the `Target` interface, the simulator, fixed-vs-random, determinism, a serial example |
| `report.py` | rendering |
| `cli.py` | `analyse` / `probe` / `selftest` |
