# Round-2 collisions: finishing the key when only the *input* is known

**Status: demonstrated end to end on recorded hardware.** Round 1 + round 2
recovers the **complete AES-128 key** from plaintexts and timing alone — no
ciphertext, no known (P,C) pair, no verification oracle — on the 250 k tiny-AES
F429 capture, in 734 s of CPU:

```
round 1: 16/16 byte differences resolved  ->  residual 2^38
round 2 chose R=10                        ->  2b7e151628aed2a6abf7158809cf4f3c  EXACT
```

Still open: the same demonstration on a *decrypt* capture (one is being taken),
the 4-table layout, and wiring the solver into the package rather than
[`../research/round2/round2_fullsolve.py`](../research/round2/round2_fullsolve.py). This document is the
design and the measured evidence behind it, so a later session can start from the
open questions rather than re-deriving the closed ones.

## What it buys, and when it is worth anything

The last-round attack needs the block cipher's **output**. Two important cases do
not have it:

| case | what is known | round-1 result |
|---|---|---|
| CBC bootloader, chosen ciphertext, no plaintext | input = `C` | differences only |
| encrypt-only device, known plaintext, ciphertext never emitted | input = `P` | differences only |

Both land on round 1, where the key enters *before* the lookup and linearly, so a
line collision reveals only `(k[a] ^ k[b]) >> line_shift` — key-byte differences
at the channel's granularity, never absolute bytes. Measured residuals
([`EXPERIMENTAL.md`](EXPERIMENTAL.md)):

* **single-table** (tiny-AES S-box, one 256-byte table): all 15 differences at
  4-byte granularity → **2^38**
* **4-table** (mbedTLS `RT0..RT3`): differences only *within* the four
  same-table groups `{0,4,8,12}`, `{1,5,9,13}`, `{2,6,10,14}`, `{3,7,11,15}` →
  **2^56**

Round 2 is the way out, because its lookup indices are a **nonlinear** function of
the key (they sit behind an S-box and MixColumns), so collisions there carry
absolute bits rather than differences.

**Before building this, check whether you need it.** If any known plaintext block
exists, 2^38 is finishable by brute force against that one pair (hours with
AES-NI) and round 2 is wasted effort. If ~10^5 known-plaintext blocks exist, the
ordinary last-round attack applies with no new code at all. Round 2 earns its
keep only when the *output side is genuinely unavailable*.

## Measured feasibility (recorded F429 capture, tiny-AES single S-box)

All from `tests/vectors/sbox_tinyaes_ecb-enc_128.npz`, 250 k random inputs,
scored against the known key.

**1. Round 2 leaks as strongly as round 1.** Predicting round-2 S-box indices and
pooling the collision dip over all 120 pairs at 4-byte granularity:

| | mean dip | pairs below −1 |
|---|---:|---:|
| round 1 | −2.31 cyc | 102/120 |
| round 2 | **−2.37 cyc** | **101/120** |

**2. It carries exactly the bits round 1 cannot see.** Perturbing only the low 2
bits of a key byte leaves every round-1 line tag identical (XOR has no carries,
so `top6(P^k) = top6(P)^top6(k)`) — a built-in control. Round 2 picks the true
value **16/16**, true −2.37 against ~−1.33 for the other three, and the round-1
control reads exactly `0.00e+00` spread.

**3. It survives not knowing the round-2 key.** `k1` enters the same-column
collision condition only as a single 6-bit nuisance target per pair, and
bucketing by the predicted quantity yields all 64 targets in one pass, so the
search is free. Still 4/4 with `k1` unknown.

**4. Pooling all 120 pairs does NOT decompose.** With 4 or more other key bytes
wrong, recovery collapses to chance (1/12, 2/8, 1/4) and the margin goes
negative. A round-2 state byte depends on 4 key bytes, so most pairs touch a
wrong one. Scoring all 120 pairs jointly makes round 2 a *verifier* over the
whole 2^38, which is useless — the whole point is to avoid enumerating it.

**5. The per-column decomposition is what makes it work.** Round-2 state byte
`4c+r` depends on exactly one diagonal of the key, so the six **same-column**
pairs of column `c` are a function of just 4 key bytes:

```
column c  ->  key bytes { 4c, 4((c+1)%4)+1, 4((c+2)%4)+2, 4((c+3)%4)+3 }
column 0  ->  0, 5, 10, 15        column 2  ->  8, 13, 2, 7
column 1  ->  4, 9, 14, 3         column 3  ->  12, 1, 6, 11
```

Given round 1, a column has 4 x 2 = **8 unknown low bits**. Column 0, 256
candidates, rank of the true one out of 256:

| traces | `k1` known | `k1` unknown, best-of-64 | `k1` unknown, max-z |
|---:|---:|---:|---:|
| 25 000 | 1 | 31 | 39 |
| **100 000** | **0 SOLVED** | **0 SOLVED** | **0 SOLVED** |
| 250 000 | **0 SOLVED** | **0 SOLVED** | **0 SOLVED** |

The 25 k failure is **statistical power, not structure** — six pairs instead of
120 is √20 less averaging. At 100 k it solves cleanly in the realistic mode.

**6. The full attacker position solves.** Column 0 with *both* unknowns searched
jointly — the shared 6-bit reference `R` and the column's 8 low bits, 64 x 256 =
16 384 candidates, `k1` unknown:

| traces | rank of true candidate | margin over best wrong | time |
|---:|---:|---:|---:|
| 50 000 | 1 / 16384 | — | 35 s |
| **100 000** | **0 / 16384** | +0.475 z | 72 s |
| 250 000 | **0 / 16384** | **+1.338 z** | 185 s |

So `2^38` becomes **four independent 2^14 searches** that take about a minute
each, with the threshold at ~100 k traces and comfortable margin by 250 k. Since
`R` is shared, the four columns cross-check each other: the correct reference is
the one whose four columns all score well, which should push the usable threshold
below 100 k.

## The algebra

### Encryption (known plaintext)

Round-2 S-box indices are the state after round 1:

```
x2 = MixColumns( ShiftRows( SubBytes( P ^ k0 ) ) ) ^ k1
```

A line collision between two round-2 bytes is `top6(x2[j] ^ x2[j']) == 0`, and for
two bytes **in the same column** the MixColumns rows share their inputs, so

```
x2[4c+r] ^ x2[4c+r'] = XOR_m ( M[r][m] ^ M[r'][m] ) . S( P[d_m] ^ k0[d_m] )
                       ^ ( k1[4c+r] ^ k1[4c+r'] )
```

with `d_m` the diagonal above. The `k1` term is one unknown byte, and since the
condition only needs its top 6 bits, it is a **6-bit nuisance target** `T` per
pair. Note four of the six row-pairs have a vanishing MixColumns coefficient
(`[2,3,1,1]^[1,2,3,1] = [3,1,2,0]`, etc.), so they involve only **3** key bytes —
worth exploiting if the 4-byte search ever gets tight.

### Decryption (chosen or known ciphertext)

Identical in structure; only the primitives change.

```
straightforward InvCipher (tiny-AES):
    x2 = InvMixColumns( SINV( InvShiftRows( C ^ rk10 ) ) ^ rk9 )

equivalent inverse cipher (mbedTLS, Td tables):
    x2 = InvMixColumns( SINV( InvShiftRows( C ^ rk10 ) ) ) ^ rk9'
         where rk9' = InvMixColumns(rk9)
```

`rk10` is the **last encryption round key**, so recovering it and inverting the
key schedule gives the master key — the same endpoint as `direction="dec"`. The
diagonal mapping changes because InvShiftRows rotates the other way; derive it
rather than copying the encryption one.

Both forms put the round key either inside or outside the InvMixColumns, which
changes only what the nuisance byte is, not that there is one.

**Chosen ciphertext is not required.** The attack buckets traces by a predicted
quantity, so random inputs work — which is what the measurements above use. The
chosen-CT capability from a bootloader is useful for *amplification* (an image of
N identical blocks multiplies the deterministic per-block time by N), not for the
cryptanalysis. This is a simplification over the fixed-byte designs in the
Bonneau–Mironov literature and removes their worst problem, which is that holding
15 bytes fixed leaves only 256 distinct blocks whose algorithmic noise is
deterministic and cannot be averaged away.

## Implementation plan

1. **`flashattack/round2.py`** — `round2_state(blocks, rk, direction)` returning
   the 16 round-2 lookup indices, for both cipher forms. The encryption version
   already exists in prototype (see *Reproduction* below); the decrypt version is
   the main new derivation.
2. **`column_score(blocks, timing, rk_candidate, column)`** — pool the six
   same-column pairs, bucketing by `(x2[j] ^ x2[j']) >> line_shift` so all 64
   nuisance targets come out of one `bincount`; score with the standardised
   `max-z` form, which behaved best at low trace counts.
3. **`solve_round2(blocks, timing, round1_result)`** — for each of the 64 shared
   references, solve the four columns independently over their 256 low-bit
   combinations; pick the reference whose four columns agree best. 64 x 4 x 256 =
   65 536 scorings, each a handful of `bincount`s.
4. **Wire into `recover_round1_keyspace`'s output** so the pipeline is
   round 1 → round 2 → full key, and the `known=` verification pair becomes
   optional rather than required.
5. **Hardware validation**: a fresh F429 capture with a single-table **decrypt**
   victim. Everything measured so far is an *encrypt* capture; the decrypt
   analogue is structurally identical but unmeasured, and this repo's standard is
   hardware with controls.

Budget: the algebra and solver are days, given the feasibility results above. The
schedule risk is item 5, not the cryptanalysis.

## Open problems

**The 4-table layout does not decompose this way, and this is the real open
question — but it is a search problem, not a signal problem.** Measured on the
mbedTLS ECB-decrypt capture (120 k traces), predicting round-2 state with the
true key:

| | same-table pairs (offset ≡ 0 mod 4) | cross-table pairs |
|---|---:|---:|
| round 1 | −3.335 cyc (24 pairs) | −0.044 (96 pairs) |
| **round 2** | **−2.555 cyc** | −0.055 |

So round-2 collisions are there, on the same four families round 1 uses, at about
three quarters of round 1's strength; cross-table pairs are flat in both rounds,
as the separate-flash-region argument requires.

What does not carry over is the decomposition. In a T-table round the four
lookups of a column go to `RT0..RT3` — *different* tables — so same-column
round-2 pairs can never collide, and the pairs that can are
same-row-across-columns, drawing on **two** diagonals: 8 key bytes, which with
round-1's four group references is 24 + 16 + 6 = **46 bits** per relation. A
round-1 x round-2 cross-round pair in the same table is cheaper (1 + 4 key bytes)
but still carries all four group references, ~40 bits. Both are too big for a
direct numpy sweep and would want a GPU or a meet-in-the-middle; neither is
attempted here. Low priority, because a 4-table target with any known
plaintext falls to the ordinary last-round attack (its final round uses the single
256-byte `RSb`, which is exactly why the SNMPv3 and TLS demos work on mbedTLS).

**Trace count for the decrypt case is unmeasured.** 100 k is the encrypt figure.

**Selection bias in the nuisance search is handled but not analysed.** Every
candidate gets the same best-of-64 advantage so the comparison is fair, but the
variance it adds is what pushed the 25 k case to rank 31. A likelihood-ratio
score over the 64 buckets would probably beat max-z and lower the trace
requirement; untested.

## Reproduction

Prototypes are kept in [`../research/round2/`](../research/round2/). They are
research scripts, not part of the package or the test suite -- run them from the
repo root, and they score against the known key because they exist to answer
"does this work", not to attack anything:

| script | what it establishes |
|---|---|
| `round2_gonogo.py` | round 2 sees the low 2 bits; round-1 control is exactly flat |
| `round2_nuisance.py` | survives unknown `k1`; trace-count curve |
| `round2_solve.py` | pooling all 120 pairs does *not* decompose; reference R is findable |
| `round2_column.py` | the per-column decomposition |
| `round2_power.py` | 25 k fails / 100 k solves — power, not structure |
| `round2_joint2.py` | the full 16384-candidate joint search, rank 0 at 100 k |

The relevant one-liner for any future check is that perturbing only the low 2
bits of a key byte is invisible to round 1 by construction, which makes it a free
control on every round-2 experiment.
