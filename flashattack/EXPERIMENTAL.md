# Experimental / partial results and their ceilings

This documents two investigations whose outcomes are **partial** — real, validated,
but not full key recovery — so future work knows exactly where the walls are and
why. Both stem from the same fact: a flash-line collision reveals only the **top
bits** of a lookup index (a 16-byte line ⇒ nibble resolution for an S-box), and it
is only useful when the collision relates to the key through a **nonlinear**
function. AES's SPN last round provides that; other structures do not.

## 1. Known-plaintext-only recovery (AES) — `engine.recover_round1_keyspace`

**Scenario:** the attacker sees the *inputs* (plaintext) and timing but **not the
ciphertext** (e.g. a device that encrypts chosen/known plaintexts without exposing
output, or the first block of a CMAC).

**Method:** round-1 S-box index = `pt ^ k0`, and `topbits(pt^k0) = topbits(pt) ^
topbits(k0)`, so two positions collide iff `topbits(pt[a])^topbits(pt[b]) ==
topbits(k0[a]^k0[b])`. Bucketing by the (known) left side and taking the
shortest-time bucket gives the **top-bit key-byte difference** for each leaking
pair; a confidence-ranked graph propagation then assigns every byte's top bits
relative to a reference.

**Measured (F429, recorded vectors):**

| Implementation | resolved | correct | residual keyspace |
|---|---|---|---|
| **S-box** (tiny-AES) | 16/16 | **16/16** | 128 → **~68 bits** |
| **T-table** (Mbed-TLS, 4-table) | 16/16* | 4/16 | unreliable |

*The 4-table layout interleaves the round-1 lookups across four separate tables,
so few pairs truly collide; the method reports resolutions with false confidence.
**Reliable only on S-box implementations.**

**Ceiling (why it's partial):** pairwise collisions carry only **top-bit
differences** — the low nibble of every byte and one reference offset are
unrecoverable from timing (the cache line is 16 bytes). For AES-128 S-box that
leaves ~68 bits: a real keyspace reduction, not a break. **Any** single output
observation (the last-round attack) removes the limitation and gives the full key.
`recover_round1_diffs` (naive all-vs-ref) and `recover_round1_keyspace` (robust,
graph) are both **experimental**, not wired into `attack()`.

**Future:** select leaking pairs by margin (done); combine with a partial output
oracle to anchor the differences; profiled/template variant for very low SNR.

## 2. SM4 (`sm4.py`) — a structural resistance result

SM4 is fully implemented (GM/T 0002 reference verified) and integrated as a target
(`fw_f4_lib LIB=sm4`, GmSSL). The security-relevant finding:

- **GmSSL's default SM4 uses four separate T-tables (`T0..T3`)** — the four
  per-round lookups hit four different tables, so they **never share a cache
  line**: no within-round collision at all (exactly like the "safe" 4-table AES).
- **The single-table / S-box build** (`ENABLE_SMALL_FOOTPRINT`, `make LIB=sm4
  SM4_SBOX=1`) does collide, **but SM4 is a Feistel cipher**: the last-round S-box
  index is `X32^X33^X34 ^ rk31` with `X32..X34` known from the ciphertext, and the
  S-box *output* is not observable (`X31` is unknown). So the collision is on an
  index that is **linear** in the key ⇒ only the **top-nibble differences of the
  last round key `rk31`** leak, and you **cannot peel** to earlier rounds (peeling
  needs the full round key). `recover_rk31_topnibble_diffs` returns exactly that.

**Contrast with AES:** AES's SPN last round is `ct = SBOX(state) ^ k10`, so the
index `state = SINV[ct ^ k10]` passes through the **nonlinear** inverse S-box —
which is what lets the collision pin the *full* key byte and enables full recovery.
SM4's pre-S-box key XOR (Feistel) denies that anchor. **SM4 is therefore markedly
more resistant to this flash-timing channel than AES: only a partial top-nibble
leak of one round key, no full-key path.**

Validated: reference (GM/T vector), synthetic partial leak (3/3 rk31 top-nibble
diffs), and on real F429 silicon (S-box build) — see RESULTS. A previous "full SM4
recovery" claim was a modeling error (collisions were planted on the S-box
*output* instead of the *index*); corrected here.

**Future:** the same partial leak applies to other Feistel/ARX table ciphers;
Camellia (FL/S-box) and ARIA (SPN, like AES — likely fully recoverable) are natural
next comparisons.

---

Both results reinforce the project's central theme: **the flash-timing collision
recovers the full key only for an SPN last round with a table (AES-style); Feistel
structure and non-table (bitsliced/constant-time) or interleaved-4-table layouts
reduce it to a partial leak or nothing.**
