"""Replay captured hardware trace vectors through the engine (long test).

Run with:  PYTHONPATH=. pytest tests/test_vectors.py --runslow
Each tests/vectors/*.npz is a real capture (S-box or T-table, various key sizes
and modes). Success criterion:
  * AES-128  -> full master key recovered and verified;
  * AES-192/256 -> the last round key recovered 16/16 (full master needs the
    second round key -- see docs).
"""
import glob
import os
import pytest

pytest.importorskip("numpy")
from flashattack import vectors  # noqa: E402

VEC_DIR = os.path.join(os.path.dirname(__file__), "vectors")
VEC_FILES = sorted(glob.glob(os.path.join(VEC_DIR, "*.npz")))


@pytest.mark.slow
@pytest.mark.skipif(not VEC_FILES, reason="no captured vectors in tests/vectors/")
@pytest.mark.parametrize("path", VEC_FILES, ids=[os.path.basename(p) for p in VEC_FILES])
def test_replay_vector(path):
    meta = vectors.load(path)
    key = bytes.fromhex(meta["key_hex"])
    res = vectors.replay(path, verify=True)
    if int(meta["keysize"]) == 128:
        # full master expected (brute-force may fix a near-miss, so assert on master)
        assert res.verified and res.master == key, \
            f"{os.path.basename(path)}: master not recovered ({res.truth_correct}/16 assembled)"
    else:
        # 192/256: byte-wise attack yields the last round key; master needs 2nd round key
        assert res.truth_correct == 16, \
            f"{os.path.basename(path)}: only {res.truth_correct}/16 round-key bytes"
