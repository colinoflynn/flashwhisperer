"""SM4 reference (GM/T 0002 vector) and synthetic full-master recovery."""
import numpy as np
import pytest
from flashattack import sm4


def test_sm4_vector():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    pt = np.frombuffer(bytes.fromhex("0123456789abcdeffedcba9876543210"), np.uint8)[None, :]
    assert sm4.encrypt_blocks(key, pt)[0].tobytes().hex() == "681edf34d206965e86b3e94f536e4246"


def test_sm4_key_schedule_inversion():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    rk = sm4.key_schedule(key)
    assert sm4.invert_key_schedule([rk[28], rk[29], rk[30], rk[31]]) == key


@pytest.mark.slow
def test_sm4_partial_leak_synthetic():
    # SM4 (Feistel) leaks only top-nibble differences of the last round key rk31 --
    # a partial keyspace reduction, NOT the full key (see EXPERIMENTAL.md).
    correct, true, got = sm4._selftest(n=200000, delta=6.0, noise=15.0, seed=1)
    assert correct == 3          # all 3 independent rk31 top-nibble diffs recovered
