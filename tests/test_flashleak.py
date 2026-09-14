"""flashleak's conclusions against targets whose answers are known.

The simulator is the point of this file: it leaks from every round, like a real
cipher, and its decryption walks a real InvCipher. Both matter. A one-round
simulator makes the input-vs-output discriminator read ~6 where hardware reads
~1.4, and walking the encryption from the plaintext to model a decryption makes
the target look input-side when it is not -- either shortcut would have graded
the detector against a target that flatters it.
"""
import numpy as np
import pytest

from flashleak import (SimulatedTarget, assess, fixed_vs_random, determinism,
                       probe)

N = 60_000


def _run(n=N, **kw):
    tgt = SimulatedTarget(seed=1, **kw)
    blocks = np.random.default_rng(0).integers(0, 256, size=(n, 16), dtype=np.uint8)
    timing, seen = tgt.measure_many(blocks)
    return assess(seen, timing, quick=True), tgt


def _answers(res):
    return " | ".join(f.answer for f in res.findings).lower()


def test_constant_time_is_called_out():
    res, _ = _run(n=5000, layout="none", noise=0.0)
    assert "constant time" in _answers(res)


def test_noise_without_a_channel_is_not_called_leakage():
    res, _ = _run(layout="none", noise=3.0)
    a = _answers(res)
    assert "none detected" in a
    assert "cipher input" not in a


def test_input_side_is_identified_and_is_specific():
    """Concentration must fire for the input-side target and not for others --
    that specificity is the whole reason the statistic exists."""
    res, _ = _run(direction="enc", observe="input")
    assert "cipher input" in _answers(res)
    conc = max(res.tests["xor_concentration"].values())
    res2, _ = _run(direction="enc", observe="output")
    conc2 = max(res2.tests["xor_concentration"].values())
    assert conc > conc2 * 2, (conc, conc2)


def test_output_side_does_not_masquerade_as_input():
    """The failure that mattered: falling through to an INPUT verdict when
    nothing actually identified the side."""
    res, _ = _run(direction="enc", observe="output")
    assert "cipher input" not in _answers(res)


@pytest.mark.slow
def test_encrypt_and_decrypt_outputs_are_told_apart():
    for direction, expect in (("enc", "encryption output"),
                              ("dec", "decryption output")):
        tgt = SimulatedTarget(seed=1, direction=direction, observe="output")
        blocks = np.random.default_rng(0).integers(0, 256, size=(150_000, 16),
                                                   dtype=np.uint8)
        timing, seen = tgt.measure_many(blocks)
        assert expect in _answers(assess(seen, timing))


@pytest.mark.slow
def test_four_table_layout_is_recognised():
    tgt = SimulatedTarget(seed=1, direction="enc", observe="output", layout="four")
    blocks = np.random.default_rng(0).integers(0, 256, size=(150_000, 16),
                                               dtype=np.uint8)
    timing, seen = tgt.measure_many(blocks)
    res = assess(seen, timing)
    assert "four separate tables" in _answers(res)
    prof = res.tests["offset_profile"]
    assert min(prof[4], prof[8]) > max(prof[d] for d in prof if d % 4)


def test_decryption_model_walks_a_real_invcipher():
    """If this drifts, the decrypt cases are testing a fiction."""
    from flashattack import aesref
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    tgt = SimulatedTarget(key=key, direction="dec")
    ct = np.random.default_rng(5).integers(0, 256, size=(32, 16), dtype=np.uint8)
    idx = tgt._all_round_indices_dec(ct)
    assert len(idx) == 10
    st = np.asarray(probe.SINV, np.uint8)[idx[-1]] ^ np.frombuffer(
        bytes(tgt._rk[0]), np.uint8)[None, :]
    assert np.array_equal(st, np.asarray(aesref.decrypt_blocks(key, ct), np.uint8))


def test_controlled_probes_separate_leaking_from_clean():
    leaky = SimulatedTarget(seed=2, direction="enc", observe="output")
    clean = SimulatedTarget(seed=2, layout="none", noise=3.0)
    assert fixed_vs_random(leaky, n=4000)["leaking"]
    assert not fixed_vs_random(clean, n=4000)["leaking"]


def test_determinism_reports_a_noiseless_target_as_deterministic():
    assert determinism(SimulatedTarget(seed=3, noise=0.0), trials=30)["deterministic"]
    assert not determinism(SimulatedTarget(seed=3, noise=5.0), trials=30)["deterministic"]


def test_blocks_must_be_16_wide():
    with pytest.raises(ValueError):
        probe.data_dependence(np.zeros((10, 8), np.uint8), np.zeros(10))
