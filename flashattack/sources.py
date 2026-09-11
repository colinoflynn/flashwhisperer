"""Trace sources: where a Capture comes from. The engine/attack never care — they
consume a Capture. To add a new hardware interface or data format, implement one
method:

    class MySource:
        def capture(self) -> Capture:
            ...                      # read your interface / file, return a Capture

That is the entire contract (see `TraceSource`). Below are ready-made sources for
recorded files and for the project's serial firmware; a live power/EM/network
interface would look the same.
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable
import numpy as np
from .capture import Capture


@runtime_checkable
class TraceSource(Protocol):
    def capture(self) -> Capture:  # noqa: D401
        """Return a Capture (observed data + timing, no key)."""
        ...


class RecordedSource:
    """Load a Capture from a recorded file (.npz written by Capture.save_npz, or
    a .csv with a 'timing' column and optional plaintext/ciphertext columns)."""
    def __init__(self, path, mode="ecb-enc", keysize=128, **csv_kw):
        self.path, self.mode, self.keysize, self.csv_kw = path, mode, keysize, csv_kw

    def capture(self) -> Capture:
        if str(self.path).endswith(".npz"):
            return Capture.from_npz(self.path)
        return Capture.from_csv(self.path, mode=self.mode, keysize=self.keysize, **self.csv_kw)


class ArraySource:
    """Wrap in-memory arrays (e.g. produced by another agent's capture loop)."""
    def __init__(self, timing, mode="ecb-enc", keysize=128, plaintext=None,
                 ciphertext=None, iv=None, line_shift_last=4, line_shift_prev=2, label=""):
        self._cap = Capture(timing=timing, mode=mode, keysize=keysize, plaintext=plaintext,
                            ciphertext=ciphertext, iv=iv, line_shift_last=line_shift_last,
                            line_shift_prev=line_shift_prev, label=label)

    def capture(self) -> Capture:
        return self._cap


class SerialModesSource:
    """The project's fw_f4_modes / fw_f4_lib firmware over serial. This is a
    *known-key* lab oracle: the device streams timings for host-generated
    plaintexts, and we synthesise the observed ciphertext from `key` (a real
    interface would instead read the ciphertext off the wire). Produces a Capture
    with no key stored.
    """
    def __init__(self, port, mode, key_hex, n, *, acr="00000705", seed="5eed01",
                 impl="ttable", batch_cmd=None):
        self.port, self.mode, self.key = port, mode, bytes.fromhex(key_hex)
        self.n, self.acr, self.seed, self.impl, self.batch_cmd = n, acr, int(seed, 16), impl, batch_cmd

    def capture(self) -> Capture:
        from . import transport, modes, aesref
        tgt = transport.SerialTarget(self.port)
        banner = tgt.banner(); tgt.set_acr(self.acr); tgt.setkey(self.key.hex())
        bc = self.batch_cmd or (("X" if (self.mode == "ecb-enc" and "-lib" in banner)
                                 else "X " + modes.MODE_CHAR[self.mode]))
        material, cyc = transport.collect_oncore(tgt, bc, self.seed, self.n); tgt.close()
        # synthesise observed data (a real wire interface would supply these directly)
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        pt = ct = None; ivb = None
        if self.mode == "ecb-enc":
            pt, ct = material, aesref.encrypt_blocks(self.key, material)
        elif self.mode == "cbc-enc":
            ivb = iv; ct = aesref.encrypt_blocks(self.key, material ^ np.frombuffer(iv, np.uint8))
        elif self.mode == "ctr":
            pt = np.zeros_like(material); ct = aesref.encrypt_blocks(self.key, material)
        elif self.mode == "ecb-dec":
            pt, ct = aesref.decrypt_blocks(self.key, material), material
        elif self.mode == "cbc-dec":
            ivb = iv; pt = aesref.decrypt_blocks(self.key, material) ^ np.frombuffer(iv, np.uint8)
        return Capture(timing=cyc, mode=self.mode, keysize=len(self.key) * 8,
                       plaintext=pt, ciphertext=ct, iv=ivb,
                       line_shift_last=4, line_shift_prev=(2 if "ttable" in self.impl else 4),
                       label=self.impl)
