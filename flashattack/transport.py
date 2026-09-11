"""Transports and pluggable timing sources.

The engine only needs (known_blocks, timing). This module produces the raw
(material, timing) from a target; `modes.known_output` turns material into the
block the engine scans. Two timing sources are provided:

  * collect_oncore  -- device streams its on-chip cycle count per op (fw_f4_modes
                       / fw_f4_lib 'X' batch). Low jitter; the calibration oracle.
  * collect_acklatency -- host times the ACK on its own clock (fw_f4_boot). The
                       realistic external oracle; supports in-device amplification
                       (K) and host-side min-filtering (R).

Firmware protocols live in hardware/ and may move; this module is the thin glue.
"""
from __future__ import annotations
import time
import numpy as np

try:
    import serial
except ImportError:                       # allow importing the package without pyserial
    serial = None


def gen_pts(seed, n):
    """Mirror the firmware xorshift32: 4 words -> 16 big-endian bytes per trace."""
    s = seed & 0xFFFFFFFF or 1
    words = np.empty(n * 4, dtype=np.uint64)
    x = s
    for i in range(n * 4):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        words[i] = x
    w = words.reshape(n, 4).astype(np.uint32)
    pts = np.empty((n, 16), dtype=np.uint8)
    for k in range(4):
        pts[:, 4*k+0] = (w[:, k] >> 24) & 0xFF
        pts[:, 4*k+1] = (w[:, k] >> 16) & 0xFF
        pts[:, 4*k+2] = (w[:, k] >> 8) & 0xFF
        pts[:, 4*k+3] = w[:, k] & 0xFF
    return pts


class SerialTarget:
    def __init__(self, port, baud=115200, timeout=2.0):
        if serial is None:
            raise RuntimeError("pyserial not installed")
        self.s = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3); self.s.reset_input_buffer()

    def cmd(self, line):
        self.s.reset_input_buffer(); self.s.write((line + "\n").encode())
        return self.s.readline().decode(errors="replace").strip()

    def banner(self):        return self.cmd("V")
    def setkey(self, keyhex): return self.cmd("S " + keyhex)
    def set_acr(self, acr):   return self.cmd(f"C {acr}")
    def close(self):          self.s.close()


def collect_oncore(target, batch_cmd, seed, n):
    """Send a streaming batch command (e.g. 'X e', 'X d', or bare 'E'/'Q' forms)
    and read n cycle counts terminated by END. Returns (material, cycles)."""
    target.s.reset_input_buffer()
    target.s.write(f"{batch_cmd} {seed:08x} {n}\n".encode())
    c = np.empty(n); i = 0; empt = 0
    while i < n:
        ln = target.s.readline().decode(errors="replace").strip()
        if ln == "END": break
        if ln == "":
            empt += 1
            if empt > 5: break
            continue
        empt = 0
        try: c[i] = float(ln); i += 1
        except ValueError: continue
    if i < n:
        raise RuntimeError(f"short read {i}/{n}")
    return gen_pts(seed, n), c


def collect_acklatency(target, blocks, K=64, R=1):
    """fw_f4_boot: for each 16-byte ciphertext block send 0xA5,K,block; time
    send->ACK on the host clock (perf_counter). R>1 min-filters over repeats.
    Returns (rtt_ns, oncore_cyc) arrays (oncore is the device's calibration)."""
    n = len(blocks)
    rtt = np.full(n, np.nan); cyc = np.full(n, np.nan)
    for i in range(n):
        req = bytes([0xA5, K]) + bytes(blocks[i])
        best = np.inf; cc = -1
        for _ in range(R):
            target.s.reset_input_buffer()
            t0 = time.perf_counter_ns(); target.s.write(req)
            a = target.s.read(1); t1 = time.perf_counter_ns()
            cal = target.s.read(3)
            if len(a) == 1 and a[0] == 0x06 and (t1 - t0) < best:
                best = t1 - t0
                cc = (cal[0] | (cal[1] << 8) | (cal[2] << 16)) if len(cal) == 3 else -1
        rtt[i] = best; cyc[i] = cc
    return rtt, cyc
