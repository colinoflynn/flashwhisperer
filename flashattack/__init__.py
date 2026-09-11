"""flashattack -- flash-accelerator AES timing side-channel toolkit.

Target-agnostic key-recovery engine plus transports, mode mapping, feasibility
estimation and a CLI. The exploitation engine is independent of any particular
board or firmware (those live under hardware/ and may move to another project).

Quick use:
    from flashattack import engine, modes
    known, direction = modes.known_output("ctr", material, key)
    res = engine.recover(known, timing, direction=direction, verify=(pt, ct))
    print(res.summary())
"""
from . import aesref, engine, modes         # noqa: F401

__all__ = ["aesref", "engine", "modes"]
__version__ = "0.1.0"
