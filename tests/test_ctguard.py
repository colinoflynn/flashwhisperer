"""Compile and run the ctguard host test (hardware-free).

ctguard's job is to refuse to pass a build it cannot vouch for. Four of its six
verdicts are measured on the F429 (rigs/fw_f4_ctguard/README.md); the two
that matter most -- a dead cycle counter and one ticking at the wrong rate --
cannot be produced on demand on real silicon, and they are precisely the
failures that would make every build look constant-time. They are covered here
by compiling the unmodified firmware module against a mock CMSIS whose clock is
programmable.

Skipped when no C compiler is reachable.
"""
from __future__ import annotations
import os
import shutil
import subprocess
import pytest

FW = os.path.join(os.path.dirname(__file__), "..", "rigs", "fw_f4_ctguard")
FW = os.path.abspath(FW)
SRC = ["test_ctguard_host.c", "ctguard.c", "hosttest/mock_cmsis.c"]


def _compiler():
    """A C compiler plus the argv prefix needed to reach it."""
    for cc in ("cc", "gcc", "clang"):
        if shutil.which(cc):
            return [cc]
    if shutil.which("wsl"):                      # Windows dev box, toolchain in WSL
        try:
            r = subprocess.run(["wsl", "which", "gcc"], capture_output=True, timeout=30)
            if r.returncode == 0:
                return ["wsl", "gcc"]
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def test_ctguard_verdicts(tmp_path):
    cc = _compiler()
    if cc is None:
        pytest.skip("no C compiler available")
    exe = "ctgtest_pytest" + (".exe" if cc[0] != "wsl" and os.name == "nt" else "")
    build = cc + ["-Ihosttest", "-I.", "-Wall", "-Wextra", "-O1", "-o", exe] + SRC
    r = subprocess.run(build, cwd=FW, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, f"compile failed:\n{r.stdout}\n{r.stderr}"
    try:
        run = (["wsl", "./" + exe] if cc[0] == "wsl" else [os.path.join(FW, exe)])
        r = subprocess.run(run, cwd=FW, capture_output=True, text=True, timeout=120)
        print(r.stdout)
        assert r.returncode == 0, f"ctguard host test failed:\n{r.stdout}\n{r.stderr}"
        # every case, not just the aggregate line
        assert "FAIL" not in r.stdout.replace("got=FAIL", "").replace(
            "want=FAIL", ""), r.stdout
        assert "all ctguard verdicts behave as specified" in r.stdout
    finally:
        try:
            os.remove(os.path.join(FW, exe))
        except OSError:
            pass
