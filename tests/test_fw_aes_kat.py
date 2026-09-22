"""Known-answer test for every firmware copy of `aes.c`.

This exists because of a real regression: `aes_ttable_encrypt_nr` and
`aes_ttable1_encrypt_nr` wrote `s[c]` in place in the final round, so columns
1-3 consumed state earlier iterations had already overwritten and **neither
function computed AES**.  FIPS-197 C.1 came back
`69c4e0d86a7b0476d8cd46b37037c2a8` instead of `...0430d8cdb78070b4c55a`.

Nothing caught it for the lifetime of the code, because a timing side-channel
harness never checks its own ciphertext -- the attack scores against a known
key, and rounds 1..9 were correct, so round-1 results looked fine.  That is the
same class of silent failure the ctguard workstream exists to detect, and it is
why this test compiles the *actual* firmware sources rather than a copy.

Skipped where no host C compiler is available.
"""
from __future__ import annotations
import os, shutil, subprocess, sys, textwrap
import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RIGS = os.path.join(REPO, "rigs")

# FIPS-197 C.1 (AES-128)
KEY = "000102030405060708090a0b0c0d0e0f"
PT = "00112233445566778899aabbccddeeff"
CT = "69c4e0d86a7b0430d8cdb78070b4c55a"

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "aes.h"
static const unsigned char K[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const unsigned char P[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                  0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
static void emit(const char *n, const unsigned char *o) {
    printf("%s ", n); for (int i=0;i<16;i++) printf("%02x", o[i]); printf("\n");
}
int main(void) {
    unsigned int w[44]; unsigned char o[16];
    aes_key_schedule(K, w);
    aes_sbox_encrypt(P,o,w);          emit("sbox", o);
    aes_sbox_encrypt_alt(P,o,w);      emit("sbox_alt", o);
    aes_ttable_encrypt(P,o,w);        emit("ttable4", o);
    aes_ttable1_encrypt_nr(P,o,w,10); emit("ttable1", o);
    aes_ttw_encrypt(P,o,w,0);         emit("ttw0", o);
    aes_ttw_encrypt(P,o,w,1);         emit("ttw1", o);
    return 0;
}
"""


def _cc():
    for c in ("cc", "gcc", "clang"):
        if shutil.which(c):
            return c
    return None


def _winpath_to_wsl(p):
    p = os.path.abspath(p)
    drive, rest = os.path.splitdrive(p)
    return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")


def _wsl_gcc():
    """On Windows the only compiler in this environment lives in WSL."""
    if sys.platform != "win32" or not shutil.which("wsl"):
        return None
    r = subprocess.run(["wsl", "-e", "bash", "-lc", "command -v gcc"],
                       capture_output=True, text=True)
    return r.stdout.strip() or None


def _build_and_run(workdir):
    """Compile kat.c + aes.c and run it. Returns (ok, stdout, why_not)."""
    cc = _cc()
    if cc:
        exe = os.path.join(workdir, "kat.exe" if sys.platform == "win32" else "kat")
        r = subprocess.run([cc, "-O1", "-o", exe,
                            os.path.join(workdir, "kat.c"),
                            os.path.join(workdir, "aes.c")],
                           capture_output=True, text=True, cwd=workdir)
        if r.returncode != 0:
            return False, "", r.stderr
        out = subprocess.run([exe], capture_output=True, text=True, cwd=workdir)
        return out.returncode == 0, out.stdout, out.stderr
    if _wsl_gcc():
        w = _winpath_to_wsl(workdir)
        r = subprocess.run(["wsl", "-e", "bash", "-lc",
                            f"cd {w} && gcc -O1 -o kat kat.c aes.c && ./kat"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False, r.stdout, r.stderr
        return True, r.stdout, ""
    return False, "", "no compiler"


def _fw_dirs():
    out = []
    for d in sorted(os.listdir(RIGS)):
        p = os.path.join(RIGS, d)
        if os.path.isdir(p) and os.path.exists(os.path.join(p, "aes.c")) \
           and os.path.exists(os.path.join(p, "aes.h")):
            out.append(d)
    return out


@pytest.mark.parametrize("fw", _fw_dirs())
def test_firmware_aes_matches_fips197(fw, tmp_path):
    if _cc() is None and _wsl_gcc() is None:
        pytest.skip("no host C compiler (native or WSL)")
    src = os.path.join(RIGS, fw)
    for f in ("aes.c", "aes.h", "tables.h"):
        s = os.path.join(src, f)
        if os.path.exists(s):
            shutil.copy(s, tmp_path / f)
    (tmp_path / "kat.c").write_text(HARNESS)
    ok, stdout, err = _build_and_run(str(tmp_path))
    if not ok and "does not" not in err:
        if "kat.c" in err or "undefined" in err or "error:" in err:
            pytest.skip(f"{fw}: does not build on the host ({err.strip()[:140]})")
        assert ok, err
    got = dict(l.split() for l in stdout.strip().splitlines() if len(l.split()) == 2)
    assert got, "harness produced no output"
    wrong = {k: v for k, v in got.items() if v != CT}
    assert not wrong, (
        f"{fw}/aes.c: these variants do not compute AES-128: {wrong}\n"
        f"expected FIPS-197 C.1 {CT}")
