# flashwhisperer

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Host-side toolkit for flash-accelerator timing side channels on
microcontrollers: a simulator, a target-agnostic key-recovery engine, a
black-box leak assessor, a memory-system mapper, and an arbitration probe.

Nothing here drives a board by itself. Every package takes either recorded
data or a transport you supply, which is what lets the recovery engine be
re-used against a capture from any instrument.

```bash
pip install -e .            # the five packages
pip install -e .[serial]    # ...and pyserial, for the transports that want it
python -m pytest -q         # fast: FIPS vectors, schedule inversion, mode mapping
python -m pytest -q --runslow   # also engine scans and captured-trace replays
```

## The packages

| | |
|---|---|
| `flashsim` | simulator: vectorised AES emitting ordered table-access traces, a flash line-buffer / small-cache timing model, and a Bernstein-style correlation attack over the result |
| `flashattack` | the recovery engine: last-round cache-collision scoring, row geometry, outlier-tolerant assembly, AES-128/192/256, mode mapping, feasibility estimates, and the `flashattack` CLI |
| `flashleak` | black-box assessment: given blocks and times, or a target you can send to, decide whether it leaks, without being told the mode, the direction, or which side you're watching |
| `flashmap` | reverse-engineer a part's memory system: flash read width, read latches, caches, and which configuration knobs reach them |
| `flasharb` | the arbitration probe's host half: how many cycles a table load saves by colliding with the previous load in the flash read word |

Import layering runs left to right in that table and has no back edges.
`flashmap` imports none of the others and `tests/test_flashmap.py` asserts
it; the rest holds because nothing has broken it, which is not the same
thing. [`docs/PACKAGING.md`](docs/PACKAGING.md) has the re-measurement
command.

**NOTE:** a package here may not import `serial` at module level, and may
not import a board driver at all. That rule is what keeps the toolkit
installable and testable without a bench, and it's why the scripts that
drive hardware live in the firmware repository rather than in here.

## Where the firmware went

This repository is the host half. The firmware, the boards, the measurement
rigs and the campaign results live separately, and a few things in here
point at them:

* Docstrings cite campaign documents (`research/targets/*.md`,
  `results/<campaign>/`) for their measured claims. Those paths resolve in
  the firmware repository, not here. They're provenance, not imports, and
  nothing loads them.
* Two tests were left behind: a known-answer test that compiles each
  firmware copy of `aes.c`, and the ctguard host test. Both test firmware.
* Tests that read firmware assets skip when the assets are absent. Point
  `FLASHWHISPERER_RIGS` at a firmware checkout's `rigs/` to run them, and
  drop `flashmap` captures at `results/flashmap/*.raw.json` to run the
  replays.

## Status

Extracted from a private research repository, with the history of all five
packages intact across the reorganisation that first grouped them. The
distribution is named for this repository; `flashattack` stays the console
script, since that spelling is in every capture script written against it.

No licence is declared yet. That is a decision, not an oversight.
