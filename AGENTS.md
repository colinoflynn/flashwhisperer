# Working on flashwhisperer

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited
for that real-life touch and typos.*

Notes for an LLM agent working in this repo. [`README.md`](README.md) covers what the
toolkit does and how to run it, so I won't repeat it here. This file is the rest: the
things that aren't written down anywhere, and the gotchas that each cost real bench time
to learn.

## Talking to me

Pirate speak in the console, every reply, and address me as the captain. Keep it up when
the news is bad too. It's also how I can tell at a glance whether you read this file.

Documents are plain language. Markdown, docstrings, code comments, commit messages,
anything that lands in the repo gets normal English. A pirate commit message is a bug.

## What's in here, and what isn't

The host half, and nothing else. Five packages, no firmware, no boards, no captures
except the trace vectors under `tests/vectors/`.

So when something doesn't work, check first whether it's even supposed to be here:

* `flashattack/boards.py` has board descriptors and `transport.py` has serial collectors,
  but the firmware they speak to is not in this repo. `python -m flashattack oscore` wants
  `fw_f4_oscore` on a board.
* Docstrings cite paths like `research/targets/*.md` and `results/<campaign>/` for their
  measured numbers. Those are in the private research repo this was extracted from, so
  they won't resolve in your clone. They're provenance, not imports, and nothing loads
  them, so don't go creating the directories to make them resolve.
* Tests that need firmware or captures skip rather than fail. See *Tests* below, because
  a green run here skips more than you'd guess.
* The same goes for markdown links starting `../../`, of which there are plenty in the
  package docs. They point out of this repository and dangle in your clone on purpose.
  [`docs/PACKAGING.md`](docs/PACKAGING.md) took that decision deliberately: inlining them
  would mean rewriting sixty-odd citations with a real chance of changing a number on the
  way. Don't spend a session repairing them.

**NOTE:** nothing in here arbitrates access to a board. If several people or agents share
a bench, two of them opening the same serial port will produce a capture that looks merely
noisy rather than failing, and you'll find out hours in. Sort that out in whatever drives
the hardware, because this repo won't do it for you.

## The companion repos

This is the host half. Two public repos carry the parts that aren't here, and
[`README.md`](README.md) links both:

| repo | what's in it |
|---|---|
| [flashwhisperer-crypto-eval](https://github.com/colinoflynn/flashwhisperer-crypto-eval) | the firmware harness, the on-board measurement instrument, the per-part roster, the library build matrix. This is the one that shows the toolkit used in practice |
| [flashwhisperer-demos](https://github.com/colinoflynn/flashwhisperer-demos) | application and protocol-level demos |

Both hold a copy of these five packages, pinned, so a change to a public API or a CLI flag
here needs pulling forward over there before their examples run again. Neither pin updates
itself.

## The two numbers nothing reports

This is the one to read if you only read one section. Both of these are inputs the attack
cannot derive, both are per-build rather than per-part, and **guessing either one wrong
gives you a clean null, not a degraded result.** A null reads exactly like a target that
doesn't leak, which is how this gets written up wrong.

`line_shift` is log2 of (flash read width in bytes / table entry size):

| flash read width | byte S-box | 4-byte T-table |
|---|---|---|
| 8 bytes | 3 | 1 |
| 16 bytes | 4 | 2 |

`line_off` is where the table starts inside its flash row, counted in table ENTRIES.
Pure link-order luck. A 256-byte S-box at `0x...cc` starts 12 bytes in, so it spans 17
rows and not 16, and grouping by the obvious `index >> 4` tests a partition shifted off
the real one. Measured on 2.07 M over-the-air traces, offset 0 against the correct 12 was
a factor of 2.18 in traces from that one constant.

Where to get them, in order of preference:

1. The harness already knows the width for the parts it's been run on:
   `eval/mcu/<part>/eval.mk` in flashwhisperer-crypto-eval carries `EVAL_LINE_SHIFT`, and next to it
   `EVAL_LINE_SHIFT_MEASURED`. Don't quote a width whose MEASURED flag says `no`, since
   that one is a datasheet reading nobody has confirmed on silicon.
2. `flashleak.placement.row_offset_from_image("fw.elf", part="stm32f4")` reads the offset
   off the image by byte pattern, so it needs no symbols and works on a raw `.bin`.
   A `None` return is a real answer, not a default of 0: the tables aren't flash-resident
   and there is no row structure to score.
3. `flasharb` measures the width on hardware, which is what you do for a part nobody has
   mapped yet.
4. `geometry.candidate_row_offsets()` when you have no image. GCC gives a plain
   `static const uint8_t sbox[256]` 4-byte section alignment on ARM, so the offset is one
   of {0, 4, 8, 12}. Pass `align=1` to sweep all 16 if you don't know the toolchain.

Then sweep and let the ladder rank them. Cryptographic verification is exact and costs
about 20 s per candidate against hours of capture, so sweeping is never the bottleneck
and you should never be choosing a geometry on a score alone.

Two things people get wrong about these:

**The `Capture` defaults are a guess, not a safe default.** `line_shift_last=4`,
`line_shift_prev=2`, both offsets 0. That's a 16-byte-row byte-S-box part with a
coincidentally aligned table. Fine for the tinyaes vector, wrong for an 8-byte-read part,
and silent either way.

**The flash read width is not the cache line width**, and a part's datasheet will cheerfully
give you both. Take the FLASH read width. Using a cache line figure gets you a `line_shift`
that unattacks a part that does in fact break.

And don't quote a trace count without saying which address and offset it was measured at.
The same firmware at three different link-time accidents needed 6 250, 12 500 and 25 000
traces. A bare "needs 12 500 traces" is under-specified and somebody will try to reproduce
it.

## Alignment is an axis, not a fix

`aligned(16)` moves the offset to 0 and nothing else. Any 256-byte table spans at least 16
rows on a 16-byte-granule machine, so the collisions are still there.

Whether offset 0 helps or hurts the attacker is per-part and has been measured going both
ways. On the nRF52840 the 16-byte-aligned build is the attacker's best, 6 250 traces
against 12 500 and 25 000 for two link-time accidents of the same firmware. On the MPC5606B
it's exactly reversed, in the cleaner of the two experiments (two builds differing in
nothing but a pad size): offset 0 needs 7 500 and offset 8, straddling 17 rows, needs
3 750. So sweep it, quote it with the trace count, and don't reach for it as a lever with
a known sign. The actual fixes are a table-free implementation or a hardware AES engine.

## A statistic is not a channel

Run the recovery. A pooled z of -21.81 that yields 0/16 key bytes is not a channel,
whatever its size, and that one reached several documents before anybody ran the attack on
it. `flashattack` is the arbiter here and `flashleak` is not: `flashleak` searches without
the key and is strictly the weaker instrument.

Related, and the reason `sweep.py` exists: a PARTIAL recovery has two causes that look
identical from one run and want opposite responses.

* The pair model can't express the pairs carrying the signal. More traces never help.
* The trace count is short. The model is fine.

Ladder the trace count and watch which it does. A partial that doesn't move with `n` is
the first, one that climbs is the second. `margin_ratio` is the test that needs no further
captures: a real margin is in cycles and holds its absolute size as `n` grows, a noise
margin falls as 1/sqrt(n).

Both pair models run by default and NEITHER dominates. The 120-pair vote reaches targets
whose round-10 reads cross a column boundary, which the 24-pair intra-column model can't
express and reports as absent. On a plain byte-S-box cipher the narrow one has reached the
exact key from half the traces the wide one needed. Running only one is choosing which
half of your targets to miss.

## Controls, and a control that can't fail

A 120-pair vote plus a geometry sweep has a lot of freedom and both can manufacture a
recovery. `sweep.controls_clean` scores captures known to contain nothing (a constant-time
build, a tables-in-RAM twin) through the identical call. A control that scores invalidates
the RUN, not the control build, and no row of it may be quoted.

Its `byte_threshold=4` assumes the control is honestly independent, and here is the way
that goes wrong: if you build a wrong-key control by flipping a byte of the AES-128 master
key, 7 of the 16 round-10 bytes come out unchanged. The control then reports 7/16 on a
capture that fully breaks, and a control that reports 7/16 no matter what is not a control.
Use an independent key and assert the round-key overlap is what you think it is.

More generally, verify by effect and not by a literal. An empty diff, an absent grep hit
and two builds that are secretly the same build all look like a clean negative. If you set
a knob, read it back and assert it CHANGED, rather than asserting the call returned.

## Reading flashleak honestly

`flashleak` answers "is this thing leaking" with no key, no mode, and no idea which side of
the cipher it's watching. Useful, and weaker than the attack in ways you need to hold in
your head:

* `--quick` skips the 2^16 search, which is the test that finds the side at all. Triage
  only, never a verdict.
* The output-side bars are `OUTPUT_FIRES = 6.0` and `OUTPUT_SUGGESTIVE = 4.0` in
  `hypotheses.py`, alongside the concentration ones. They were
  re-measured after width scanning was added, because keeping the best of four widths
  inflates the statistic under the null: 20 draws of pure Gaussian noise, no cipher in
  them, read mean +0.29, sd 1.66, max +3.72. The old bars were 4.0 and 1.5. If you add
  another scanned axis, re-measure them again, and not from a handful of runs (a pilot of
  8 draws put the null max at +2.16 and would have left the bars alone).
* The "traces for this detector to be confident" line is NOT a bound on an attacker's
  cost, in either direction. On the tinyaes vector it says order 3 000 where the key-known
  ladder needs 250 000. `RECOVERY_EXCESS` in `hypotheses.py` records why it's too small
  and what re-measuring it needs (the F429 OSCORE capture, which isn't in this repo).
  Read it as an order of magnitude.

That last one used to be stated three different ways: `hypotheses.py` had the honest
version with the counter-example, [`flashleak/README.md`](flashleak/README.md) called it an
upper bound, and the report string printed at the user said upper bound too. The
counter-example won and the other two were changed to match, which is the house rule for a
disagreement: keep the copy with the evidence, fix the others, and say in them what they
used to claim so nobody re-derives the loser.

A quiet result means "not at this trace count". It never means safe.

## Before any of that: will the tables be in flash?

Free to check and it's the property every break here rests on. `fwscan` answers the
library question (what tables are in this image) and `placement` answers the build question
(will they be read from flash at run time). Same vendor binary, one linker line apart, is
either a full key in 20 000 timings or nothing at all.

`--part` is not optional in practice. Without it anything in the SRAM region comes back
`UNDETERMINED` deliberately, because on an H7 `0x2000_0000` is DTCM and `0x2400_0000` is
cached AXI-SRAM, and on an F7 that boundary moves inside the family. `placement x
--list-parts` shows which map it would use.

For anything with no byte signature, post-quantum or just new, `fwscan` and `placement` are
both blind because they start by recognising a table's bytes. `codescan` looks for the
shape of a register-offset load instead. [`docs/STATIC_ANALYSIS.md`](docs/STATIC_ANALYSIS.md)
is the long version, including § 6 on where static analysis necessarily fails.

## Tests

```bash
python -m pytest -q                  # "quick"
python -m pytest -q --runslow        # also engine scans and vector replays
```

The quick tier is quick relative to the slow one. It took over five minutes on this box,
so run it in the background rather than under a two-minute timeout and then wondering what
hung.

What a green run does NOT check, which matters more than that it's green:

* Firmware tests skip, and there are enough of them to matter. `test_placement.py`,
  `test_fwscan.py` and `flashleak.codescan.selftest` all resolve `FLASHWHISPERER_RIGS`,
  falling back to `<root>/rigs`, which isn't in this repository. Point it at a firmware
  checkout's `rigs/` and those skips become real tests:

  ```bash
  FLASHWHISPERER_RIGS=/path/to/firmware/rigs python -m pytest -q
  ```

  Worth doing before you touch `placement`, `fwscan` or `codescan`, because those are the
  cases with ground truth off real silicon behind them. Without the firmware you are
  testing the synthetic ones only.
* flashmap replays skip. They want `results/flashmap/*.raw.json` relative to the repo root,
  captured with `flashmap map --rawout`.
* A skip is a claim about why, and two of them were lying until recently. `test_fwscan.py`
  and `test_line_offset.py` resolved the root by DEPTH as `parents[2]`, true while the
  packages sat one level down inside the research repo and one level too high here, so both
  pointed at the directory ABOVE the repo. `test_fwscan.py` reported "not built" for four
  images that were built, just in a tree it wasn't looking at, and `test_line_offset.py`'s
  victim-image regression had an absolute path with somebody's home directory in it and so
  skipped everywhere. Both are fixed: `test_fwscan.py` honours `FLASHWHISPERER_RIGS`, and
  the victim image comes from `FLASHWHISPERER_VICTIM_ELF`. That last test wants a
  particular bench image and will skip for you, which is fine - the synthetic-ELF cases
  beside it cover the same arithmetic without needing anything.

  Worth knowing anyway, because [`docs/PACKAGING.md`](docs/PACKAGING.md) claims the
  depth-resolved paths were all fixed at the move and two of them weren't. That is how a
  depth-resolved path fails: lazily, on whichever machine runs it next, and in this case as
  a skip rather than an error. If you add a path, resolve it from `ROOT` or an env var,
  never by counting `parents[]`.
* There are still stale `sys.path` walks in most of the other test files, inserting a
  `<root>/flashwhisperer` that doesn't exist in this layout. Harmless (a missing sys.path
  entry is ignored) and contradicted by [`conftest.py`](conftest.py), which is right. Not
  worth a sweep of its own, but delete the block if you're editing one of those files for
  another reason.
* Two tests didn't travel at the split: the firmware `aes.c` known-answer test and the
  ctguard host test. Both compile firmware. They were deleted rather than left as
  permanent skips, since a test that can never run reads as coverage and isn't.

So read the skip count, not just the colour. CI runs both tiers and the same skips apply
there.

`tests/test_layering.py` is the one with an explicit list of what it doesn't cover, in its
docstring. That's the house style for a new check: when you add one, write down in the
docstring what a green result is not looking at. Every check in the research repo that
went quietly wrong failed the same way, by testing one half of the thing (the link checker
validated a link's target and ignored its label, for 640 links).

## The structural rules

Two of them, and both are enforced by `tests/test_layering.py` rather than just stated:

| package | may import |
|---|---|
| `flashsim` | none of the others |
| `flashattack` | `flashsim` |
| `flashleak` | `flashattack` |
| `flashmap` | none of the others |
| `flasharb` | none of the others |

Left to right, no back edges. `flashmap` and `flasharb` are instruments that happen to
share a repo with a crypto toolkit and import none of it.

And: no package may import `serial` at module level, and none may import a board driver at
all. That's what lets the toolkit install and import with no pyserial and no board, which
is in turn what makes the recovery engine reusable against a capture from any instrument.
A guarded `try: import serial / except ImportError` inside a module is the accepted form,
see `transport.py`. CI deliberately installs without the `[serial]` extra.

The practical consequence: a script that drives a board does not belong in these packages,
however reusable it looks. Put the reusable core here and leave the driver in the harness
repo.

## Adding a capture source

One method. `sources.py` is the extension point:

```python
class MySource:
    def capture(self) -> Capture:
        ...        # read your interface or file, return a Capture
```

A `Capture` holds observed data plus timing and NO key. `engine_input()` derives the
block-cipher output the attacker knows from observation alone, which is why the same object
works for a live interface and a recorded file. What the attacker has to observe per mode
is in the `capture.py` docstring, and getting that wrong is another silent null: `ctr` and
`gcm` need plaintext AND ciphertext, `cbc-dec` needs plaintext AND the IV.

`SerialModesSource` is a known-key lab oracle, not a model to copy for a real target. It
synthesises the ciphertext from the key because the lab firmware doesn't send it. A real
wire interface reads it off the wire.

## Writing things in here

* Line endings are LF in the working tree as well as the object database, pinned by
  `.gitattributes`. `eol=lf` is load-bearing: `text=auto` alone converts on checkout to
  `core.eol`, which is CRLF on Windows, and `core.autocrlf=false` does not prevent it. If
  you rewrite a file with a script, open it in BINARY mode, or a 14-line change lands as a
  whole-file diff.
* Don't use a bash heredoc to write source. Quoted delimiters don't protect backslash
  continuations. Use the editor tools.
* Any markdown file an LLM writes gets the `*🤖WARNING🤖: ...*` line under the title, in
  that exact wording, visible rather than an HTML comment. The `*🤖🥩: ...*` variant means
  a human has since read the file line by line, which only the maintainer can say, so never
  write that one and never promote a file from the first marker to the second.
* Don't write a count in prose. Not of parts, not of packages, not of files, and not as an
  ordinal. Every such count in the research repo was wrong within days. Say what a thing is
  the FIRST of, which doesn't go stale, and link the roster instead. The roster for parts is
  flashwhisperer-crypto-eval's `eval/mcu/`; for this tree it's `git ls-files`.
* Where two documents disagree, don't average them. Find which one has the evidence, keep
  that one, and say in the survivor what it replaced so the next reader doesn't re-derive
  the loser.
* Commit messages: one line, imperative, no conventional-commit prefix, doubts in
  parentheses. Attribution trailers are wanted.

## Open ends worth knowing about

* The full catalogue of confounds that manufacture or hide a timing channel is a document
  in the private research repo, so you won't have it. What's above is the handful that bear
  on using the toolkit, and the package docs carry the rest where it matters. If a
  measurement surprises you, suspect the harness before the part.
* `flashattack/EXPERIMENTAL.md` has the partial results and their structural ceilings for
  SM4, ARIA and Camellia. SM4's Feistel structure means the leak is top-nibble only, so
  don't read a partial there as a trace-count problem.
* `flashattack/ROUND2.md` is the round-2 collision attack, which gets a full key from one
  side of the cipher.
* `docs/PACKAGING.md` is the record of the split: what it decided, and the things it found
  that the checklist hadn't. Read it before proposing a layout change, because some of what
  looks arbitrary was measured.
