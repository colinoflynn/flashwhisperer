# Making `flashmap` right on every board it can reach

The brief: *"a tool that produces reliable results on all current platforms,
without any hacks or results that require special knowledge. It may be some
cache artifacts cannot be easily determined."*

The standard held to throughout: **a result must not depend on the operator
already knowing the answer.** A number that is only correct because someone
chose the right sweep parameter for that part is a hack. `unknown` is a good
outcome. A confident wrong answer is not.

Every measurement below is a fresh capture taken today through
[`PROTOCOL.md`](PROTOCOL.md) on the three boards this work owns -- NUCLEO-F429ZI,
NUCLEO-G474RE and NUCLEO-L552ZE-Q -- with the shims unchanged. **Every defect
turned out to be in the host inference or in the plan. Not one was a shim bug**,
and no firmware under `hardware/fw_map_*` was modified.

The committed captures (`flashmap/f429.raw.json`, `hardware/map_g4.raw.json`,
`hardware/map_l5.raw.json`) were taken part-way through the work, and two plan
details moved after them: the wait-state calibration's divisor was corrected, so
those runs chose `LATENCY = 5` where a fresh run chooses 4, and the phase-2
chase ladder was widened. Neither changes a structural result -- every number in
the table below is what `flashmap map --raw` produces from those captures under
the final code, which is exactly what the new regression tests re-check on every
run. Each capture is a complete, unmodified transcript of the board it names.

---

## 1. Where it stands

| | F429 | G474 | L552 |
|---|---|---|---|
| read width | **16 B** | **8 B** | **8 B** |
| fill unit | unknown (see section 4) | unknown (see section 4) | **16 B** |
| latch | **1 x 16 B**, depth 1 | **1 x 8 B**, depth 1 | **2 x 8 B on A[3]**, depth 1 |
| does a register reach the latch | no | no | no |
| cache | **128 B, 8 tags x 16 B, fully associative** | **256 B, 8-way, 32 B conflict period**, counted in tags | **8192 B, 16 B line**, counted in tags; 1-way/8192 B or 2-way/4096 B by `WAYSEL` |
| replacement policy | **LRU**, measured against FIFO | **LRU**, measured against FIFO | **LRU**, measured against FIFO |
| wait-state scaling | 1.000 cyc/WS | 1.000 cyc/WS | 1.000 cyc/WS |
| twin calibration | +0.000 cyc/access | +0.000 cyc/access | **-1.000 cyc/access** (isolated config) |
| which knob does what | `dcache` controls reuse and masks the latch | `dcache` controls reuse | `icache` controls reuse; `waysel` **re-indexes** it at constant capacity |

All three match their ground-truth documents -- `hardware/F4_LATCH.md`,
`hardware/G4_ART_GEOMETRY.md`, `hardware/L5_GEOMETRY.md` -- with no
part-specific tuning anywhere in the plan or the inference. The L552's four
wrong claims are gone, and the G474 and F429 did not regress.

---

## 2. The four defects, and what the fix actually was

### 2a. `latch = 16 B x 1 entry` on the L552 (truth: 8 B x 2 entries on `A[3]`)

The right fit was already in the evidence -- 47/47 offsets fit `8 B x 2` -- and
was outvoted by five wait-state cells carrying six offsets each. Six offsets
cannot separate `8 B x 2` from `16 B x 1`: at 0, 4, 8, 16, 32 and 64 the two
models make *identical* predictions. They were nevertheless casting a vote,
because the aggregation counted each configuration's *best fit* and
`_fit_latch`'s tie-break prefers the smaller entry count.

**Fix: intersect consistency sets instead of counting best fits.** Each resolved
configuration now contributes the *set* of models its own offsets are consistent
with, and the answer is the intersection. A configuration that cannot separate
two models is silent on that distinction rather than voting for one of them.

This is the right weighting and not merely a heavier one, because it is not a
weighting at all: it is the logical content of what each sweep measured.
Evidence density is a proxy for discriminating power and would have been wrong
here in a different way -- a dense sweep of only non-negative offsets is no
better at separating an aligned block from a proximity rule than a sparse one.

The claim now also reports what it could *not* separate. If the intersection
holds more than one model the family is listed, the representative is the
*simplest* member of it (fewest entries, then smallest granularity) and the
confidence drops to `low`; if the intersection is empty the configurations
contradict each other, and that is reported as the finding rather than resolved
by preference. The published `hardware/F4_LATCH.md` table, fed in literally, is
exactly such an under-determined case -- its ten offsets fit `16 B x 1` and
`8 B x 2` equally -- and the tool now says so.

Two consequences fell out for free. The L552 latch's *depth* now resolves (1),
because the fit is taken from the dense sweep, which is in a configuration that
has `evict` rows at 16 B; and the aligned-block-versus-proximity comparison now
runs on a sweep that has negative offsets, so the caveat "this claim cannot tell
them apart" is replaced by a measurement (100% against 68%).

### 2b. `waysel -> data_reuse: no effect` on the L552

The knob-map metric was the scalar `max N_evict`, which is 1024 at spacing 8 in
both `WAYSEL` modes. The knob's entire effect is in the *shape*: 1-way = 512
sets with an 8192 B conflict period, 2-way = 256 sets with a 4096 B one, 8 KB
either way.

**Fix: the metric is now the fitted `(ways, conflict period, capacity)`
triple**, and there is a fourth verdict for what this knob does. A knob may:

* `control` a structure -- a matched pair moves it, capacity included;
* `mask` it -- the probe stops being able to see it (a cache holding both probe
  addresses hides the latch), which is not the same claim as switching it off;
* **`re-index`** it -- associativity traded against index width at *constant
  capacity*. This is a real category and the tool had no vocabulary for it;
* `confound` it -- see 2c.

`waysel` now reports `re-indexes: 1-way/period 8192 B/8192 B -> 2-way/period
4096 B/8192 B`, and the cache claim, which used to file the same fact as
`! Not every knob setting fits the same geometry`, now attributes it: it looks
for a knob that partitions the fitted geometries and says *"`waysel` selects
between them at constant capacity; neither is more true than the other"*.

### 2c. `replacement_policy = pseudo_random` on the L552 (truth: LRU)

Three causes, all of them constants that were secretly facts about one chip.

1. **The re-touch discriminator never ran.** `default_plan` emitted its `chase`
   at 16/32/64 B, and `Bench.policy_plan` emitted its re-touch walk with
   `ks = (2, 4)` hard-coded -- but `k` must be strictly *below* the measured
   associativity, or the target is evicted before the re-touch happens. On a 1-
   or 2-way cache `(2, 4)` yields **no rows at all**. `ks` is now derived:
   `{1, ways//2, ways-1}` intersected with `[1, ways)`.
2. **Phase 2 was sized from the wrong configuration.** It used the headline
   geometry, which on the L552 is the `WAYSEL = 0` direct-mapped one -- which has
   no victim to choose. It now picks the *isolated* configuration with the
   largest measured associativity and takes the spacing from that
   configuration's own conflict period.
3. **The verdict rested on a cyclic chase at `loopmem = 1`** -- the deliberately
   confounded configuration, on the one part in the rig whose cache is unified --
   at a stride 256x smaller than the conflict period, so it could not have
   reached the knee however large the working set. The chase discriminator now
   requires the stride to be a **multiple of the measured conflict period**,
   requires adjacent working-set sizes, and refuses to run in a configuration
   where the probe loop shares the structure under test.

With that, phase 2 on the L552 emits `evict n 4096 -4096` in the 2-way
configuration and the answer comes out directly:

```
waitstates=5 icache=1 waysel=1 loopmem=0: evict walk re-touching the target
after k=1 conflicts (spacing 4096, 2-way) loses it at n=4;
LRU predicts 4, FIFO predicts 3   [step sharpness 1.000]
```

which is the hand-measurement in `REQUESTS_g4_l5.md` section 10c reproduced by the
generic tool. On the F429 the same machinery now fires at three re-touch
positions (k = 1, 4, 7 -> n = 10, 13, 16; LRU predicts 10, 13, 16 and FIFO
predicts 9 throughout).

A fourth fix under the same heading: the cyclic chase's "is it a full thrash?"
test compared an absolute miss rate against a miss cost taken from a *different
loop body*. On the L552 a genuinely thrashing 3-line set over a 2-way cache
normalised to 0.75 -- close enough to the pseudo-random band that the verdict
would have been decided by the normalisation. The test is now **relative**: the
plan also emits a working set far past the knee, and the question is what
fraction of *that* the one-line-over case reaches. LRU and FIFO reach 100%; the
synthetic random victim reaches 34%. Every normalisation constant cancels.

### 2d. `twin_calibration = +0.516 cyc/access` on the L552

It averaged four `-1.000` rows from the isolated configuration with `+2`/`+3`
rows from the confounded one and a `+0.5` row from a different loop body. The
headline told the reader to correct in the wrong direction by 1.5 cycles per
access, for every structural claim in the report.

**Fix: one number per (configuration, loop body), never pooled across either.**
The headline is the isolated configuration -- the one every structural claim is
measured in -- and it is named in the claim's value, not only in its evidence.
Where the values within that pool disagree by more than 0.25 cyc/access the
claim is `unknown` rather than a mean. The sign is explained in the caveat
rather than flattened to the word "BIASED": a negative value means the flash
buffer measures *cheaper* than its own SRAM twin, which is the bus-port
signature, and correcting means subtracting it.

The L552 now reports `-1.000 cyc/access at 0 wait states in
waitstates=0 icache=0 waysel=0 loopmem=0 (walk body)`, with the confounded
`+2/+3` rows listed in the evidence and marked as such.

---

## 3. The audit: every constant in the plan that was a fact about one chip

This was the highest-value part of the work, and it found more than the brief
listed.

| constant | what it really was | what replaced it |
|---|---|---|
| `ns = [... 28, 29, 30, 31, 32, 33, ... 512, 513, ...]` | **29 is the G474's published transition point and 513 is the L552's.** Two chips' answers, written into the sweep that is supposed to discover them | a generated schedule: contiguous 0..32, then every octave bracketed from both sides |
| `chase` at `sp in (16, 32, 64)` | works on a fully-associative 32 B ART, never fires on a part whose conflict period is 4 KB | phase 1 uses the three smallest spacings the region admits, for reuse evidence only; the policy chase is emitted in phase 2 at the **measured** conflict period, and the inference refuses any chase whose stride does not divide it |
| `policy_plan(ks=(2, 4))` | assumes at least a 5-way cache | `{1, ways//2, ways-1}` from the measured associativity |
| phase 2 sized from `cache.enabled_in` | the configuration with the most *reuse*, which can be the direct-mapped one | the isolated configuration with the largest measured **associativity** |
| `_reference_waitstates`: "smallest advertised value >= 4" | assumes one wait state is worth one cycle -- true of every part in this repository, and not a property of the protocol | `Bench.calibrate_waitstates` **measures** the flash penalty each advertised setting delivers, with every other knob at its minimum, and picks the cheapest that clears 4 cycles. The old rule survives only as the offline fallback |
| `reread` offsets, hand-listed | a list that happened to straddle the boundaries of the parts on the bench | generated from `LATCH_GRANULARITIES`, the same ladder `infer.py` fits over, so the sweep is guaranteed to straddle every boundary any candidate model draws |
| `alt` offsets `(0, 4, 8, 16, 32, 64)` | the same | the same ladder |
| `spacings` starting at 8 | assumes no part has a 4-byte fetch unit | every power of two from 4 upward that the region admits |

Two further constants were left in place, deliberately, and are named here so
they are not mistaken for oversights:

* **`MAX_PLAUSIBLE_LINE = 64`** in `infer_cache`, used to decide that an
  8192-byte conflict period is an index period rather than a single cache line.
  This is a fact about cache design in general, not about a part; no
  microcontroller has a line above 64 bytes. It is an architectural prior and it
  is stated in the claim's evidence.
* **`_MIN_MISS_CYCLES = 4.0`**, the separation a miss must have before hit and
  miss can be told apart. This is a property of the *instrument* -- an
  integer-valued counter and a twin that can be a cycle off -- not of any part,
  and it is now what the wait-state calibration measures against rather than a
  wait-state number.

### What was NOT done, and why

`REQUESTS_h7_nrf.md` section 4a asks for the read-width aggregation to "take the modal
value across configurations". That would fix the H723 and **break the L552**: on
the L552's isolated grid the two saturation strides are 2 configurations each --
a tie -- and on the full grid the majority (6 of 8) is the 16-byte *fill unit*,
not the 8-byte read width. Modal is a rule that happens to work on one part.

The rule adopted instead is the same one that fixed the latch: **a structural
claim is decided on the isolated cross-product grid at the reference wait state,
and the wait-state sweep cells do not vote.** They exist to fit a slope and they
include `LATENCY = 0`, where every flash structure reads flat by construction.
That single `waitstates = 0` cell was the one configuration in thirty-eight that
saturated early on the H723. And where the saturation stride still is not
invariant, the tool now checks whether **a knob explains the split**: a fill unit
is something a knob enables, so if no knob separates the early-saturating
configurations from the rest, the claim says so and drops to `low` confidence
instead of printing a tidy two-number answer.

I could not re-infer the H723 itself -- there is no committed raw capture for it
and the board is another agent's -- so the fix is carried by two regression tests
that reproduce the shape
(`test_one_waitstate_sweep_cell_cannot_set_the_read_width` and
`test_an_unexplained_split_is_not_reported_as_a_fill_unit`). Re-running
`flashmap map --raw` over an H723 capture is the check that remains outstanding.

---

## 4. What is still `unknown`, and whether that is reachable

Only the last of these is "merely unmeasured".

**Unreachable with `memmap/1`'s primitives -- more traces cannot fix them:**

1. **The G474's `sets` and `line` separately.** A uniform-stride eviction surface
   pins the *conflict period* `sets x line` and the ways, and nothing in the
   protocol separates the two factors: "8 fully-associative 32 B tags" and
   "8-way x 4 sets x 8 B lines" predict the same number for every mode here.
   Capacity (256 B) and ways (8) are measured; the split is reported as a family,
   not chosen. Separating them needs a probe that distinguishes "two words of one
   line" from "two lines of one set" -- a randomly addressed working set swept
   across its alignment -- and there is no mode for that.
2. **`ways` against `sets` when the cache is large relative to the probe
   window.** `ways` conflicts in an S-set cache and `ways/2` in a 2S-set cache
   land at the same walk index, so the two are separable only by a spacing at or
   above the larger conflict period. Where the region is too small the tool
   reports a **capacity floor** and names the probe region size that would settle
   it. That is not the case on any of my three boards; it is on the H723 through
   a 64 KB window, which
   `test_h723_associativity_is_unknown_when_the_region_is_too_small` pins.
3. **The L552's two latch entries against a two-line direct-mapped cache.**
   Behaviourally the same object under every primitive here, and the part's own
   hit/miss counters read zero in the only configuration where either is visible.
   An identifiability limit, not a resolution limit.
4. **True LRU against tree-PLRU.** The re-touch walk separates LRU from FIFO and
   nothing more. Both are "recency", and the reference strings this protocol can
   build do not distinguish a true LRU stack from a tree approximation of one.
5. **The instruction side, independently of the probe loop.** With the loop in
   flash, a walk over the *SRAM* twin -- zero cacheable data accesses -- still
   counts hundreds of instruction-fetch hits on the L552. Reaching it needs an
   `exec <n> <spacing>` mode that executes flash-resident code at known
   addresses. `PROTOCOL.md` has no such mode and this work did not add one.
6. **`fill_unit` on the F429 and the G474.** Reported `unknown`, and that is the
   correct answer: on both parts every knob setting saturates at the same stride,
   so no fill unit is *distinguishable* from the read width. On the L552, where
   `icache` does move the saturation, it comes out at 16 B and is confirmed twice
   -- by the warm walk and by the eviction surface.

**Reachable, and a real caveat rather than a gap:**

7. **The L552's `flash - twin` is not an unbiased estimator.** `-1.000
   cyc/access` with the probe loop in SRAM, positive with it in flash, and
   loop-body dependent. The instrument-neutral quantity
   `flash(LATENCY) - flash(0)` is unaffected, and the claim now says so and names
   the configuration. Why the older bespoke `fw_l5_cache` reads one cycle per
   access dearer on the flash column remains unexplained
   (`FINDINGS_g4_l5.md` section 2c).
8. **One die, one clock, 16 MHz.** Every repeat has `min == max`. That is
   repeatability, not accuracy, and item 7 is exactly the kind of systematic
   error no number of repeats would reveal.

### One false alarm removed on the way past

A guard requested in `REQUESTS_g4_l5.md` -- "a cache-enable knob reported as
reaching nothing is more likely a classifier problem than an inert register" --
turned out to be wrong for `icache`, and it fired on the F429 and the G474 as a
`high`-confidence caveat saying *"treat this as a measurement or classification
failure"*. It is not one. Every primitive in `memmap/1` is a data access, so an
instruction cache that is not unified with the data path is invisible to all
three metrics **by construction**, and that is the published result for both
parts. The guard now covers only `dcache` and `unified`, whose structures the
probe can actually see; for `icache` the tool states the positive version
instead, and it does not need a special case for the L552, whose unified ICACHE
comes out controlling data reuse from the same measurement.

---

## 5. Protocol changes, proposed with their reasoning

Both are in [`PROTOCOL.md`](PROTOCOL.md), in the style the `evict start`
extension was adopted in.

* **`loopmem` is now a canonical knob**, with `0` = probe loop in RAM/ITCM
  (isolated) and `1` = in flash (deliberately confounded). It has to be canonical
  because the host must be able to tell an instrument control from a device
  register *by name*: a shim that called it `iloc` would have the host report
  "a register reaches the latch" on the L552, where the truth is that running the
  probe from flash destroys the measurement. With the name fixed, the host takes
  every structural claim from `loopmem = 0`, reports a difference across it as
  `confounds` rather than `controls`, refuses to read a replacement policy out of
  a `loopmem = 1` configuration, and never pools a twin calibration across it.
* **The smallest advertised value of every knob is its least-accelerated
  state.** Every shim already does this; it is now written down because the host
  relies on it in two places a transcript does not reveal -- the wait-state
  calibration runs with every other knob at its minimum, and `min(values)` is
  taken as `loopmem`'s isolating value.

Two host behaviours are documented but change no wire format: the wait-state
calibration pass before the plan, and the second pass sized from the first pass's
geometry. A shim needs to do nothing for either beyond honouring `evict`'s
optional third argument; one that does not gets the cyclic chase alone and an
honest `LRU or FIFO`.

---

## 6. Regression tests

`tests/test_flashmap.py` now carries three layers.

* **Synthetic parts** (unchanged): a mechanism-level model of a memory system,
  configured as each of the six parts.
* **Published tables** (unchanged): the literal tables from the `hardware/*.md`
  write-ups.
* **The real captures, re-inferred** (new): `infer.py` is run over the committed
  `flashmap/f429.raw.json`, `hardware/map_g4.raw.json` and
  `hardware/map_l5.raw.json`, and the published structure is asserted. Every one
  of the L552's four wrong claims has an assertion, including the two that are
  about *how* the answer was reached: `does not discriminate` must appear in the
  latch evidence, and `waysel` must be `re-indexes` with a reason that mentions
  capacity. A fourth test asserts the honesty properties across all three
  captures -- an under-determined latch model family must cost confidence, and
  `pseudo_random` may only ever be claimed from an isolated configuration at a
  conflicting stride.

These cost nothing to run -- `--raw` re-inference touches no hardware -- and they
are what stops a fix for one part from silently breaking another, which is how
three of the defects above reached the output in the first place.

`pytest tests/test_flashmap.py -q` and the whole-repository `pytest tests/ -q`
both pass.

**Outstanding, and not mine to do.** `flashmap/h723.json` and
`flashmap/nrf52840.json` are inferred structures with no committed raw capture
beside them, so they could not be re-inferred here and are now stale with
respect to `infer.py` -- `h723.json` in particular still carries the
`read_width = 8` this work fixed the cause of. Whoever owns those boards should
re-run `flashmap map --raw` over their captures (or re-capture with `--rawout`,
which is what makes a structure file reproducible at all) and commit the raw
alongside, so the same real-capture regression test can cover them.

---

## 7. Bench notes, not tool defects

* The **NUCLEO-F429ZI stopped answering on COM9** twice during this work, once
  between sessions and once immediately after a `map` run, and
  `boards.py reset` did not recover it -- only a reflash did, after which three
  consecutive sessions passed. It also refused to open with
  `PermissionError: Access is denied` for a minute or so afterwards. It looks
  like the ST-LINK VCP wedging rather than the shim being damaged, and running
  three captures in parallel seems to make it likelier. Recorded because a future
  run that sees this should reach for `boards.py flash` rather than start
  debugging the shim.
* Long captures must be launched with an explicit tool timeout. A foreground
  command that overran its own 120 s budget took two running background captures
  down with it.
