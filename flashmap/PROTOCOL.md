# `memmap/1` — the device protocol `flashmap` speaks

One firmware shim per part, one host tool. The shim exposes **timed memory
primitives and configuration knobs**; it knows nothing about what is being
inferred. All structure inference happens on the host, so adding a part means
writing a shim, not an analysis.

This is deliberately **not** a crypto tool. It characterises a memory system:
flash read width, read latches, data and instruction caches, and the knobs that
move them.

## Line format

ASCII, one command per line, `\n` terminated, 115200 8N1 unless the shim's
banner says otherwise. Replies are one line unless stated. Numbers are decimal
unless prefixed `0x`. A command the shim does not implement replies `unsupported`.
Errors reply `err <reason>`. **Every reply ends in `\n` and nothing else is
printed** — no banners mid-stream, no progress chatter.

## Commands

### `V` — identify
```
memmap/1 <part> <core> <clk_hz> <timer> <timer_hz> <caps>
```
`timer` is `systick` | `dwt` | other; `timer_hz` is the *counter's* rate, which
is not always the core clock. `caps` is a comma-separated set from
`counters` (has hardware hit/miss counters), `icache`, `dcache`, `unified`,
`waitstates`, `ramfunc` (the probe loop runs from RAM/TCM).

> The shim MUST verify its counter actually advances before reporting it, and
> MUST report `timer=none` if it does not. A frozen counter makes every probe
> identical and therefore every structure look absent — the archetypal silent
> pass. The DWT is dead on the nRF52 and on the H7 when enabled too early; both
> were found this way.

### `R` — list probe regions
One line per region, then `END`:
```
<name> <base_hex> <size_bytes> <kind>
```
`kind` ∈ `flash` | `sram` | `itcm` | `dtcm` | `axisram` | `ccm` | `other`.
Every shim MUST expose at least one `flash` region and one uncached RAM region
of the same size — the **twin**. The twin is what every flash measurement is
subtracted against; it must be the *same probe function over an identically
shaped buffer*, never a second function.

### `K` — list knobs
One line per knob, then `END`:
```
<name> <values,...> <current>
```
Canonical names, so the host can reason across parts: `waitstates`, `icache`,
`dcache`, `prefetch`, `waysel`, `unified`. Parts without a knob simply omit it.

### `S <knob> <value>` — set a knob
Reply `ok <knob>=<value_readback>`. **The shim performs whatever invalidation
the reference manual requires** (F4/G4: pulse `ICRST`/`DCRST` with the caches
off; L5: `ICACHE_CR.CACHEINV` and wait `BSYENDF`; M7: `SCB_InvalidateICache` /
`InvalidateDCache`). The host trusts the readback, so read the register back —
do not echo the requested value.

### `T <region> <mode> <args...>` — one timed primitive
Reply `<cycles> <checksum_hex>`. The checksum is over the values actually read;
it exists so a probe that measured nothing (loop optimised away, region
unmapped, `.ramfunc` not copied) is detectable rather than silently fast.

Modes — all take byte offsets/strides, all run from RAM if `ramfunc`:

| mode | args | what it times |
|---|---|---|
| `walk` | `stride n` | cold forward walk, `n` reads `stride` apart |
| `reread` | `off` | read A, read A+`off`, re-read A — **the latch probe** |
| `evict` | `n spacing` | read A, touch `n` addresses `spacing` apart, re-read A |
| `chase` | `n stride reps` | pointer chase over `n` nodes (defeats prefetch) |
| `alt` | `off reps` | alternate A and A+`off` `reps` times — amplification |
| `nop` | `reps` | the loop with no memory access — the instrument's own floor |

`alt` and `chase` exist because single-shot `reread` sits at the counter's
resolution floor (10 vs 13 cycles on the nRF). Accumulating over `reps` gives
1/`reps`-cycle resolution and is how a sub-cycle effect becomes visible.

### `A <region> <mode> ...` — same, but returns `min max mean n` over repeats
Optional. Where absent the host repeats `T` itself.

### `C` — hardware counters
`<name>=<value> ...` then `END`, or `unsupported`. Reset on read.
Only the L552 (`ICACHE_HMONR`/`MMONR`) and nRF52840 (`NVMC.IHIT`/`IMISS`) have
these. Where present they are an **independent instrument**: every timing-derived
claim can be cross-checked against a counter, and a disagreement is a result.

### `X` — self-test
Reply `ok` or `fail <what>`. MUST check: the timer advances; a `nop` costs less
than a `walk`; the flash and twin checksums are what the shim expects; and if
`ramfunc` is claimed, that the copied code's first word is not zero.

## Rules the host relies on

1. **Interrupts off inside the timed region**, fixed clock, nothing printed.
2. **A fixed warm-up access precedes every timed access**, so each probe enters
   from the same state. Without it the first access after a knob change is
   systematically dearer and reads as input dependence.
3. **The probe loop runs from RAM/ITCM** where the part allows it. On a part with
   an I-cache this is not optional: running from flash with the I-cache off
   understated the H7's differential by 42 %.
4. **Buffers are aligned to at least 32 bytes** and the shim reports the actual
   address, because alignment mod the read width is itself a variable.

## Adding a part

1. Copy the nearest existing shim (`fw_map_*`).
2. Implement `V R K S T X`; `A` and `C` are optional.
3. Run `python -m flashmap selftest --port COMn` — it exercises every command,
   checks the checksums move when they should, and fails loudly on a frozen
   counter or an uncopied `.ramfunc`.
4. Run `python -m flashmap map --port COMn --out <part>.json`.
