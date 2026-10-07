# What `flashwhisperer/` would need to become a project of its own

The five packages here are meant to be liftable out of this repository, and
this records what that would take, measured rather than assumed. It lives
inside the thing it describes so it travels with it.

**Status 2026-10-07: the packaged test suite passes with only
`flashwhisperer/` on `sys.path`.** It did not before: `tests/test_line_offset.py`
inserted `hardware/` to reach the row-offset arithmetic, which was the one back
edge out of the package, and that arithmetic is now
[`../flashattack/geometry.py`](../flashattack/geometry.py).

## The layering, and what enforces it

| package | imports |
|---|---|
| `flashsim` | none of the others |
| `flashattack` | `flashsim` |
| `flashleak` | `flashattack` |
| `flashmap` | none of the others |
| `flasharb` | none of the others |

Left to right, no back edges. Only `flashmap`'s independence is enforced by a
test (`tests/test_flashmap.py` asserts it imports no crypto); the rest holds
because nothing has broken it yet, which is not the same thing. Re-measure with

```bash
for pkg in flashsim flashattack flashleak flashmap flasharb; do
  printf "%s -> " $pkg
  grep -rhoE "(from|import) (flashsim|flashattack|flashleak|flashmap|flasharb)" \
    flashwhisperer/$pkg/*.py | awk '{print $2}' | sort -u | tr '\n' ' '
  echo
done
```

The rule that keeps it true: **a package here may not import `serial` or
`hardware.hil`.** That is why the board-driving scripts went to `rigs/host/`
rather than into `flashattack` — see [`../../REORG_PLAN.md`](../../REORG_PLAN.md),
*What was deliberately refused* — and why a campaign that drives hardware can
contribute a reusable core to the toolkit but never move into it wholesale.

## What a split still has to deal with

* **`conftest.py` lives at the repository root** and registers `--runslow`,
  which `demo/oscore/` also needs; registering it in two conftests is an error
  its own docstring warns about, which is why it was not moved. A standalone
  package needs its own copy and the demo keeps the root one.
* **The shims stay behind.** `hardware/atk_lastround.py`,
  `hardware/aes_ref.py`, `hardware/refaes.py`, `hardware/line_offset.py` and
  `demo/oscore/oracle.py` exist only to keep this repository's callers working
  after their implementations moved into the package. They are not part of the
  toolkit and should not travel with it.
* **[`../../pyproject.toml`](../../pyproject.toml) is named `flashattack`**
  while the directory and the five packages are `flashwhisperer`. It also
  points `package-dir` at `flashwhisperer`, so a standalone release has to pick
  one name and keep the console script (`flashattack = flashattack.cli:main`)
  or deprecate it deliberately.
* **The test vectors are tracked and small on purpose** (`tests/vectors/*.npz`
  store timing only, with seed-regenerated material), so they travel. The
  captures the campaigns replay do not: they are untracked, recorded in
  `results/MANIFEST.tsv`, and a split loses the long-run replays unless those
  vectors come too.
* **Documentation that points outward.** The package docstrings cite campaign
  results under `results/` for their measured claims, which is correct here and
  dangling in a standalone clone. Decide per link whether to inline the number
  or drop the citation; do not leave a path that resolves on one machine only.

## What this document does not cover

Whether the split is worth doing, and what the package would be called. Both
are decisions, not measurements, and nothing here settles them.
