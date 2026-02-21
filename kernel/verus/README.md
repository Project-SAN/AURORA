# Verus verification setup for AURORA kernel

This directory contains the runner/docs for Verus proofs colocated with kernel sources.

## 1) Install Verus

Use one of the official methods from `verus-lang/verus`:

### Option A: prebuilt release binary

1. Download the latest release archive from:
   - <https://github.com/verus-lang/verus/releases>
2. Extract it and set `VERUS_BIN` to the `verus` executable path.

Example:

```bash
export VERUS_BIN="$HOME/tools/verus-x86-linux/verus"
```

### Option B: build from source

Follow the current upstream build guide:
- <https://github.com/verus-lang/verus/blob/main/BUILD.md>

## 2) Run verification

From repository root:

```bash
./kernel/verus/run-verus.sh
```

## 3) Current proof scope

- `kernel/src/paging.verus.rs`
  - page-table index bounds (`< 512`) for all levels
  - 2MiB align-down invariants with bit masks
  - page/huge-page offset range checks
- `kernel/src/memory.verus.rs`
  - `align_up` page-alignment and upper-bound properties
  - allocation window soundness used by `alloc_contiguous_range`
  - split/coalesce step invariants for non-overlap and merge safety

## 4) Next files to migrate

- `kernel/src/user/elf.rs`: parser bounds and segment range validity
