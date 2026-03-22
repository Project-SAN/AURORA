# salt-PRISM implementation plan

This document records the implementation sequence required to turn the current
PRISM prototype into a paper-faithful salt-PRISM backend.

## Current state

The repository already has:

- `no_std` field arithmetic over `Fp` / `Fp2`
- Montgomery and short-Weierstrass curve arithmetic
- torsion and Weil-pairing helpers
- protocol wiring for `salt-PRISM`
- placeholder `RandomIdealGivenNorm`, `Qlapoti`, `IdealToIsogeny`, and `Kani`
  paths that exercise the flow end-to-end

The repository does not yet have the algebra backend required by the paper.
The main gaps are structural, not cosmetic:

- `degree` and `norm` bookkeeping is still largely `u128`, but paper parameters
  require up to about 640 bits for `q(2^a-q)`
- quaternion coefficients are still `i64`
- ideal arithmetic is currently generator-and-norm bookkeeping, not a real
  lattice/order implementation
- `Qlapoti` is a factorization surrogate
- `IdealToIsogeny` is driven by bounded search / public hints, not by Deuring
  kernel extraction from quaternion ideals
- `Kani` currently proves consistency of a witness transcript, not the actual
  2-dimensional quotient isogeny used in the paper

## Phase 0: widen the numeric model

Before any paper-faithful backend work, replace the narrow bookkeeping types:

- use a fixed-width unsigned integer for ideal norms and challenge degrees
- add a signed wide integer for quaternion coefficients
- remove `u128` assumptions from protocol and algebra interfaces

This phase is mandatory. Without it, even Level I challenge degrees do not fit.

## Phase 1: real quaternion and ideal representation

Replace the current simplified ideal layer with:

- maximal order elements represented with wide signed coefficients
- left/right ideal arithmetic over explicit bases
- principal ideals and conjugation over the widened model
- stage decomposition data structures that represent actual ideal products, not
  hashed surrogates

## Phase 2: RandomIdealGivenNorm and Qlapoti

Implement the paper-facing ideal generation path:

- `RandomIdealGivenNorm(O0, N)` for `N = q(2^a-q)`
- `Qlapoti` decomposition into the principal / smooth-norm stages used by
  `IdealToIsogeny`
- deterministic stage replay from encoded witnesses so verification does not
  depend on hidden search choices

## Phase 3: IdealToIsogeny

Replace bounded search with actual kernel extraction:

- recover kernel data from the stage ideals
- evaluate the isogeny chain over the NIST parameter sets
- compute the codomain `E_sig` and the images of the fixed torsion basis
- expose the exact data needed by `GenIsogeny`

## Phase 4: Kani / product isogeny

Replace transcript-only consistency checks with the actual quotient:

- construct the 2-dimensional kernel
- build the quotient `Phi : E_vk × E_sig -> E1 × E2`
- verify the expected Weil-pairing relation from the paper
- keep explicit witness encoding only as an implementation aid, not as the
  definition of correctness

## Phase 5: encoding and hardening

After the algebra backend is real:

- implement the paper’s signature encoding/compression choices
- run sign/verify tests for all published parameter sets
- benchmark and document remaining constant-time gaps

## Immediate next step

Start Phase 0:

1. introduce fixed-width wide integers for degree/norm bookkeeping
2. refactor challenge-degree derivation to stop truncating to `u128`
3. then widen quaternion coefficients before touching `RandomIdealGivenNorm`
