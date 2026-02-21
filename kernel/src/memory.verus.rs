use verus_builtin::*;
use verus_builtin_macros::*;
use vstd::prelude::*;

verus! {

const PAGE_SIZE: u64 = 4096;
const PAGE_OFFSET_MASK: u64 = PAGE_SIZE - 1;
const MIN_USABLE_ADDR: u64 = PAGE_SIZE;
const MAX_PHYS_ADDR: u64 = 0x1_0000_0000;
const DMA_LIMIT: u64 = 0x1000_0000 - 1;

spec fn disjoint(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_end <= b_start || b_end <= a_start
}

spec fn contained_in(outer_start: u64, outer_end: u64, inner_start: u64, inner_end: u64) -> bool {
    outer_start <= inner_start && inner_end <= outer_end
}

spec fn in_range(x: u64, start: u64, end: u64) -> bool {
    start <= x && x < end
}

spec fn alloc_size(pages: u64) -> u64 {
    (pages * PAGE_SIZE) as u64
}

spec fn alloc_candidate_start(region_start: u64, min: u64) -> u64 {
    (((((if region_start >= min { region_start } else { min }) + PAGE_SIZE - 1) as u64) & !PAGE_OFFSET_MASK) as u64)
}

spec fn alloc_candidate_alloc_end(region_start: u64, min: u64, pages: u64) -> u64 {
    (alloc_candidate_start(region_start, min) + alloc_size(pages)) as u64
}

spec fn alloc_candidate_end(region_end: u64, max: u64) -> u64 {
    if region_end <= max + 1 { region_end } else { (max + 1) as u64 }
}

spec fn step_merge_end(current_end: u64, next_end: u64) -> u64 {
    if current_end >= next_end { current_end } else { next_end }
}

spec fn split_result(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
) -> Seq<(u64, u64)> {
    if alloc_start == region_start && alloc_end == region_end {
        seq![]
    } else if alloc_start == region_start {
        seq![(alloc_end, region_end)]
    } else if alloc_end == region_end {
        seq![(region_start, alloc_start)]
    } else {
        seq![(region_start, alloc_start), (alloc_end, region_end)]
    }
}

spec fn alloc_idx_update_result(
    regions: Seq<(u64, u64)>,
    idx: int,
    alloc_start: u64,
    alloc_end: u64,
) -> Seq<(u64, u64)> {
    regions.subrange(0, idx)
        + split_result(regions[idx].0, regions[idx].1, alloc_start, alloc_end)
        + regions.subrange(idx + 1, regions.len() as int)
}

spec fn coalesce_step_result(
    current_start: u64,
    current_end: u64,
    next_start: u64,
    next_end: u64,
) -> Seq<(u64, u64)> {
    if next_start <= current_end {
        seq![(current_start, step_merge_end(current_end, next_end))]
    } else {
        seq![(current_start, current_end), (next_start, next_end)]
    }
}

spec fn in_regions(x: u64, regions: Seq<(u64, u64)>) -> bool
    decreases regions.len()
{
    if regions.len() == 0 {
        false
    } else {
        in_range(x, regions[0].0, regions[0].1) || in_regions(x, regions.drop_first())
    }
}

spec fn regions_strictly_sorted_disjoint(regions: Seq<(u64, u64)>) -> bool {
    forall|i: int, j: int|
        #![auto]
        0 <= i < j < regions.len() ==> regions[i].1 < regions[j].0
}

spec fn regions_non_empty(regions: Seq<(u64, u64)>) -> bool {
    forall|i: int|
        #![auto]
        0 <= i < regions.len() ==> regions[i].0 < regions[i].1
}

spec fn free_list_inv(regions: Seq<(u64, u64)>) -> bool {
    regions_non_empty(regions) && regions_strictly_sorted_disjoint(regions)
}

spec fn regions_bounded(regions: Seq<(u64, u64)>) -> bool {
    forall|i: int|
        #![auto]
        0 <= i < regions.len() ==> regions[i].1 <= MAX_PHYS_ADDR
}

spec fn region_fits(
    regions: Seq<(u64, u64)>,
    idx: int,
    min: u64,
    max: u64,
    pages: u64,
) -> bool {
    0 <= idx < regions.len()
        && alloc_candidate_alloc_end(regions[idx].0, min, pages)
            <= alloc_candidate_end(regions[idx].1, max)
}

spec fn first_fit_idx_from(
    regions: Seq<(u64, u64)>,
    start: int,
    min: u64,
    max: u64,
    pages: u64,
) -> Option<int>
    decreases regions.len() - start
{
    if start >= regions.len() {
        Option::None
    } else if region_fits(regions, start, min, max, pages) {
        Option::Some(start)
    } else {
        first_fit_idx_from(regions, start + 1, min, max, pages)
    }
}

spec fn fit_update_ready(
    regions: Seq<(u64, u64)>,
    min: u64,
    max: u64,
    pages: u64,
) -> bool {
    forall|i: int|
        #![auto]
        0 <= i < regions.len() && region_fits(regions, i, min, max, pages)
            ==> (
                regions[i].1 <= MAX_PHYS_ADDR
                && regions[i].0 <= alloc_candidate_start(regions[i].0, min)
                && alloc_candidate_start(regions[i].0, min) < alloc_candidate_alloc_end(regions[i].0, min, pages)
                && alloc_candidate_alloc_end(regions[i].0, min, pages) <= regions[i].1
            )
}

proof fn lemma_in_regions_singleton(x: u64, start: u64, end: u64)
    ensures
        in_regions(x, seq![(start, end)]) <==> in_range(x, start, end),
{
    reveal_with_fuel(in_regions, 2);
}

proof fn lemma_in_regions_pair(x: u64, start1: u64, end1: u64, start2: u64, end2: u64)
    ensures
        in_regions(x, seq![(start1, end1), (start2, end2)])
            <==> (in_range(x, start1, end1) || in_range(x, start2, end2)),
{
    reveal_with_fuel(in_regions, 3);
}

proof fn lemma_in_regions_concat(x: u64, left: Seq<(u64, u64)>, right: Seq<(u64, u64)>)
    ensures
        in_regions(x, left + right) <==> (in_regions(x, left) || in_regions(x, right)),
    decreases left.len(),
{
    if left.len() == 0 {
        reveal_with_fuel(in_regions, 1);
        assert(left + right == right);
    } else {
        reveal_with_fuel(in_regions, 1);
        assert((left + right)[0] == left[0]);
        assert((left + right).drop_first() == left.drop_first() + right);
        lemma_in_regions_concat(x, left.drop_first(), right);
    }
}

proof fn lemma_first_fit_idx_from_some(
    regions: Seq<(u64, u64)>,
    start: int,
    min: u64,
    max: u64,
    pages: u64,
    idx: int,
)
    requires
        0 <= start <= regions.len(),
        first_fit_idx_from(regions, start, min, max, pages) == Option::Some(idx),
    ensures
        start <= idx < regions.len(),
        region_fits(regions, idx, min, max, pages),
        forall|j: int| start <= j < idx ==> !region_fits(regions, j, min, max, pages),
    decreases regions.len() - start,
{
    if start >= regions.len() {
        assert(first_fit_idx_from(regions, start, min, max, pages) == Option::<int>::None);
    } else if region_fits(regions, start, min, max, pages) {
        assert(first_fit_idx_from(regions, start, min, max, pages) == Option::Some(start));
        assert(idx == start);
        assert forall|j: int| start <= j < idx implies !region_fits(regions, j, min, max, pages) by {};
    } else {
        assert(first_fit_idx_from(regions, start, min, max, pages)
            == first_fit_idx_from(regions, start + 1, min, max, pages));
        lemma_first_fit_idx_from_some(regions, start + 1, min, max, pages, idx);
        assert forall|j: int| start <= j < idx implies !region_fits(regions, j, min, max, pages) by {
            if start <= j < idx {
                if j == start {
                    assert(!region_fits(regions, start, min, max, pages));
                } else {
                    assert(start + 1 <= j < idx);
                }
            }
        };
    }
}

proof fn lemma_first_fit_idx_from_none(
    regions: Seq<(u64, u64)>,
    start: int,
    min: u64,
    max: u64,
    pages: u64,
)
    requires
        0 <= start <= regions.len(),
        first_fit_idx_from(regions, start, min, max, pages) == Option::<int>::None,
    ensures
        forall|j: int| start <= j < regions.len() ==> !region_fits(regions, j, min, max, pages),
    decreases regions.len() - start,
{
    if start >= regions.len() {
    } else if region_fits(regions, start, min, max, pages) {
        assert(first_fit_idx_from(regions, start, min, max, pages) == Option::Some(start));
    } else {
        assert(first_fit_idx_from(regions, start, min, max, pages)
            == first_fit_idx_from(regions, start + 1, min, max, pages));
        lemma_first_fit_idx_from_none(regions, start + 1, min, max, pages);
        assert forall|j: int| start <= j < regions.len() implies !region_fits(regions, j, min, max, pages) by {
            if start <= j < regions.len() {
                if j == start {
                    assert(!region_fits(regions, start, min, max, pages));
                } else {
                    assert(start + 1 <= j < regions.len());
                }
            }
        };
    }
}

#[verifier::bit_vector]
proof fn lemma_align_up_page(addr: u64)
    requires
        addr <= MAX_PHYS_ADDR,
    ensures
        addr <= ((((addr + PAGE_SIZE - 1) as u64) & !PAGE_OFFSET_MASK) as int),
        ((((addr + PAGE_SIZE - 1) as u64) & !PAGE_OFFSET_MASK) & PAGE_OFFSET_MASK) == 0,
        ((((addr + PAGE_SIZE - 1) as u64) & !PAGE_OFFSET_MASK) as int) <= addr + PAGE_OFFSET_MASK,
{
}

#[verifier::bit_vector]
proof fn lemma_saturating_guard_implies_bounded_sum(start: u64, size: u64, bound: u64)
    requires
        bound < u64::MAX,
        start.saturating_add(size) <= bound,
    ensures
        start + size <= bound,
        start <= start + size,
{
}

#[verifier::bit_vector]
proof fn lemma_positive_pages_implies_positive_size(pages: u64)
    requires
        pages > 0,
        pages <= u64::MAX / PAGE_SIZE,
    ensures
        alloc_size(pages) > 0,
{
}

proof fn lemma_allocation_window_is_sound(
    region_start: u64,
    region_end: u64,
    min: u64,
    max: u64,
    pages: u64,
    usable_start: u64,
    usable_end: u64,
)
    requires
        region_start < region_end,
        min <= max,
        region_end <= MAX_PHYS_ADDR,
        max < MAX_PHYS_ADDR,
        pages > 0,
        pages <= u64::MAX / PAGE_SIZE,
        usable_start == (((((if region_start >= min { region_start } else { min }) + PAGE_SIZE - 1) as u64) & !PAGE_OFFSET_MASK) as u64),
        usable_end == if region_end <= max + 1 { region_end } else { (max + 1) as u64 },
        usable_start + pages * PAGE_SIZE <= usable_end,
    ensures
        usable_start >= region_start,
        usable_start >= min,
        (usable_start & PAGE_OFFSET_MASK) == 0,
        usable_start + pages * PAGE_SIZE <= region_end,
        usable_start + pages * PAGE_SIZE <= max + 1,
{
    if region_start >= min {
        lemma_align_up_page(region_start);
    } else {
        lemma_align_up_page(min);
    }

    if region_end <= max + 1 {
        assert(usable_end == region_end);
    } else {
        assert(usable_end == max + 1);
    }
}

proof fn lemma_split_case_partition_is_exhaustive(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        region_start <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= region_end,
    ensures
        (alloc_start == region_start && alloc_end == region_end)
        || (alloc_start == region_start && alloc_end < region_end)
        || (alloc_start > region_start && alloc_end == region_end)
        || (alloc_start > region_start && alloc_end < region_end),
{
    if alloc_start == region_start {
        if alloc_end == region_end {
        } else {
            assert(alloc_end < region_end);
        }
    } else {
        assert(alloc_start > region_start);
        if alloc_end == region_end {
        } else {
            assert(alloc_end < region_end);
        }
    }
}

proof fn lemma_split_prefix_case_sound(
    region_start: u64,
    region_end: u64,
    alloc_end: u64,
)
    requires
        region_start < alloc_end,
        alloc_end < region_end,
    ensures
        contained_in(region_start, region_end, alloc_end, region_end),
        disjoint(alloc_end, region_end, region_start, alloc_end),
{
}

proof fn lemma_split_prefix_case_semantics(
    region_start: u64,
    region_end: u64,
    alloc_end: u64,
    x: u64,
)
    requires
        region_start < alloc_end,
        alloc_end < region_end,
    ensures
        in_range(x, alloc_end, region_end) <==> (in_range(x, region_start, region_end) && !in_range(x, region_start, alloc_end)),
{
}

proof fn lemma_split_suffix_case_sound(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
)
    requires
        region_start < alloc_start,
        alloc_start < region_end,
    ensures
        contained_in(region_start, region_end, region_start, alloc_start),
        disjoint(region_start, alloc_start, alloc_start, region_end),
{
}

proof fn lemma_split_suffix_case_semantics(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    x: u64,
)
    requires
        region_start < alloc_start,
        alloc_start < region_end,
    ensures
        in_range(x, region_start, alloc_start) <==> (in_range(x, region_start, region_end) && !in_range(x, alloc_start, region_end)),
{
}

proof fn lemma_split_middle_case_sound(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        region_start < alloc_start,
        alloc_start < alloc_end,
        alloc_end < region_end,
    ensures
        contained_in(region_start, region_end, region_start, alloc_start),
        contained_in(region_start, region_end, alloc_end, region_end),
        disjoint(region_start, alloc_start, alloc_start, alloc_end),
        disjoint(alloc_end, region_end, alloc_start, alloc_end),
        disjoint(region_start, alloc_start, alloc_end, region_end),
{
}

proof fn lemma_split_middle_case_semantics(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
    x: u64,
)
    requires
        region_start < alloc_start,
        alloc_start < alloc_end,
        alloc_end < region_end,
    ensures
        (in_range(x, region_start, alloc_start) || in_range(x, alloc_end, region_end))
            <==> (in_range(x, region_start, region_end) && !in_range(x, alloc_start, alloc_end)),
{
}

proof fn lemma_split_cases_keep_disjointness(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        region_start <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= region_end,
    ensures
        disjoint(region_start, alloc_start, alloc_start, alloc_end),
        disjoint(alloc_end, region_end, alloc_start, alloc_end),
{
}

proof fn lemma_split_result_wf(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        region_start <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= region_end,
    ensures
        split_result(region_start, region_end, alloc_start, alloc_end).len() <= 2,
        regions_non_empty(split_result(region_start, region_end, alloc_start, alloc_end)),
        regions_strictly_sorted_disjoint(split_result(region_start, region_end, alloc_start, alloc_end)),
{
    lemma_split_case_partition_is_exhaustive(region_start, region_end, alloc_start, alloc_end);
    if alloc_start == region_start && alloc_end == region_end {
    } else if alloc_start == region_start {
        assert(alloc_end < region_end);
    } else if alloc_end == region_end {
        assert(region_start < alloc_start);
    } else {
        assert(region_start < alloc_start);
        assert(alloc_end < region_end);
    }
}

proof fn lemma_split_result_bounds(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        region_start <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= region_end,
    ensures
        forall|k: int|
            0 <= k < split_result(region_start, region_end, alloc_start, alloc_end).len()
                ==> region_start <= split_result(region_start, region_end, alloc_start, alloc_end)[k].0
                    && split_result(region_start, region_end, alloc_start, alloc_end)[k].1 <= region_end,
{
}

proof fn lemma_sorted_disjoint_pair_from_invariant(regions: Seq<(u64, u64)>, i: int, j: int)
    requires
        regions_strictly_sorted_disjoint(regions),
        0 <= i < j < regions.len(),
    ensures
        regions[i].1 < regions[j].0,
{
}

proof fn lemma_subrange_preserves_sorted_disjoint(regions: Seq<(u64, u64)>, lo: int, hi: int)
    requires
        regions_strictly_sorted_disjoint(regions),
        0 <= lo <= hi <= regions.len(),
    ensures
        regions_strictly_sorted_disjoint(regions.subrange(lo, hi)),
{
    assert forall|i: int, j: int|
        0 <= i < j < regions.subrange(lo, hi).len()
            implies regions.subrange(lo, hi)[i].1 < regions.subrange(lo, hi)[j].0
    by {
        assert(lo + i < lo + j);
        assert(lo + j < hi);
        assert(regions.subrange(lo, hi)[i] == regions[lo + i]);
        assert(regions.subrange(lo, hi)[j] == regions[lo + j]);
        lemma_sorted_disjoint_pair_from_invariant(regions, lo + i, lo + j);
    };
}

proof fn lemma_subrange_preserves_non_empty(regions: Seq<(u64, u64)>, lo: int, hi: int)
    requires
        regions_non_empty(regions),
        0 <= lo <= hi <= regions.len(),
    ensures
        regions_non_empty(regions.subrange(lo, hi)),
{
    assert forall|i: int|
        0 <= i < regions.subrange(lo, hi).len()
            implies regions.subrange(lo, hi)[i].0 < regions.subrange(lo, hi)[i].1
    by {
        assert(regions.subrange(lo, hi)[i] == regions[lo + i]);
    };
}

proof fn lemma_concat_preserves_sorted_disjoint(left: Seq<(u64, u64)>, right: Seq<(u64, u64)>)
    requires
        regions_strictly_sorted_disjoint(left),
        regions_strictly_sorted_disjoint(right),
        forall|i: int, j: int| 0 <= i < left.len() && 0 <= j < right.len() ==> left[i].1 < right[j].0,
    ensures
        regions_strictly_sorted_disjoint(left + right),
{
    let both = left + right;
    assert forall|i: int, j: int|
        0 <= i < j < both.len()
            implies both[i].1 < both[j].0
    by {
        if j < left.len() {
            assert(i < left.len());
            assert(both[i] == left[i]);
            assert(both[j] == left[j]);
        } else if i < left.len() {
            let rj = j - left.len();
            assert(0 <= rj < right.len());
            assert(both[i] == left[i]);
            assert(both[j] == right[rj]);
        } else {
            let ri = i - left.len();
            let rj = j - left.len();
            assert(0 <= ri < rj < right.len());
            assert(both[i] == right[ri]);
            assert(both[j] == right[rj]);
        }
    };
}

proof fn lemma_concat_preserves_non_empty(left: Seq<(u64, u64)>, right: Seq<(u64, u64)>)
    requires
        regions_non_empty(left),
        regions_non_empty(right),
    ensures
        regions_non_empty(left + right),
{
    let both = left + right;
    assert forall|i: int|
        0 <= i < both.len()
            implies both[i].0 < both[i].1
    by {
        if i < left.len() {
            assert(both[i] == left[i]);
        } else {
            let ri = i - left.len();
            assert(0 <= ri < right.len());
            assert(both[i] == right[ri]);
        }
    };
}

proof fn lemma_split_result_semantics(
    region_start: u64,
    region_end: u64,
    alloc_start: u64,
    alloc_end: u64,
    x: u64,
)
    requires
        region_start <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= region_end,
    ensures
        in_regions(x, split_result(region_start, region_end, alloc_start, alloc_end))
            <==> (in_range(x, region_start, region_end) && !in_range(x, alloc_start, alloc_end)),
{
    lemma_split_case_partition_is_exhaustive(region_start, region_end, alloc_start, alloc_end);
    if alloc_start == region_start && alloc_end == region_end {
        reveal_with_fuel(in_regions, 1);
    } else if alloc_start == region_start {
        assert(alloc_end < region_end);
        lemma_in_regions_singleton(x, alloc_end, region_end);
        lemma_split_prefix_case_semantics(region_start, region_end, alloc_end, x);
    } else if alloc_end == region_end {
        assert(region_start < alloc_start);
        lemma_in_regions_singleton(x, region_start, alloc_start);
        lemma_split_suffix_case_semantics(region_start, region_end, alloc_start, x);
    } else {
        assert(region_start < alloc_start);
        assert(alloc_end < region_end);
        lemma_in_regions_pair(x, region_start, alloc_start, alloc_end, region_end);
        lemma_split_middle_case_semantics(region_start, region_end, alloc_start, alloc_end, x);
    }
}

proof fn lemma_alloc_idx_update_preserves_sorted_disjoint(
    regions: Seq<(u64, u64)>,
    idx: int,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        regions_strictly_sorted_disjoint(regions),
        0 <= idx < regions.len(),
        regions[idx].0 <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= regions[idx].1,
    ensures
        regions_strictly_sorted_disjoint(alloc_idx_update_result(regions, idx, alloc_start, alloc_end)),
{
    let prefix = regions.subrange(0, idx);
    let middle = split_result(regions[idx].0, regions[idx].1, alloc_start, alloc_end);
    let suffix = regions.subrange(idx + 1, regions.len() as int);

    lemma_subrange_preserves_sorted_disjoint(regions, 0, idx);
    lemma_split_result_wf(regions[idx].0, regions[idx].1, alloc_start, alloc_end);
    lemma_subrange_preserves_sorted_disjoint(regions, idx + 1, regions.len() as int);
    lemma_split_result_bounds(regions[idx].0, regions[idx].1, alloc_start, alloc_end);

    assert forall|i: int, j: int|
        0 <= i < prefix.len() && 0 <= j < middle.len()
            implies prefix[i].1 < middle[j].0
    by {
        assert(prefix[i] == regions[i]);
        lemma_sorted_disjoint_pair_from_invariant(regions, i, idx);
        assert(regions[idx].0 <= middle[j].0) by {
            assert(0 <= j < split_result(regions[idx].0, regions[idx].1, alloc_start, alloc_end).len());
        };
    };

    lemma_concat_preserves_sorted_disjoint(prefix, middle);
    let pm = prefix + middle;

    assert forall|i: int, j: int|
        0 <= i < pm.len() && 0 <= j < suffix.len()
            implies pm[i].1 < suffix[j].0
    by {
        if i < prefix.len() {
            assert(pm[i] == prefix[i]);
            assert(prefix[i] == regions[i]);
            assert(suffix[j] == regions[idx + 1 + j]);
            lemma_sorted_disjoint_pair_from_invariant(regions, i, idx + 1 + j);
        } else {
            let k = i - prefix.len();
            assert(0 <= k < middle.len());
            assert(pm[i] == middle[k]);
            assert(suffix[j] == regions[idx + 1 + j]);
            assert(middle[k].1 <= regions[idx].1) by {
                assert(0 <= k < split_result(regions[idx].0, regions[idx].1, alloc_start, alloc_end).len());
            };
            lemma_sorted_disjoint_pair_from_invariant(regions, idx, idx + 1 + j);
        }
    };

    lemma_concat_preserves_sorted_disjoint(pm, suffix);
    assert(pm + suffix == alloc_idx_update_result(regions, idx, alloc_start, alloc_end));
}

proof fn lemma_alloc_idx_update_preserves_non_empty(
    regions: Seq<(u64, u64)>,
    idx: int,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        regions_non_empty(regions),
        0 <= idx < regions.len(),
        regions[idx].0 <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= regions[idx].1,
    ensures
        regions_non_empty(alloc_idx_update_result(regions, idx, alloc_start, alloc_end)),
{
    let prefix = regions.subrange(0, idx);
    let middle = split_result(regions[idx].0, regions[idx].1, alloc_start, alloc_end);
    let suffix = regions.subrange(idx + 1, regions.len() as int);

    lemma_subrange_preserves_non_empty(regions, 0, idx);
    lemma_split_result_wf(regions[idx].0, regions[idx].1, alloc_start, alloc_end);
    lemma_subrange_preserves_non_empty(regions, idx + 1, regions.len() as int);

    lemma_concat_preserves_non_empty(prefix, middle);
    let pm = prefix + middle;
    lemma_concat_preserves_non_empty(pm, suffix);
    assert(pm + suffix == alloc_idx_update_result(regions, idx, alloc_start, alloc_end));
}

proof fn lemma_alloc_idx_update_preserves_free_list_inv(
    regions: Seq<(u64, u64)>,
    idx: int,
    alloc_start: u64,
    alloc_end: u64,
)
    requires
        free_list_inv(regions),
        0 <= idx < regions.len(),
        regions[idx].0 <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= regions[idx].1,
    ensures
        free_list_inv(alloc_idx_update_result(regions, idx, alloc_start, alloc_end)),
{
    lemma_alloc_idx_update_preserves_sorted_disjoint(regions, idx, alloc_start, alloc_end);
    lemma_alloc_idx_update_preserves_non_empty(regions, idx, alloc_start, alloc_end);
}

proof fn lemma_alloc_idx_update_semantics_partition(
    regions: Seq<(u64, u64)>,
    idx: int,
    alloc_start: u64,
    alloc_end: u64,
    x: u64,
)
    requires
        0 <= idx < regions.len(),
        regions[idx].0 <= alloc_start,
        alloc_start < alloc_end,
        alloc_end <= regions[idx].1,
    ensures
        in_regions(x, alloc_idx_update_result(regions, idx, alloc_start, alloc_end))
            <==> (
                in_regions(x, regions.subrange(0, idx))
                || in_regions(x, regions.subrange(idx + 1, regions.len() as int))
                || (in_range(x, regions[idx].0, regions[idx].1) && !in_range(x, alloc_start, alloc_end))
            ),
{
    let prefix = regions.subrange(0, idx);
    let middle = split_result(regions[idx].0, regions[idx].1, alloc_start, alloc_end);
    let suffix = regions.subrange(idx + 1, regions.len() as int);
    let pm = prefix + middle;

    lemma_in_regions_concat(x, middle, suffix);
    lemma_in_regions_concat(x, pm, suffix);
    lemma_split_result_semantics(regions[idx].0, regions[idx].1, alloc_start, alloc_end, x);

    assert(pm + suffix == alloc_idx_update_result(regions, idx, alloc_start, alloc_end));
    assert(in_regions(x, alloc_idx_update_result(regions, idx, alloc_start, alloc_end))
        <==> in_regions(x, pm + suffix));
    lemma_in_regions_concat(x, prefix, middle);
    assert(in_regions(x, pm) <==> (in_regions(x, prefix) || in_regions(x, middle)));
    assert(in_regions(x, pm + suffix)
        <==> (in_regions(x, pm) || in_regions(x, suffix)));
    assert(in_regions(x, middle + suffix) <==> (in_regions(x, middle) || in_regions(x, suffix)));
    assert(in_regions(x, middle)
        <==> (in_range(x, regions[idx].0, regions[idx].1) && !in_range(x, alloc_start, alloc_end)));
}

proof fn lemma_alloc_contiguous_range_idx_update_spec(
    regions: Seq<(u64, u64)>,
    idx: int,
    min: u64,
    max: u64,
    pages: u64,
    x: u64,
)
    requires
        free_list_inv(regions),
        0 <= idx < regions.len(),
        regions[idx].1 <= MAX_PHYS_ADDR,
        min <= max,
        max < MAX_PHYS_ADDR,
        pages > 0,
        pages <= u64::MAX / PAGE_SIZE,
        alloc_candidate_alloc_end(regions[idx].0, min, pages)
            <= alloc_candidate_end(regions[idx].1, max),
        regions[idx].0 <= alloc_candidate_start(regions[idx].0, min),
        alloc_candidate_start(regions[idx].0, min)
            < alloc_candidate_alloc_end(regions[idx].0, min, pages),
        alloc_candidate_alloc_end(regions[idx].0, min, pages) <= regions[idx].1,
    ensures
        free_list_inv(
            alloc_idx_update_result(
                regions,
                idx,
                alloc_candidate_start(regions[idx].0, min),
                alloc_candidate_alloc_end(regions[idx].0, min, pages),
            ),
        ),
        in_regions(
            x,
            alloc_idx_update_result(
                regions,
                idx,
                alloc_candidate_start(regions[idx].0, min),
                alloc_candidate_alloc_end(regions[idx].0, min, pages),
            ),
        ) <==> (
            in_regions(x, regions.subrange(0, idx))
            || in_regions(x, regions.subrange(idx + 1, regions.len() as int))
            || (
                in_range(x, regions[idx].0, regions[idx].1)
                && !in_range(
                    x,
                    alloc_candidate_start(regions[idx].0, min),
                    alloc_candidate_alloc_end(regions[idx].0, min, pages),
                )
            )
        ),
{
    let region_start = regions[idx].0;
    let alloc_start = alloc_candidate_start(region_start, min);
    let alloc_end = alloc_candidate_alloc_end(region_start, min, pages);

    lemma_alloc_idx_update_preserves_free_list_inv(regions, idx, alloc_start, alloc_end);
    lemma_alloc_idx_update_semantics_partition(regions, idx, alloc_start, alloc_end, x);
}

proof fn lemma_in_regions_split_at_idx(
    regions: Seq<(u64, u64)>,
    idx: int,
    x: u64,
)
    requires
        0 <= idx < regions.len(),
    ensures
        in_regions(x, regions)
            <==> (
                in_regions(x, regions.subrange(0, idx))
                || in_range(x, regions[idx].0, regions[idx].1)
                || in_regions(x, regions.subrange(idx + 1, regions.len() as int))
            ),
{
    let prefix = regions.subrange(0, idx);
    let mid = seq![(regions[idx].0, regions[idx].1)];
    let suffix = regions.subrange(idx + 1, regions.len() as int);

    lemma_in_regions_singleton(x, regions[idx].0, regions[idx].1);
    lemma_in_regions_concat(x, mid, suffix);
    lemma_in_regions_concat(x, prefix, mid + suffix);
    assert(mid + suffix == regions.subrange(idx, regions.len() as int));
    assert(prefix + (mid + suffix) == regions);
}

proof fn lemma_alloc_contiguous_range_first_fit_complete(
    regions: Seq<(u64, u64)>,
    min: u64,
    max: u64,
    pages: u64,
    x: u64,
)
    requires
        free_list_inv(regions),
        regions_bounded(regions),
        fit_update_ready(regions, min, max, pages),
        min <= max,
        max < MAX_PHYS_ADDR,
        pages > 0,
        pages <= u64::MAX / PAGE_SIZE,
    ensures
        match first_fit_idx_from(regions, 0, min, max, pages) {
            Option::None => forall|j: int| 0 <= j < regions.len() ==> !region_fits(regions, j, min, max, pages),
            Option::Some(idx) => (
                0 <= idx < regions.len()
                && region_fits(regions, idx, min, max, pages)
                && forall|j: int| 0 <= j < idx ==> !region_fits(regions, j, min, max, pages)
                && free_list_inv(
                    alloc_idx_update_result(
                        regions,
                        idx,
                        alloc_candidate_start(regions[idx].0, min),
                        alloc_candidate_alloc_end(regions[idx].0, min, pages),
                    ),
                )
                && (
                    in_regions(
                        x,
                        alloc_idx_update_result(
                            regions,
                            idx,
                            alloc_candidate_start(regions[idx].0, min),
                            alloc_candidate_alloc_end(regions[idx].0, min, pages),
                        ),
                    ) <==> (
                        in_regions(x, regions.subrange(0, idx))
                        || in_regions(x, regions.subrange(idx + 1, regions.len() as int))
                        || (
                            in_range(x, regions[idx].0, regions[idx].1)
                            && !in_range(
                                x,
                                alloc_candidate_start(regions[idx].0, min),
                                alloc_candidate_alloc_end(regions[idx].0, min, pages),
                            )
                        )
                    )
                )
            ),
        },
{
    let ff = first_fit_idx_from(regions, 0, min, max, pages);
    match ff {
        Option::None => {
            lemma_first_fit_idx_from_none(regions, 0, min, max, pages);
        }
        Option::Some(idx) => {
            lemma_first_fit_idx_from_some(regions, 0, min, max, pages, idx);
            assert(region_fits(regions, idx, min, max, pages));
            assert(fit_update_ready(regions, min, max, pages));
            assert(regions[idx].1 <= MAX_PHYS_ADDR);
            assert(regions[idx].0 <= alloc_candidate_start(regions[idx].0, min));
            assert(alloc_candidate_start(regions[idx].0, min)
                < alloc_candidate_alloc_end(regions[idx].0, min, pages));
            assert(alloc_candidate_alloc_end(regions[idx].0, min, pages) <= regions[idx].1);

            lemma_alloc_contiguous_range_idx_update_spec(
                regions,
                idx,
                min,
                max,
                pages,
                x,
            );
        }
    }
}

proof fn lemma_coalesce_step(
    current_start: u64,
    current_end: u64,
    next_start: u64,
    next_end: u64,
)
    requires
        current_start <= current_end,
        current_start <= next_start,
        next_start <= next_end,
    ensures
        (next_start <= current_end) ==> (
            current_start <= (if current_end >= next_end { current_end } else { next_end })
            && current_end <= (if current_end >= next_end { current_end } else { next_end })
            && next_end <= (if current_end >= next_end { current_end } else { next_end })
        ),
        (!(next_start <= current_end)) ==> disjoint(current_start, current_end, next_start, next_end),
{
    if next_start <= current_end {
        if current_end >= next_end {
            assert((if current_end >= next_end { current_end } else { next_end }) == current_end);
        } else {
            assert((if current_end >= next_end { current_end } else { next_end }) == next_end);
        }
    } else {
        assert(current_end < next_start);
    }
}

proof fn lemma_coalesce_step_semantics_merge(
    current_start: u64,
    current_end: u64,
    next_start: u64,
    next_end: u64,
    x: u64,
)
    requires
        current_start <= current_end,
        current_start <= next_start,
        next_start <= current_end,
        next_start <= next_end,
    ensures
        in_range(x, current_start, if current_end >= next_end { current_end } else { next_end })
            <==> (in_range(x, current_start, current_end) || in_range(x, next_start, next_end)),
{
}

proof fn lemma_coalesce_step_semantics_no_merge(
    current_start: u64,
    current_end: u64,
    next_start: u64,
    next_end: u64,
    x: u64,
)
    requires
        current_start <= current_end,
        current_start <= next_start,
        current_end < next_start,
        next_start <= next_end,
    ensures
        in_range(x, current_start, current_end) || in_range(x, next_start, next_end)
            <==> in_range(x, current_start, current_end) || in_range(x, next_start, next_end),
{
}

proof fn lemma_coalesce_step_result_wf(
    current_start: u64,
    current_end: u64,
    next_start: u64,
    next_end: u64,
)
    requires
        current_start < current_end,
        current_start <= next_start,
        next_start < next_end,
    ensures
        1 <= coalesce_step_result(current_start, current_end, next_start, next_end).len() <= 2,
        regions_non_empty(coalesce_step_result(current_start, current_end, next_start, next_end)),
        regions_strictly_sorted_disjoint(coalesce_step_result(current_start, current_end, next_start, next_end)),
{
    if next_start <= current_end {
        if current_end >= next_end {
            assert(step_merge_end(current_end, next_end) == current_end);
        } else {
            assert(step_merge_end(current_end, next_end) == next_end);
        }
    } else {
        assert(current_end < next_start);
    }
}

proof fn lemma_coalesce_step_result_semantics(
    current_start: u64,
    current_end: u64,
    next_start: u64,
    next_end: u64,
    x: u64,
)
    requires
        current_start <= current_end,
        current_start <= next_start,
        next_start <= next_end,
    ensures
        in_regions(x, coalesce_step_result(current_start, current_end, next_start, next_end))
            <==> (in_range(x, current_start, current_end) || in_range(x, next_start, next_end)),
{
    if next_start <= current_end {
        lemma_in_regions_singleton(x, current_start, step_merge_end(current_end, next_end));
        lemma_coalesce_step_semantics_merge(
            current_start,
            current_end,
            next_start,
            next_end,
            x,
        );
    } else {
        lemma_in_regions_pair(x, current_start, current_end, next_start, next_end);
    }
}

proof fn lemma_dma_and_normal_ranges_do_not_overlap()
    ensures
        MIN_USABLE_ADDR <= DMA_LIMIT + 1,
        DMA_LIMIT + 1 <= MAX_PHYS_ADDR - 1,
        disjoint(
            MIN_USABLE_ADDR,
            (DMA_LIMIT + 1) as u64,
            (DMA_LIMIT + 1) as u64,
            MAX_PHYS_ADDR,
        ),
{
}

} // verus!

#[verifier::external_body]
fn main() {}
