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
