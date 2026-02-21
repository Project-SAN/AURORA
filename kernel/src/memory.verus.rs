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
