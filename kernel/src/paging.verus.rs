use verus_builtin::*;
use verus_builtin_macros::*;
use vstd::prelude::*;

verus! {

const PAGE_SIZE: u64 = 4096;
const PAGE_OFFSET_MASK: u64 = PAGE_SIZE - 1;
const ENTRIES: u64 = 512;
const ENTRY_MASK: u64 = 0x1ff;
const HUGE_PAGE_SIZE: u64 = 0x20_0000;
const HUGE_PAGE_OFFSET_MASK: u64 = HUGE_PAGE_SIZE - 1;

#[verifier::bit_vector]
proof fn lemma_page_table_index_bounds(virt: u64)
    ensures
        ((virt >> 39) & ENTRY_MASK) < ENTRIES,
        ((virt >> 30) & ENTRY_MASK) < ENTRIES,
        ((virt >> 21) & ENTRY_MASK) < ENTRIES,
        ((virt >> 12) & ENTRY_MASK) < ENTRIES,
{
}

#[verifier::bit_vector]
proof fn lemma_align_down_2m(phys: u64)
    ensures
        (phys & !HUGE_PAGE_OFFSET_MASK) <= phys,
        ((phys & !HUGE_PAGE_OFFSET_MASK) & HUGE_PAGE_OFFSET_MASK) == 0,
        phys - (phys & !HUGE_PAGE_OFFSET_MASK) <= HUGE_PAGE_OFFSET_MASK,
{
}

#[verifier::bit_vector]
proof fn lemma_huge_page_offset_range(virt: u64)
    ensures
        (virt & HUGE_PAGE_OFFSET_MASK) < HUGE_PAGE_SIZE,
{
}

#[verifier::bit_vector]
proof fn lemma_page_offset_range(virt: u64)
    ensures
        (virt & PAGE_OFFSET_MASK) < PAGE_SIZE,
{
}

} // verus!

#[verifier::external_body]
fn main() {}
