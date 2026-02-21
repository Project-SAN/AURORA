ENTRY(_start)

SECTIONS
{
  . = 0x400000;
  /* 16M heap is required by the router binary to accommodate routing tables,
   * replay caches, policy metadata, and concurrent socket state. The previous
   * 1M limit caused out-of-memory panics under realistic traffic. On
   * resource-constrained targets (e.g. embedded boards with limited RAM)
   * reduce this value and rebuild; the router will OOM-panic early if the
   * chosen size is insufficient rather than silently misbehave. */
  HEAP_SIZE = 16M;

  .text : ALIGN(4K)
  {
    *(.text .text.*)
  }

  .rodata : ALIGN(4K)
  {
    *(.rodata .rodata.*)
  }

  .data : ALIGN(4K)
  {
    *(.data .data.*)
  }

  .bss : ALIGN(4K)
  {
    *(.bss .bss.* COMMON)
  }

  .heap : ALIGN(16)
  {
    _heap_start = .;
    . = . + HEAP_SIZE;
    _heap_end = .;
  }
}
