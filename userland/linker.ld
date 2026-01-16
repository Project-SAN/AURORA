ENTRY(_start)

SECTIONS
{
  . = 0x400000;
  HEAP_SIZE = 8M;

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
