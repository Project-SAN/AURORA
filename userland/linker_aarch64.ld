ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x40000000;
  .text : ALIGN(64K)
  {
    *(.text .text.*)
  } :text

  .rodata : ALIGN(64K)
  {
    *(.rodata .rodata.*)
    *(.eh_frame_hdr)
    *(.eh_frame)
  } :rodata

  . = 0x41000000;
  /* AArch64 full-policy guest mode needs substantially more heap than the
   * early route-only bring-up. Keep this below the reserved stack window at
   * 0x41c00000 while leaving room for .data/.bss growth. */
  HEAP_SIZE = 10M;

  .data : ALIGN(64K)
  {
    *(.data .data.*)
    *(.got .got.*)
  } :data

  .bss : ALIGN(64K)
  {
    *(.bss .bss.* COMMON)
  } :data

  .heap : ALIGN(64K)
  {
    _heap_start = .;
    . = . + HEAP_SIZE;
    _heap_end = .;
  } :data
}
