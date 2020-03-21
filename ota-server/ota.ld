/* This linker script generated from xt-genldscripts.tpp for LSP . */
/* Linker Script for ld -N */
MEMORY
{
  dport0_0_seg :                        org = 0x3FF00000, len = 0x10
  dram0_0_seg :                         org = 0x3FFE8000, len = 0x14000
  iram1_0_seg :                         org = 0x40100000, len = 0x8000
  irom0_0_seg :                         org = 0x40208000 + 0x1000, len = 0x33000
}

INCLUDE ota_common.ld
