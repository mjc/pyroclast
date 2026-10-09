.text
.globl _start
_start:
  nop
  ret
.Lend:
.section .debug_abbrev,"",@progbits
  .uleb128 1
  .uleb128 0x11
  .byte 1
  .uleb128 0x03
  .uleb128 0x08
  .uleb128 0x11
  .uleb128 0x01
  .uleb128 0x12
  .uleb128 0x07
  .uleb128 0x10
  .uleb128 0x17
  .byte 0,0
  .uleb128 2
  .uleb128 0x2e
  .byte 0
  .uleb128 0x6e
  .uleb128 0x1f21
  .uleb128 0x11
  .uleb128 0x01
  .uleb128 0x12
  .uleb128 0x07
  .byte 0,0,0
.section .debug_info,"",@progbits
  .long .Lcuend-.Lcu
.Lcu:
  .short 4
  .long 0
  .byte 8
  .uleb128 1
  .asciz "alt.c"
  .quad _start
  .quad .Lend-_start
  .long 0
  .uleb128 2
  .long 0
  .quad _start
  .quad .Lend-_start
  .byte 0
.Lcuend:
.section .debug_line,"",@progbits
  .long .Llineend-.Lline
.Lline:
  .short 2
  .long .Lheaderend-.Lheader
.Lheader:
  .byte 1,1,-5,14,13
  .byte 0,1,1,1,1,0,0,0,1,0,0,1
  .byte 0
  .asciz "alt.c"
  .byte 0,0,0,0
.Lheaderend:
  .byte 0,9,2
  .quad _start
  .byte 1,2,2,0,1,1
.Llineend:
.section .gnu_debugaltlink,"",@progbits
  .asciz "alt.debug"
  .byte 1,2,3,4
.section .note.GNU-stack,"",@progbits
