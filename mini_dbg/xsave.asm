.section .bss
    .lcomm    buffer, 10000

.section .text
.global    _start
_start:
    movl     $1, %eax
    xsave buffer
