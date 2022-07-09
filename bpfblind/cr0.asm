bits 64

global get_cr0
global set_cr0
global reset_wp

section .text

get_cr0:
 mov rax, cr0
 ret

; arg0 in RDI
set_cr0:
 mov rax, cr0
 mov cr0, rdi
 ret

reset_wp:
 mov rax, cr0
 push rax
 btr rax, 16 ; wp is 16 bit
 mov cr0, rax
 pop rax
 ret