bits 64

; conv calling in linux kernel: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame
; arg0 in RDI
; arg1 in RSI
; arg2 in RDX
; arg3 in RCX
; arg4 in R8
; arg5 in R9
global get_gs
global get_gs_dword
global get_gs_word
global get_gs_byte
global get_this_gs
global xchg_ptrs
; all put_gs_xxx functions return old value
global put_gs
global put_gs_dword
global put_gs_word
global put_gs_byte

section .text

; rdi - offset
get_gs:
	mov rax, [gs:rdi]
	ret

get_gs_dword:
	mov eax, [gs:rdi]
	ret

get_gs_word:
	mov ax, [gs:rdi]
	ret

get_gs_byte:
	mov al, [gs:rdi]
	ret

; rdi - this_cpu_off
; rsi - offset
get_this_gs:
	mov rax, [gs:rdi]
	add rax, rsi
	ret

; rdi - offset
; rsi - value
put_gs:
	mov rax, [gs:rdi]
	mov [gs:rdi], rsi
	retn

put_gs_dword:
	mov eax, [gs:rdi]
	mov [gs:rdi], esi
	retn

put_gs_word:
	mov ax, [gs:rdi]
	mov [gs:rdi], si
	retn

put_gs_byte:
	mov ax, si
	shl ax, 8 ; now byte in ah
	mov al, [gs:rdi] ; store old value in al
	mov [gs:rdi], ah ; set new value
	retn

; linux kernel arch_xchg is very hard to use so this is simple impl of function to exchange couple of pointers
; 1st param - first arg in rdi
; 2nd param - address of what must be placed to 1st
; also put old value from 1st arg to 2nd and return it
xchg_ptrs:
	mov rax, [rsi] ; second arg
	lock xchg [rdi], rax
	mov rax, [rsi] ; put old value in second arg
	retn
