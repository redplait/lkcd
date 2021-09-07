bits 64

; conv calling in linux kernel: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame
; arg0 in RDI
; arg1 in RSI
; arg2 in RDX
; arg3 in RCX
; arg4 in R8
; arg5 in R9
global get_gs
global get_gs32
global get_this_gs

section .text

; rdi - offset
get_gs:
	mov rax, [gs:rdi]
	ret

get_gs32:
	mov eax, [gs:rdi]
	ret

; rdi - this_cpu_off
; rsi - offset
get_this_gs:
	mov rax, [gs:rdi]
	add rax, rsi
	ret