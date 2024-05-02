bits 64
entry_malloc_hook:
; entry for __malloc_hook
 mov rax, [rel mh_old]
 jmp .unpatch
; entry for __free_hook
 mov rax, [rel fh_old]
.unpatch:
 push rax
; save arg regs
 push rdi
 push rsi
 push rdx
 push rcx
 push r8
 push r9
; restore old hooks
 lea rax, [rel mh]
 mov rdi, [rax]
 mov rsi, [rax + 8] ; mh_old
 mov [rdi], rsi
 add rax, 16
 mov rdi, [rax]
 ; second hook may not be used
 test rdi, rdi
 jz .dlopen
 mov rsi, [rax + 8] ; fh_old
 mov [rdi], rsi
; call dlopen
.dlopen:
 push 2 ; RTLD_NOW
 lea rdi, [rel dll_path]
 pop rsi
 call [rel dlopen_ptr]
 test rax, rax
 jz .fail
 mov rdi, rax ; handle
 lea rsi, [rel func_name]
 call [rel dlsym_ptr]
 test rax, rax
 jz .fail
 lea rdi, [rel entry_malloc_hook] ; first arg - address of this memory chunk
 call rax
.fail:
 pop r9
 pop r8
 pop rcx
 pop rdx
 pop rsi
 pop rdi
 ; get address of old hook handler from stack
 pop rax
 test rax, rax
 jnz .tail
 ret
.tail:
 jmp rax

align 8
; __malloc_hook original
mh: db "EbiGusej"
mh_old: dq 0
; __free_hook
        dq 0
fh_old: dq 0
dlopen_ptr: dq 0
dlsym_ptr: dq 0
func_name: db "inject", 0
dll_path:  db "./test.so", 0
