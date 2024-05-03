.arch armv8-a
.text
.global t1, t2
// ripped from aarch64/include/asm
.macro  adr_l, dst, sym
        adrp    \dst, \sym
        add     \dst, \dst, :lo12:\sym
.endm
.macro  ldr_l, dst, sym, tmp=
        .ifb    \tmp
        adrp    \dst, \sym
        ldr     \dst, [\dst, :lo12:\sym]
        .else
        adrp    \tmp, \sym
        ldr     \dst, [\tmp, :lo12:\sym]
        .endif
.endm

/* according to ABI https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
 * we must save r30 bcs this is return address and args in r0-r7
 * I assume that thunks will have max 2 arg to store only r0 & r1
 * Stack must be aligned on 16 bytes if I right remember
 */
t1:
  bti c // bcs this is indirectly called function
  adr x9, .dtab
  ldr x9, [x9, 8]
  b .cmn_thunk
t2:
  bti c // bcs this is indirectly called function
  ldr_l x9, fh_old
.cmn_thunk:
  // store regs
  stp x29, x30, [sp, -16]!
  stp x0, x1, [sp, -16]!
  stp x2, x9, [sp, -16]!
  // dirty hack - use FP as ptr to marker
  adr x29, .dtab
  // restore old hooks
  ldr x9, [x29]      // addr of hook_malloc
  ldr x11, [x29, 8]  // old hook_malloc value
  str x11, [x9]
  ldr x9, [x29, 16]  // addr of free_hook
  cbz x9, .skip_second // skip if second hook not used
  ldr x11, [x29, 24]   // value of fh_old
  str x11, [x9]
.skip_second:
  mov x1, 2 // RTLD_NOW - second arg for dlopen
  adr x0, dll_path
  ldr x10, [x29, 32]
  blr x10
  cbz x0, .fail
  adr x1, func_name // second arg for dlsym
  ldr x10, [x29, 40]
  blr x10
  cbz x0, .fail
  mov x10, x0
  adr x0, t1
  blr x10
.fail:
  ldp x2, x9, [sp], 16
  ldp x0, x1, [sp], 16
  ldp x29, x30, [sp], 16
  cbnz x9, .call_orig
  ret
.call_orig:
  br x9

.align 3
.dtab: .string "EbiGusej"
.align 3
.free_hook: .xword 0
fh_old: .xword 0
dlopen_ptr: .xword 0
dlsym_ptr: .xword 0
func_name: .string "inject"
dll_path:  .string "./test.so"

