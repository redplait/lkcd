.text
t1:
 addi.d $r8, $r0, 8 # dtab + 8 = old malloc hook
 b .common
t2:
 addi.d $r8, $r0, 24 # dtab + 24 = fh_old
.common:
 # make stack frame
 # stack layout
 # 0 - ret addr
 # 8 - r8 with index in dtab
 # 16 - a0
 # 24 - a1
 # 32 - a2
 # 40 - r22, fp
 addi.d $sp, $sp, -48
 st.d $a0, $sp, 16
 st.d $a1, $sp, 24
 st.d $a2, $sp, 32
 st.d $r22, $sp, 40
 st.d $r8, $sp, 8
 st.d $r1, $sp, 0 # ret addr
 # put dtab addr into r22
 la.pcrel $r22, dtab
 # patch old values
 ld.d $r8, $r22, 0 # address of malloc_hook
 ld.d $r9, $r22, 8
 st.d $r9, $r8, 0
 ld.d $r8, $r22, 16 # address of free_hook
 beqz $r8, dlopen
 ld.d $r9, $r22, 24
 st.d $r9, $r8, 0
dlopen:
 # args r4 - name of .so, r5 - 2
 addi.d $r5, $r0, 2
 la.pcrel $r4, dll_path
 ld.d $r8, $r22, 32
 jirl $r1, $r8, 0
 # check res in r4
 beqz $r4, .end
 addi.d $r5, $r22, 49
 ld.d $r8, $r22, 40
 jirl $r1, $r8, 0
 beqz $r4, .end
 move $r8, $r4
 la.pcrel $r4, t1
 jirl $r1, $r8, 0
.end:
 ld.d $r8, $sp, 8     # restore from stack r8
 ldx.d $r8, $r22, $r8 # r8 <- [r22 + r8]
 ld.d $r1, $sp, 0 # ret addr
 ld.d $r22, $sp, 40
 ld.d $a2, $sp, 32
 ld.d $a1, $sp, 24
 ld.d $a0, $sp, 16
 addi.d $sp, $sp, 48  # restore stack
 bnez $r8, chain
 ret
chain:
 jr $r8

dtab: .ascii "EbiGusej"
.mh_old: .quad 0     # off 8
.free_hook: .quad 0  # off 16
.fh_old: .quad 0     # off 24
.dlopen_ptr: .quad 0 # off 32
.dlsym_ptr: .quad 0  # off 40
.byte t2 - t1        # off 48, func_name 49
func_name: .string "inject"
dll_path:  .string "./test.so"
