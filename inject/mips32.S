.text
# post-processing after j can broke your brain
.set reorder
# t1 is entry point for malloc_hook
# t2 for free_hook
# to save space $8 will hold offset relative .dtab for old hook value + 4
t1:
  move $8, $0
  j .common
t2:
  li $8, 8
.common:
  # need to save ra, $gp, $4, $5, $6 & $8
  subu $sp, $sp, 24
  # stack layout - must be aligned on 8 bytes
  # 20 - $6
  # 16 - $gp
  # 12 $8 - index of thunk
  # 8 $5 - second arg
  # 4 $4 - first arg
  # 0 ra
  sw $ra, 0($sp)
  sw $4, 4($sp)
  sw $5, 8($sp)
  sw $8, 12($sp)
  sw $gp, 16($sp)
  sw $6, 20($sp)
  # load $gp with address of .dtab - dirty hack for PICode
  jal .rel
.rel:
  li $9, .dtab - .rel
  # now $gp holds address of .dtab
  addu $gp, $ra, $9
  # restore old hooks
  lw $9, 0($gp)  # addr of malloc_hook
  lw $8, 4($gp)  # value of old malloc_hook
  sw $8, ($9)
  lw $9, 8($gp)  # addr of free_hook
  beq $9, $0, .call_dlopen # can be zero - then skip patch
  lw $8, 12($gp) # value of old free_hook
  sw $8, ($9)
.call_dlopen:
  # args: 1st in $4, second in $5
  li $9, dll_path - .dtab
  li $5, 2 # RTLD_NOW
  addu $4, $gp, $9 # $4 holds address of dll_path
  lw $8, 16($gp)   # dlopen_ptr
  jalr $8, $ra
  beq $2, $0, .end # check result, if zero - goto .end
  li $9, func_name - .dtab
  move $4, $2      # first arg - handle from dlopen
  lw $8, 20($gp)   # dlsym_ptr
  addu $5, $gp, $9 # $5 holds address of func_name
  jalr $8, $ra
  beq $2, $0, .end # check result, if zero - goto .end
  li $4, .dtab - t1
  subu $4, $gp, $4 # address of t1
  jalr $2, $ra    # call function returned from dlsym, arg in $4 - address of t1
.end:
  # pop back saved in stack $8
  lw $8, 12($sp)
  addu $8, $gp   # $8 holds .dtab + index stored at begin in $8
  lw $8, 4($8)   # load in $8 old hook value
  # epilogue
  lw $6, 20($sp)
  lw $gp, 16($sp)
  lw $5, 8($sp)
  lw $4, 4($sp)
  lw $ra, 0($sp)
  addu $sp, $sp, 24
  beq $8, $0, .ret
  jr $8 # jump to old hook
.ret:
  jr $ra # if $8 is zero - just return
  nop

.dtab: .ascii "EbiGusej"
.free_hook: .word 0
fh_old: .word 0
dlopen_ptr: .word 0
dlsym_ptr: .word 0
func_name: .string "inject"
dll_path:  .string "./test.so"
