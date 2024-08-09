struct x64_thunk
{
  const char *name;
  ud_type reg;
};

static const x64_thunk s_x64_thunks[] = {
  { "__x86_indirect_thunk_rax", UD_R_RAX },
  { "__x86_indirect_thunk_rbx", UD_R_RBX },
  { "__x86_indirect_thunk_rcx", UD_R_RCX },
  { "__x86_indirect_thunk_rdx", UD_R_RDX },
  { "__x86_indirect_thunk_rsi", UD_R_RSI },
  { "__x86_indirect_thunk_rdi", UD_R_RDI },
  { "__x86_indirect_thunk_rbp", UD_R_RBP },
  { "__x86_indirect_thunk_r8",  UD_R_R8 },
  { "__x86_indirect_thunk_r9",  UD_R_R9 },
  { "__x86_indirect_thunk_r10", UD_R_R10 },
  { "__x86_indirect_thunk_r11", UD_R_R11 },
  { "__x86_indirect_thunk_r12", UD_R_R12 },
  { "__x86_indirect_thunk_r13", UD_R_R13 },
  { "__x86_indirect_thunk_r14", UD_R_R14 },
  { "__x86_indirect_thunk_r15", UD_R_R15 },
};

// 32bit x86 don`t supported but just for completness
static const x64_thunk s_x86_thunks[] = {
  { "__x86_indirect_thunk_eax", UD_R_EAX },
  { "__x86_indirect_thunk_ebx", UD_R_EBX },
  { "__x86_indirect_thunk_edx", UD_R_EDX },
  { "__x86_indirect_thunk_ecx", UD_R_ECX },
  { "__x86_indirect_thunk_esi", UD_R_ESI },
  { "__x86_indirect_thunk_edi", UD_R_EDI },
  { "__x86_indirect_thunk_ebp", UD_R_EBP },
};
