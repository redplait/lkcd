#include "x64_disasm.h"

int x64_disasm::reg32to64(ud_type from, ud_type &res) const
{
  switch(from)
  {
    case UD_R_EAX: res = UD_R_RAX; return 1;
    case UD_R_ECX: res = UD_R_RCX; return 1;
    case UD_R_EDX: res = UD_R_RDX; return 1;
    case UD_R_EBX: res = UD_R_RBX; return 1;
    case UD_R_ESP: res = UD_R_RSP; return 1;
    case UD_R_EBP: res = UD_R_RBP; return 1;
    case UD_R_ESI: res = UD_R_RSI; return 1;
    case UD_R_EDI: res = UD_R_RDI; return 1;
    case UD_R_R8D:  res = UD_R_R8; return 1;
    case UD_R_R9D:  res = UD_R_R9; return 1;
    case UD_R_R10D: res = UD_R_R10; return 1;
    case UD_R_R11D: res = UD_R_R11; return 1;
    case UD_R_R12D: res = UD_R_R12; return 1;
    case UD_R_R13D: res = UD_R_R13; return 1;
    case UD_R_R14D: res = UD_R_R14; return 1;
    case UD_R_R15D: res = UD_R_R15; return 1;
  }
  return 0;
}

ud_type x64_disasm::expand_reg(int idx) const
{
  if ( ud_obj.operand[idx].size == 32 )
  {
    ud_type out = UD_NONE;
    if ( reg32to64(ud_obj.operand[idx].base, out) )
      return out;
  }
  return ud_obj.operand[idx].base;
}

int x64_disasm::is_jmp() const
{
  switch(ud_obj.mnemonic)
  {
    case UD_Ijo:
    case UD_Ijno:
    case UD_Ijb:
    case UD_Ijae:
    case UD_Ijz:
    case UD_Ijnz:
    case UD_Ijbe:
    case UD_Ija:
    case UD_Ijs:
    case UD_Ijns:
    case UD_Ijp:
    case UD_Ijnp:
    case UD_Ijl:
    case UD_Ijge:
    case UD_Ijle:
    case UD_Ijg:
    case UD_Ijcxz:
    case UD_Ijecxz:
    case UD_Ijrcxz:
    case UD_Ijmp:
     return 1;
  }
  return 0;
}

int x64_disasm::is_call_jimm() const
{
  return (ud_obj.mnemonic == UD_Icall) && (ud_obj.operand[0].type == UD_OP_JIMM);
}

int x64_disasm::is_jxx_jimm() const
{
  if ( !is_jmp() )
    return 0;
  return (ud_obj.operand[0].type == UD_OP_JIMM);
}

int x64_disasm::is_end() const
{
  return (ud_obj.mnemonic == UD_Iint3) ||
         (ud_obj.mnemonic == UD_Iret)  ||
         (ud_obj.mnemonic == UD_Iretf) ||
         (ud_obj.mnemonic == UD_Iud2)  ||
         (ud_obj.mnemonic == UD_Ijmp)
  ;
}

int x64_disasm::is_memw(ud_mnemonic_code c) const
{
  return (ud_obj.mnemonic == c) &&
         (ud_obj.operand[0].type == UD_OP_MEM) && 
         (ud_obj.operand[0].base == UD_R_RIP)
  ;
}

int x64_disasm::is_rmem(ud_mnemonic_code c) const
{
  return (ud_obj.mnemonic == c) &&
         (ud_obj.operand[0].type == UD_OP_REG) &&
         (ud_obj.operand[1].type == UD_OP_MEM)
  ;
}

int x64_disasm::is_mrip(ud_mnemonic_code c) const
{
  return (ud_obj.mnemonic == c) &&
         (ud_obj.operand[1].type == UD_OP_MEM) && 
         (ud_obj.operand[1].base == UD_R_RIP)
  ;
}

ptrdiff_t x64_disasm::get_addr(int idx) const
{
  return ud_obj.pc + (sa64)ud_obj.operand[idx].lval.sdword;
}

ptrdiff_t x64_disasm::find_mov(ptrdiff_t toff)
{
  ELFIO::Elf_Half n = m_reader->sections.size();
  if ( !n )
    return 0;
  for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
     ELFIO::section* sec = m_reader->sections[i];
     if ( sec->get_type() != SHT_PROGBITS )
       continue;
     if ( !(sec->get_flags() & SHF_EXECINSTR) )
       continue;
     const unsigned char *body = (const unsigned char *)sec->get_data();
     const unsigned char *end = body + sec->get_size();
     for ( auto curr = body; curr < end + 6; ++curr )
     {
       // mov reg, [mem + rip] encoded as
       // 48 8B modrm
       // 4C 8B modrm
       // both form 7 byte
       if ( (curr[0] == 0x48 || curr[0] == 0x4c) && curr[1] == 0x8b && (curr[2] & 7) == 5 )
       {
         int rva = 7 + *(int *)(curr + 3);
         ptrdiff_t off = (ptrdiff_t)(curr + rva - body + sec->get_address());
         if ( off == toff )
           return curr - body + sec->get_address();
       }
     }
  }
  return 0;
}

ptrdiff_t x64_disasm::find_lea(ptrdiff_t toff)
{
  ELFIO::Elf_Half n = m_reader->sections.size();
  if ( !n )
    return 0;
  for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
     ELFIO::section* sec = m_reader->sections[i];
     if ( sec->get_type() != SHT_PROGBITS )
       continue;
     if ( !(sec->get_flags() & SHF_EXECINSTR) )
       continue;
     const unsigned char *body = (const unsigned char *)sec->get_data();
     const unsigned char *end = body + sec->get_size();
     for ( auto curr = body; curr < end + 6; ++curr )
     {
       // lea reg, [mem + rip] can be encoded as
       // 48 8D modrm
       // 4C 8D modrm
       // both form 7 byte
       if ( (curr[0] == 0x48 || curr[0] == 0x4c) && curr[1] == 0x8d && (curr[2] & 7) == 5 )
       {
         int rva = 7 + *(int *)(curr + 3);
         ptrdiff_t off = (ptrdiff_t)(curr + rva - body + sec->get_address());
         if ( off == toff )
           return curr - body + sec->get_address();
       }
     }
  }
  return 0;
}