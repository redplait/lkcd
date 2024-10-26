#pragma once
#include "dis_base.h"
#include "mips/mips.h"
#include <bitset>

extern int g_opt_d;

// for handling lui/lw pairs
struct mips_regs {
  int64_t regs[mips::REG_RA];
  std::bitset<mips::REG_RA> pres;
  int64_t get(int idx) const
  {
    if ( idx < 0 || idx >= mips::REG_RA ) return 0;
    if ( !pres[idx] ) return 0;
    return regs[idx];
  }
  int set(int idx, int64_t v)
  {
    if ( idx < 0 || idx >= mips::REG_RA ) return 0;
    pres[idx] = 1;
    regs[idx] = v;
    return 1;
  }
 int clear(int idx)
  {
    if ( idx >= mips::REG_RA || idx < 0 ) return 0;
    pres[idx] = 0;
    regs[idx] = 0;
    return 1;
  }
};

// to handle move reg, reg
struct mips_regs2 {
 char regs[mips::REG_RA];
 mips_regs2() {
   memset(regs, -1, mips::REG_RA);
 }
 int check(int idx) const
 {
   if ( idx >= mips::REG_RA ) return -1;
   return regs[idx];
 }
 int set(int idx, int src)
 {
   if ( idx >= mips::REG_RA || src >= mips::REG_RA ) return 0;
   regs[idx] = src;
   return 1;
 }
};

struct mdis {
 mdis(int m, mips::MipsVersion e): m_bigend(m), m_mv(e)
 {
   psp = end = nullptr;
 }
 // internal disasm data
 PBYTE psp, end;
 int m_bigend;
 mips::MipsVersion m_mv;
 mips::Instruction inst;
 // methods
 int disasm() {
   if ( psp >= end ) return 0;
   int rc = mips::mips_decompose((const uint32_t*)psp, 4, &inst, m_mv, (uint64_t)psp, m_bigend, 1);
  if ( rc ) return 0;
   if ( g_opt_d )
   {
     char txt[1024];
     txt[0] = 0;
     if ( !mips::mips_disassemble(&inst, txt, 1023) )
       printf("%s\n", txt);
   }
   psp += inst.size;
   // check for speculative execution
   if ( is_end() )
     end = psp + 4;
   return 1;
 }
 int is_end() const
 {
   switch(inst.operation)
   {
     case mips::MIPS_BREAK:
     case mips::MIPS_B:
     case mips::MIPS_JR:
     case mips::MIPS_J:
      return 1;
   }
   return 0;
 }
 int is_jal(a64 &ja) const
 {
   if ( inst.operation == mips::MIPS_JAL && inst.operands[0].operandClass == mips::OperandClass::LABEL )
   {
     ja = (a64)inst.operands[0].immediate;
     return 1;
   }
   return 0;
 }
 int is_lbX() const
 {
   return (inst.operation == mips::MIPS_LBU || inst.operation == mips::MIPS_LB ||
      inst.operation == mips::MIPS_LH || inst.operation == mips::MIPS_LHU ||
      inst.operation == mips::MIPS_LW || inst.operation == mips::MIPS_LL || inst.operation == mips::MIPS_LLD) &&
    inst.operands[0].operandClass == mips::OperandClass::REG &&
    inst.operands[1].operandClass == mips::OperandClass::MEM_IMM;
 }
 int is_stX() const
 {
  return (inst.operation == mips::MIPS_SB || inst.operation == mips::MIPS_SH ||
       inst.operation == mips::MIPS_SW || inst.operation == mips::MIPS_SD) &&
    inst.operands[0].operandClass == mips::OperandClass::REG &&
    inst.operands[1].operandClass == mips::OperandClass::MEM_IMM;
 }
 int is_lw() const
 {
   return (inst.operation == mips::MIPS_LW || inst.operation == mips::MIPS_LBU) &&
          inst.operands[0].operandClass == mips::OperandClass::REG &&
          inst.operands[1].operandClass == mips::OperandClass::MEM_IMM;
 }
 int is_addiu(int &val) const
 {
   if ( inst.operation == mips::MIPS_ADDIU &&
        inst.operands[0].operandClass == mips::OperandClass::REG &&
        inst.operands[1].operandClass == mips::OperandClass::REG &&
        inst.operands[2].operandClass == mips::OperandClass::IMM )
   {
     val = (int)inst.operands[2].immediate;
     return 1;
   }
   return 0;
 }
 int is_lw(int reg, int &val) const
 {
   if ( inst.operation == mips::MIPS_LW && inst.operands[1].operandClass == mips::OperandClass::MEM_IMM &&
        inst.operands[1].reg == reg
   )
   {
     val = (int)inst.operands[1].immediate;
     return 1;
   }
   return 0;
 }
 unsigned long is_jxx() const
 {
   using namespace mips;
   // https://www.cs.cmu.edu/afs/cs/academic/class/15740-f97/public/doc/mips-isa.pdf
   switch(inst.operation) {
     case MIPS_B:
     case MIPS_J:
      if ( inst.operands[0].operandClass == mips::LABEL )
        return inst.operands[0].immediate;
      break;

     // REG/LABEL
     case MIPS_BEQZ: // Branch on Equal Zero
     case MIPS_BGEZ:  // Branch on Greater Than Equal Zero
     case MIPS_BGEZAL:
     case MIPS_BGEZALL:
     case MIPS_BGEZL:
     case MIPS_BLTZL: // Branch on Greater Than or Equal to Zero Likely
     case MIPS_BLTZAL:
     case MIPS_BLTZALL:
     case MIPS_BLTZ:  // Branch on Less Than Zero
     case MIPS_BGTZ:  // Branch on Greater Than Zero
     case MIPS_BGTZL: // Branch on Greater Than Zero Likely
     case MIPS_BLEZ:  // Branch on Less Than or Equal to Zero
     case MIPS_BLEZL: // Branch on Less Than or Equal to Zero Likely
      if ( inst.operands[1].operandClass == mips::LABEL )
        return inst.operands[1].immediate;
      break;

     // reg/reg/LABEL
    case MIPS_BEQ:
     case MIPS_BEQL: // Branch on Equal Likely
     case MIPS_BNE:
     case MIPS_BNEL:  // Branch on Not Equal Likely
      if ( inst.operands[2].operandClass == mips::LABEL )
        return inst.operands[2].immediate;
      break;

     // next group can be LABEL or FLAG/LABEL
     case MIPS_BC1T:
     case MIPS_BC1F:
     case MIPS_BC1FL:
     case MIPS_BC1TL:
     case MIPS_BC2F:
     case MIPS_BC2FL:
     case MIPS_BC2T:
     case MIPS_BC2TL:
      if ( inst.operands[0].operandClass == mips::LABEL )
        return inst.operands[0].immediate;
      if ( inst.operands[1].operandClass == mips::LABEL )
        return inst.operands[1].immediate;
      break;
   }
   return 0;
 }
 int is_dst() const
 {
using namespace mips;
   // https://www.cs.cmu.edu/afs/cs/academic/class/15740-f97/public/doc/mips-isa.pdf
   switch(inst.operation) {
     case MIPS_ABS_D:
     case MIPS_ABS_PS:
     case MIPS_ABS_S:
     case MIPS_DADD:
     case MIPS_DADDI:
     case MIPS_DADDIU:
     case MIPS_DADDU:
     case MIPS_ADD:
     case MIPS_ADDU:
     case MIPS_ADDIU:
     case MIPS_SUB:
     case MIPS_DSUB:
     case MIPS_SUBU:
     case MIPS_DSUBU:
     case MIPS_MUL:
     case MIPS_MULT:
     case MIPS_MULTU:
     case MIPS_DIV_D:
     case MIPS_DIV_PS:
     case MIPS_DIV_S:
     case MIPS_MFHI:
     case MIPS_MTHI:
     case MIPS_MFLO:
     case MIPS_MTLO:
     case MIPS_NEG_D:
     case MIPS_NEG_PS:
     case MIPS_NEG_S:
     case MIPS_NEG:
     case MIPS_NEGU:
     case MIPS_NOR:
     case MIPS_NOT:
     case MIPS_C_SEQ_D:
     case MIPS_C_SEQ_PS:
     case MIPS_C_SEQ_S:
     case MIPS_C_SEQ:
     case MIPS_SRA:
     case MIPS_SRAV:
     case MIPS_DSRA:
     case MIPS_SLT:
     case MIPS_SLTI:
     case MIPS_SLTU:
     case MIPS_SLTIU:
     case MIPS_AND:
     case MIPS_OR:
     case MIPS_ANDI:
     case MIPS_ORI:
     case MIPS_XOR:
     case MIPS_XORI:
     case MIPS_SLL:
     case MIPS_SLLV:
     case MIPS_SRL:
     case MIPS_SRLV:
     case MIPS_DSRL:
     case MIPS_DSLL:
     case MIPS_MOVN:
     case MIPS_MOVZ:
      return 1;
   }
   return 0;
 }
 int handle(mips_regs &regs, int off = 0);
 int handle(mips_regs2 &regs);
};

class mips_disasm: public dis_base
{
  public:
    mips_disasm(int bigend, int elf_size, a64 text_base, size_t text_size, const char *text, a64 data_base, size_t data_size)
     : dis_base(text_base, text_size, text, data_base, data_size),
       m_bigend(bigend)
    {
      mv = elf_size == 32 ? mips::MIPS_32 : mips::MIPS_64;
    }
    virtual int process(a64 addr, std::map<a64, a64> &, std::set<a64> &out_res);
    virtual int find_kfunc_set_tab_off(a64 addr) override;
    virtual int find_kmem_cache_next(a64 addr) override;
    virtual int find_kmem_cache_name(a64 addr, a64 kfree_const) override;
    virtual int find_kmem_cache_ctor(a64 addr, int &flag_off) override;
    virtual int process_sl(lsm_hook &) override;
    virtual a64 process_bpf_target(a64 addr, a64 mlock) override;
    virtual int process_trace_remove_event_call(a64 addr, a64 free_event_filter) override;
    void add_noreturn(a64 addr)
    {
      m_noreturn.insert(addr);
    }
    virtual ~mips_disasm() = default;
  protected:
   PBYTE uconv(a64 addr) const
    {
      return (PBYTE)m_text + addr - m_text_base;
    }
    a64 conv(PBYTE addr) const
    {
      return m_text_base + (a64)(addr - (PBYTE)m_text);
    }
    int is_noret(a64 addr) const
    {
      auto f = m_noreturn.find(addr);
      if ( f == m_noreturn.cend() )
        return 0;
      return 1;
    }
    int setup(PBYTE psp, mdis *);
    int setup(a64 addr, mdis *);
    int m_bigend = 0;
    mips::MipsVersion mv;
    // set of __noreturn functions
    std::set<a64> m_noreturn;
};