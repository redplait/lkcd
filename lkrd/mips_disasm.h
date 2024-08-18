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
    if ( idx >= mips::REG_RA ) return 0;
    if ( !pres[idx] ) return 0;
    return regs[idx];
  }
  int set(int idx, int64_t v)
  {
    if ( idx >= mips::REG_RA ) return 0;
    pres[idx] = 1;
    regs[idx] = v;
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
 int handle(mips_regs &regs);
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
    virtual int find_kfunc_set_tab_off(a64 addr);
    virtual int process_sl(lsm_hook &);
    virtual a64 process_bpf_target(a64 addr, a64 mlock);
    virtual int process_trace_remove_event_call(a64 addr, a64 free_event_filter);
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