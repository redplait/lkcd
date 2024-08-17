#include "mips_disasm.h"

int mdis::handle(mips_regs &r)
{
  if ( inst.operation == mips::MIPS_LUI )
  {
// printf("handle(%s) %d %d, %d %d\n", mips::get_operation(inst.operation), inst.operands[0].operandClass, inst.operands[1].operandClass);
   if ( inst.operands[0].operandClass == mips::OperandClass::REG && inst.operands[1].operandClass == mips::OperandClass::IMM )
   {
    return r.set(inst.operands[0].reg, inst.operands[1].immediate << 16);
   }
  }
  if ( inst.operation == mips::MIPS_LW && inst.operands[0].operandClass == mips::OperandClass::REG &&
    inst.operands[1].operandClass == mips::OperandClass::MEM_IMM )
  {
    auto old = r.get(inst.operands[1].reg);
// printf("lw(%d) old %lX\n", inst.operands[1].reg, old);
    if ( !old ) return 0;
    old += (int)inst.operands[1].immediate;
    return r.set(inst.operands[0].reg, old);
  }
  return 0;
}

int mips_disasm::setup(PBYTE psp, mdis *md)
{
  const PBYTE end = (const PBYTE)(m_text + m_text_size);
  if ( psp > end )
    return 0;
  md->psp = psp;
  md->end = end;
  return 1;
}

int mips_disasm::process(a64 addr, std::map<a64, a64> &, std::set<a64> &out_res)
{
  return 0;
}

int mips_disasm::process_sl(lsm_hook &sl)
{
  mdis md(m_bigend, mv);
  if ( !setup(uconv(sl.addr), &md) )
    return 0;
  mips_regs regs;
  while( md.disasm() )
  {
    if ( md.handle(regs) && md.inst.operation == mips::MIPS_LW )
    {
      auto v = regs.get(md.inst.operands[0].reg);
      if ( v && is_sec_heads(v) )
      {
        sl.list = v;
        return 1;
      }
    }
  }
  return 0;
}

a64 mips_disasm::process_bpf_target(a64 addr, a64 mlock)
{
  mdis md(m_bigend, mv);
  if ( !setup(uconv(addr), &md) )
    return 0;
  mips_regs regs;
  int state = 0; // 1 after jal mlock
  while( md.disasm() )
  {
    a64 caddr = 0;
    if ( !state && md.is_jal(caddr) )
    {
      if ( mlock == caddr ) {
        state = 1;
        continue;
      }
    } else if ( state )
    {
      if ( md.handle(regs) && md.inst.operation == mips::MIPS_LW )
      {
        auto v = regs.get(md.inst.operands[0].reg);
        if ( v && in_data(v) )
          return v;
      }
    }
  }
  return 0;
}

int mips_disasm::process_trace_remove_event_call(a64 addr, a64 free_event_filter)
{
  return 0;
}

int mips_disasm::find_kfunc_set_tab_off(a64 addr)
{
  mdis md(m_bigend, mv);
  if ( !setup(uconv(addr), &md) )
    return 0;
  while( md.disasm() )
  {
    if ( md.is_lw(mips::REG_A0, kfunc_set_tab_off) )
      return kfunc_set_tab_off;
  }
  return 0;
}
