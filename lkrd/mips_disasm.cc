#include "mips_disasm.h"

int mdis::handle(mips_regs2 &r)
{
  if ( inst.operation == mips::MIPS_MOVE )
  {
    return r.set(inst.operands[0].reg, inst.operands[1].reg);
  }
  return 0;
}

int mdis::handle(mips_regs &r, int off)
{
  if ( inst.operation == mips::MIPS_LUI || inst.operation == mips::MIPS_LI )
  {
// printf("handle(%s) %d %d, %d %d\n", mips::get_operation(inst.operation), inst.operands[0].operandClass, inst.operands[1].operandClass);
   if ( inst.operands[0].operandClass == mips::OperandClass::REG && inst.operands[1].operandClass == mips::OperandClass::IMM )
   {
    return r.set(inst.operands[0].reg, inst.operands[1].immediate << 16);
   }
  }
  if ( is_lw() )
  {
    auto old = r.get(inst.operands[1].reg);
// printf("lw(%d) old %lX\n", inst.operands[1].reg, old);
    if ( !off ) {
      if ( !old ) return 0;
      old += (int)inst.operands[1].immediate;
    } else
      old = (int)inst.operands[1].immediate;
    return r.set(inst.operands[0].reg, old);
  }
  if ( inst.operands[0].operandClass == mips::OperandClass::REG && is_dst() )
     r.clear(inst.operands[0].reg);
  return 0;
}

int mips_disasm::setup(a64 addr, mdis *md)
{
  if ( addr < m_text_base ) return 0;
  if ( addr >= m_text_base + m_text_size ) return 0;
  auto psp = uconv(addr);
  return setup(psp, md);
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
  if ( !setup(sl.addr, &md) )
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
  if ( !setup(addr, &md) )
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

int mips_disasm::find_kmem_cache_next(a64 addr)
{
  mdis md(m_bigend, mv);
  if ( !setup(addr, &md) )
    return 0;
  int state = 0; // 1 after first call (hopefully _mcount)
  mips_regs2 regs;
  while( md.disasm() )
  {
    if ( md.handle(regs) ) continue;
    a64 caddr = 0;
    if ( md.is_jal(caddr) )
    {
      state++;
      if ( state > 1 ) break;
    }
    int val = 0;
    if ( state && md.is_addiu(val) && val < 0 )
    {
      auto reg = md.inst.operands[1].reg;
      if ( reg == mips::REG_SP ) continue;
      if ( reg == mips::REG_A1 ) return -val;
      auto old = regs.check(reg);
      if ( old == mips::REG_A1 ) return -val;
    }
  }
  return 0;
}

int mips_disasm::find_kmem_cache_name(a64 addr, a64 kfree_const)
{
  mdis md(m_bigend, mv);
  if ( !setup(addr, &md) )
    return 0;
  int state = 0; // 1 after call kfree_const
  mips_regs2 regs;
  while( md.disasm() )
  {
    if ( md.handle(regs) ) continue;
    a64 caddr = 0;
    if ( !state && md.is_jal(caddr) )
    {
      if ( caddr == kfree_const )
      {
        state++;
        continue;
      }
    }
    if ( state )
    {
      // check lw reg, imm(a0 or copy)
      if ( md.is_lw() )
      {
        auto reg = md.inst.operands[1].reg;
        if ( reg == mips::REG_SP ) continue;
        if ( reg == mips::REG_A0 ) return md.inst.operands[1].immediate;
        auto old = regs.check(reg);
        if ( old == mips::REG_A0 ) return md.inst.operands[1].immediate;
      }
      state++;
      if ( state > 1 ) break;
    }
  }
  return 0;
}

int mips_disasm::find_kmem_cache_ctor(a64 addr, int &flag_off)
{
  mdis md(m_bigend, mv);
  if ( !setup(addr, &md) )
    return 0;
  int state = 0; // 1 after first and
  mips_regs2 regs;
  mips_regs offs;
  while( md.disasm() )
  {
    if ( !state && md.inst.operation == mips::MIPS_AND ) {
      auto reg = md.inst.operands[0].reg;
      flag_off = (int)offs.get(reg);
      state = 1;
      continue;
    }
    if ( md.handle(regs) ) continue;
    if ( !state && md.handle(offs, 1) ) continue;
    if ( state && md.is_lw() )
    {
      auto reg = md.inst.operands[1].reg;
      if ( reg == mips::REG_SP ) continue; // skip loading local var from stack frame
      auto old = regs.check(reg);
      if ( old == mips::REG_A0 ) return md.inst.operands[1].immediate;
    }
  }
  return 0;
}

int mips_disasm::find_kfunc_set_tab_off(a64 addr)
{
  mdis md(m_bigend, mv);
  if ( !setup(addr, &md) )
    return 0;
  while( md.disasm() )
  {
    if ( md.is_lw(mips::REG_A0, kfunc_set_tab_off) )
      return kfunc_set_tab_off;
  }
  return 0;
}
