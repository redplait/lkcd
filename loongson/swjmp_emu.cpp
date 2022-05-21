#include "stdafx.h"
#include "idaidp.hpp"
#include <idp.hpp>
#include <frame.hpp>
#include <jumptable.hpp>
#include "disasm.h"
#include "ops.inc"
#include "swjmp_emu.h"

extern int is_pcadd(int itype);
extern ea_t pcadd(int itype, ea_t pc, int imm);

// 0) ret regA
bool loongson_jump_pattern_t::jpi0(void)
{
  if ( insn.itype != Loong_jirl )
    return false;
  trackop(insn.Op2, regA);
  return true;
}

// 1) add.d regA, regA, rJ
bool loongson_jump_pattern_t::jpi1(void)
{
  if ( insn.itype != Loong_add_d || !same_value(insn.Op1, regA) || !same_value(insn.Op2, regA) )
    return false;
#ifdef _DEBUG
  msg("jpi1: %a\n", insn.ea);
#endif
  trackop(insn.Op3, rJ);
  return true;
}

// 2) ldptr.d rJ, rS, 0
bool loongson_jump_pattern_t::jpi2(void)
{
  if ( insn.itype != Loong_ldptr_d || !same_value(insn.Op1, rJ) )
    return false;
#ifdef _DEBUG
  msg("jpi2: %a\n", insn.ea);
#endif
  si->startea = insn.ea;
  trackop(insn.Op2, rS); 
  return true;
}

// 3) alsl.d rS, rIdx, rBase, size
bool loongson_jump_pattern_t::jpi3(void)
{
  if ( insn.itype != Loong_alsl_d || !same_value(insn.Op1, rS) )
    return false;
#ifdef _DEBUG
  msg("jpi3: %a\n", insn.ea);
#endif
  trackop(insn.Op2, rIdx); 
  trackop(insn.Op3, rBase); 
  si->set_jtable_element_size(1 << insn.Op4.value);
  return true;
}

// 4) addi.d rBase, rBase2, offset
bool loongson_jump_pattern_t::jpi4(void)
{
  if ( insn.itype != Loong_addi_d || !same_value(insn.Op1, rBase) )
    return false;
#ifdef _DEBUG
  msg("jpi4: %a\n", insn.ea);
#endif
  trackop(insn.Op2, rBase2); 
  add_off = insn.Op3.value;
  return true;
}

// 5) pcadduXXi rBase2, base
bool loongson_jump_pattern_t::jpi5(void)
{
  if ( !same_value(insn.Op1, rBase2) )
    return false;
  if ( !is_pcadd(insn.itype) )
    return false;
#ifdef _DEBUG
   msg("jpi5: %a\n", insn.ea);
#endif
  // ok, we finally have address of table
  si->jumps = add_off + pcadd(insn.itype, insn.ea, insn.Op2.value);
  si->set_elbase(si->jumps);
  return true;
}

// 6)  bltu rMax, rIdx default addr
// 6b) bge rIdx, rMax, default addr
bool loongson_jump_pattern_t::jpi6(void)
{
 if ( insn.itype == Loong_bltu || insn.itype == Loong_blt )
 {
   if ( !same_value(insn.Op2, rIdx) )
     return false;
   trackop(insn.Op1, rMax); 
 } else if ( insn.itype == Loong_bge || insn.itype == Loong_bgeu )
 {
   if ( !same_value(insn.Op1, rIdx) )
     return false;
   trackop(insn.Op2, rMax); 
   is_ge = 1;
 } else
   return false;
#ifdef _DEBUG
  msg("jpi6: %a\n", insn.ea);
#endif
  si->defjump = insn.Op3.addr;
  return true;
}

// 7) mov rMax, imm
bool loongson_jump_pattern_t::jpi7(void)
{
 if ( insn.itype != Loong_mov || !same_value(insn.Op1, rMax) )
   return false;
 auto jsize = insn.Op2.value;
 if ( !is_ge )
   jsize++;
 si->set_jtable_size(jsize);
 si->flags |= SWI_SIGNED;
msg("jpi7: %a jumps %a size %d elsize %d\n", insn.ea, si->jumps, si->get_jtable_size(), si->get_jtable_element_size());
 return true;
}

bool loongson_jump_pattern_t::finish()
{
#ifdef _DEBUG
  msg("finish: %a\n", eas[7]);
#endif
  return eas[7] != BADADDR;
}

bool loongson_jump_pattern_t::handle_mov(tracked_regs_t &_regs)
{
  if ( insn.itype != Loong_mov
    && insn.Op1.type != o_reg
    && insn.Op2.type != o_reg )
  {
    return false;
  }
  return set_moved(insn.Op2, insn.Op1, _regs);
}

static int is_jump_pattern(switch_info_t *si, const insn_t &insn, procmod_t *pm)
{
  loongson_jump_pattern_t jp(si);
  if ( !jp.match(insn) || !jp.finish() )
    return JT_NONE;
  return JT_SWITCH;
}

int loongson_is_switch(switch_info_t *si, const insn_t &insn)
{
  if ( insn.itype != Loong_jirl )
    return false;
  static is_pattern_t *const patterns[] =
  {
    is_jump_pattern,
  };
  return check_for_table_jump(si, insn, patterns, qnumber(patterns));
}