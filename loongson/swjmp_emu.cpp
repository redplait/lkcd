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

bool loongson_jump_pattern9ops::is_ret()
{
  if ( insn.itype != Loong_jirl )
    return false;
  trackop(insn.Op2, regA);
  return true;
}

// add.d regA, rBase, rJ
bool loongson_jump_pattern9ops::is_add()
{
  if ( insn.itype != Loong_add_d || !same_value(insn.Op1, regA) )
    return false;
#ifdef _DEBUG
  msg("9pi1: %a\n", insn.ea);
#endif
  trackop(insn.Op2, rBase);
  trackop(insn.Op3, rJ);
  return true;
}

// ldx.d rJ, rBase, rS
bool loongson_jump_pattern9ops::is_ldx()
{
  if ( insn.itype != Loong_ldx_d || !same_value(insn.Op1, rJ) )
    return false;
  if ( same_value(insn.Op2, rBase) )
  {
    trackop(insn.Op3, rS);
// #ifdef _DEBUG
    msg("9pi2: %a rS3 %d\n", insn.ea, insn.Op3.reg);
// #endif
    return true;
  } else if ( same_value(insn.Op3, rBase) )
  {
    trackop(insn.Op2, rS);
// #ifdef _DEBUG
    msg("9pi2: %a rS2 %d\n", insn.ea, insn.Op2.reg);
// #endif
    return true;
  } else
    return false;
}

// alsl.d rS, rIdx2, r0, size
bool loongson_jump_pattern9ops::is_alsl0()
{
  if ( insn.itype != Loong_alsl_d || !same_value(insn.Op1, rS) || insn.Op3.reg )
    return false;
// #ifdef _DEBUG
  msg("9pi3: %a\n", insn.ea);
// #endif
  trackop(insn.Op2, rIdx2); 
  si->set_jtable_element_size(1 << insn.Op4.value);
  return true;
}

// bstrpick rIdx2, rIdx
bool loongson_jump_pattern9ops::is_bstrpick()
{
  if ( (insn.itype != Loong_bstrpick_w && insn.itype != Loong_bstrpick_d) || !same_value(insn.Op1, rIdx2) )
    return false;
// #ifdef _DEBUG
  msg("9pi4: %a\n", insn.ea);
// #endif
  trackop(insn.Op2, rIdx); 
  return true;
}

// addi.d rBase, rBase2, offset
bool loongson_jump_pattern9ops::is_addi()
{
  if ( insn.itype != Loong_addi_d || !same_value(insn.Op1, rBase) )
    return false;
// #ifdef _DEBUG
  msg("9pi5: %a\n", insn.ea);
// #endif
  trackop(insn.Op2, rBase2); 
  add_off = insn.Op3.value;
  return true;
}

// pcadduXXi rBase2, base
bool loongson_jump_pattern9ops::is_pcadduXXi()
{
  if ( !same_value(insn.Op1, rBase2) )
    return false;
  if ( !is_pcadd(insn.itype) )
    return false;
  // ok, we finally have address of table
  si->jumps = add_off + pcadd(insn.itype, insn.ea, insn.Op2.value);
  si->set_elbase(si->jumps);
// #ifdef _DEBUG
  msg("9pi6: %a jumps %a\n", insn.ea, si->jumps);
// #endif
  return true;
}

// bltu rMax, rIdx default addr
bool loongson_jump_pattern9ops::is_bxx()
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
  si->defjump = insn.Op3.addr;
  return true;
}

// mov rMax, imm
bool loongson_jump_pattern9ops::is_rimm()
{
 if ( insn.itype != Loong_mov || !same_value(insn.Op1, rMax) )
   return false;
 auto jsize = insn.Op2.value;
 if ( !is_ge )
   jsize++;
 si->set_jtable_size(jsize);
 si->flags |= SWI_SIGNED;
 si->startea = insn.ea;
msg("9pi9: %a jumps %a size %d elsize %d\n", insn.ea, si->jumps, si->get_jtable_size(), si->get_jtable_element_size());
 return true;
}

bool loongson_jump_pattern9ops::handle_mov(tracked_regs_t &_regs)
{
  if ( insn.itype != Loong_mov
    && insn.Op1.type != o_reg
    && insn.Op2.type != o_reg )
  {
    return false;
  }
  return set_moved(insn.Op2, insn.Op1, _regs);
}

bool loongson_jump_pattern9ops::finish()
{
#ifdef _DEBUG
  msg("finish: %a\n", eas[8]);
#endif
  return eas[8] != BADADDR;
}

// 0) ret regA
bool loongson_jump_pattern_t::is_ret(void)
{
  if ( insn.itype != Loong_jirl )
    return false;
  trackop(insn.Op2, regA);
  return true;
}

// add.d regA, rBase, regA
bool loongson_jump_pattern_t::is_add_base(void)
{
  if ( insn.itype != Loong_add_d || !same_value(insn.Op1, regA) )
    return false;
#ifdef _DEBUG
  msg("jpi1: %a\n", insn.ea);
#endif
  if ( same_value(insn.Op3, regA) )
    trackop(insn.Op2, rBase);
  else if ( same_value(insn.Op2, regA) )
    trackop(insn.Op3, rBase);
  else
    return false;
  return true;
}

// add.d regA, regA, rJ
bool loongson_jump_pattern_t::is_add(void)
{
  if ( insn.itype != Loong_add_d || !same_value(insn.Op1, regA) || !same_value(insn.Op2, regA) )
    return false;
#ifdef _DEBUG
  msg("jpi1: %a\n", insn.ea);
#endif
  trackop(insn.Op3, rJ);
  return true;
}

// ldptr.d rJ, rS, 0
bool loongson_jump_pattern_t::is_ldptr(void)
{
  if ( insn.itype != Loong_ldptr_d || (!same_value(insn.Op1, rJ) && !same_value(insn.Op1, regA)) )
    return false;
#ifdef _DEBUG
  msg("jpi2: %a\n", insn.ea);
#endif
  trackop(insn.Op2, rS); 
  return true;
}

// alsl.d rS, rBase, rIdx, size
bool loongson_jump_pattern_t::is_alsl_base(void)
{
  if ( insn.itype != Loong_alsl_d || !same_value(insn.Op1, rS) )
    return false;
#ifdef _DEBUG
  msg("jpi3: %a\n", insn.ea);
#endif
  trackop(insn.Op3, rIdx); 
  trackop(insn.Op2, rBase); 
  si->set_jtable_element_size(1 << insn.Op4.value);
  return true;
}

// alsl.d rS, rIdx, rBase, size
bool loongson_jump_pattern_t::is_alsl(void)
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
bool loongson_jump_pattern_t::is_addi(void)
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
bool loongson_jump_pattern_t::is_pcadduXXi(void)
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
bool loongson_jump_pattern_t::is_bxx(void)
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
bool loongson_jump_pattern_t::is_rimm(void)
{
 if ( insn.itype != Loong_mov || !same_value(insn.Op1, rMax) )
   return false;
 auto jsize = insn.Op2.value;
 if ( !is_ge )
   jsize++;
 si->set_jtable_size(jsize);
 si->flags |= SWI_SIGNED;
 si->startea = insn.ea;
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

template <typename T>
static int is_jump_pattern(switch_info_t *si, const insn_t &insn, procmod_t *pm)
{
  T jp(si);
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
    is_jump_pattern<loongson_jump_pattern_t1>,
    is_jump_pattern<loongson_jump_pattern_t2>,
    is_jump_pattern<loongson_jump_pattern_t3>,
    is_jump_pattern<loongson_jump_pattern_t4>,
  };
  return check_for_table_jump(si, insn, patterns, qnumber(patterns));
}