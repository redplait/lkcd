#include "arm64_disasm.h"
#include "cf_graph.h"

// check if current instruction is jmp jimm
int arm64_disasm::is_b_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_B && m_dis.cc == AD_NONE && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM )
  {
    addr = uconv(m_dis.operands[0].op_imm.bits);
    return 1;
  } else
    return 0;
}

int arm64_disasm::is_tbz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_TBZ && m_dis.num_operands == 3 && m_dis.operands[2].type == AD_OP_IMM )
  {
    addr = uconv(m_dis.operands[2].op_imm.bits);
    return 1;
  }
  return 0;
}

int arm64_disasm::is_tbnz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_TBNZ && m_dis.num_operands == 3 && m_dis.operands[2].type == AD_OP_IMM )
  {
    addr = uconv(m_dis.operands[2].op_imm.bits);
    return 1;
  }
  return 0;
}

int arm64_disasm::is_cbz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_CBZ && m_dis.num_operands == 2 && m_dis.operands[1].type == AD_OP_IMM )
  {
    addr = uconv(m_dis.operands[1].op_imm.bits);
    return 1;
  }
  return 0;
}

int arm64_disasm::is_cbnz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_CBNZ && m_dis.num_operands == 2 && m_dis.operands[1].type == AD_OP_IMM )
  {
    addr = uconv(m_dis.operands[1].op_imm.bits);
    return 1;
  }
  return 0;
}

int arm64_disasm::is_bxx_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_B && m_dis.cc != AD_NONE && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM )
  {
    addr = uconv(m_dis.operands[0].op_imm.bits);
    return 1;
  } else
    return 0;
}

// check if current instruction is call jimm
int arm64_disasm::is_bl_jimm(a64 &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_BL && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM )
  {
    addr = (a64)m_dis.operands[0].op_imm.bits;
    return 1;
  } else
    return 0;
}

int arm64_disasm::is_adr() const
{
  return (m_dis.instr_id == AD_INSTR_ADR) && 
         (m_dis.num_operands == 2) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_IMM)
  ;
}

int arm64_disasm::is_adrp() const
{
  return (m_dis.instr_id == AD_INSTR_ADRP) && 
         (m_dis.num_operands == 2) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_IMM)
  ;
}

int arm64_disasm::is_add() const
{
  return (m_dis.instr_id == AD_INSTR_ADD) && 
         (m_dis.num_operands == 3) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_IMM)
  ;
}

int arm64_disasm::is_ldr_lsl() const
{
  return (m_dis.instr_id == AD_INSTR_LDR) && 
         (m_dis.num_operands == 4) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_REG) &&
         (m_dis.operands[3].type == AD_OP_IMM)
  ;
}

int arm64_disasm::is_ldr0() const
{
  return (m_dis.instr_id == AD_INSTR_LDR) && 
         (m_dis.num_operands == 2) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG)
  ;
}

int arm64_disasm::is_ldr() const
{
  return (m_dis.instr_id == AD_INSTR_LDR) && 
         (m_dis.num_operands == 3) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_IMM)
  ;
}

int arm64_disasm::disasm()
{
  if ( m_psp + 4 >= (PBYTE)(m_text + m_text_size) )
    return 0;
  a64 addr = conv(m_psp);
  if ( ArmadilloDisassemble(*(unsigned int *)m_psp, (a64)addr, &m_dis) )
    return 0;
#ifdef _DEBUG
  printf("%I64X: %s\n", addr, m_dis.decoded);
#endif
  m_psp += 4;
  if ( (m_dis.instr_id == AD_INSTR_UDF) ||
       (m_dis.instr_id == AD_INSTR_BRK)
     )
    return 0;
  return 1;  
}

a64 arm64_disasm::process_bpf_target(a64 addr, a64 mlock)
{
  PBYTE psp = uconv(addr);
  regs_pad regs;
  int state = 0;
  if ( !setup(psp) )
    return 0;
  for ( size_t i = 0; i < 100 ; i++ )
  {
    if ( !disasm() || is_ret() )
      break;
    if ( is_adrp(regs) )
      continue;
    if ( is_adr(regs) )
      continue;
    if ( is_add() )
    {
      regs.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      continue;
    }
    // mov reg, reg
    if ( is_mov_rr(regs) )
      continue;
    a64 tmp = 0;
    if ( !state && is_bl_jimm(tmp) )
    {
      if ( tmp == mlock )
        state++;
      continue;
    }
    // ldr reg
    if ( state && (is_ldr() || is_ldr0()) )
    {
      regs.ldar(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      a64 what = regs.get(get_reg(0));
      if ( what && in_data(what) )
        return what;
    }
  }
  return 0;
}

int arm64_disasm::process_sl(lsm_hook &sl)
{
  PBYTE psp = uconv(sl.addr);
  regs_pad regs;
  if ( !setup(psp) )
    return 0;
  for ( size_t i = 0; i < 100 ; i++ )
  {
    if ( !disasm() || is_ret() )
      break;
    if ( is_adrp(regs) )
      continue;
    if ( is_adr(regs) )
      continue;
    if ( is_ldr() )
    {
      regs.ldar(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      a64 what = regs.get(get_reg(0));
      if ( what && is_sec_heads(what) )
      {
        sl.list = what;
        return 1;
      }
    }
  }
  return 0;
}

int arm64_disasm::process_trace_remove_event_call(a64 addr, a64 free_event_filter)
{
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  PBYTE psp = uconv(addr);
  addr_list.push_back(psp);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
     for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
     {
       psp = *iter;
       if ( cgraph.in_ranges(psp) )
          continue;
       if ( !setup(psp) )
         continue;
       regs_pad regs;
#ifdef _DEBUG
       printf("%d - branch %p\n", edge_gen, (void *)psp);
#endif /* _DEBUG */
       for ( ; ;  )
       {
         if ( !disasm() || is_ret() )
            break;
         if ( check_jmps_stateless(cgraph) )
            continue;
         if ( is_ldr_off() )
         {
           regs.adrp(get_reg(0), m_dis.operands[2].op_imm.bits);
           continue;
         }
         // check call jimm
         a64 tmp = 0;
         if ( is_bl_jimm(tmp) && (tmp == free_event_filter))
         {
           a64 what = regs.get(AD_REG_X0);
           return (int)what;
         }
       }
       cgraph.add_range(psp, m_psp - psp);
     }
     // prepare for next edge generation
     edge_gen++;
     if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
       break;
  }
  return 0;
}

int arm64_disasm::process(a64 addr, std::map<a64, a64> &skip, std::set<a64> &out_res)
{
  statefull_graph<PBYTE, regs_pad> cgraph;
  std::list<std::pair<PBYTE, regs_pad> > addr_list;
  regs_pad tmp;
  PBYTE psp = uconv(addr);
  addr_list.push_back(std::make_pair(psp, tmp));
  int edge_gen = 0;
  int edge_n = 0;
  int res = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
    {
      psp = iter->first;
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
#ifdef _DEBUG
      printf("branch %lX:\n", conv(psp));
      iter->second.dump();
#endif /* _DEBUG */
      for ( size_t i = 0; i < 10000 ; i++ )
      {
//        if (conv(m_psp) == 0xFFFFFFC01066BAD0)
//          printf("r");
         if ( !disasm() || is_ret() )
            break;
         if ( is_adrp(iter->second) )
            continue;
         if ( is_adr(iter->second) )
            continue;
         if ( check_jmps(cgraph, iter->second) )
            continue;
         a64 tmp = 0;
         if ( is_bl_jimm(tmp) )
         {
           if ( is_noret(tmp) )
             break;
           // zero x0 after call
           iter->second.zero(AD_REG_X0);
           continue;
         }
         PBYTE b_addr = NULL;
         if ( is_b_jimm(b_addr) )
         {
            cgraph.add(b_addr, iter->second);
            break;
         }
         if ( is_ldpsw(iter->second) )
           continue;
         if ( is_mov_rim(iter->second) )
           continue;
         if ( is_ldraa(iter->second) )
           continue;
         if ( is_ldr_lsl() )
         {
           iter->second.zero(get_reg(0));
           continue;
         }
         if ( is_ldr() )
         {
           iter->second.ldar(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
           continue;
         }
         // mov reg, reg
         if ( is_mov_rr(iter->second) )
           continue;
         // check for add
         if ( is_add() )
         {
           iter->second.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
           continue;
         }
         if ( is_add_r(iter->second) )
           continue;
         // blr
         if ( is_bl_reg() )
         {
           a64 what = iter->second.get(get_reg(0));
           if ( !what )
             continue;
           if ( in_data(what) )
           {
             auto was = skip.find(what);
             if ( was == skip.end() )
             {
#ifdef _DEBUG
               if (what == 0xFFFFFFC01147EB90)
                 printf("gy");
#endif /* _DEBUG */
               out_res.insert(what);
               res++;
             }
           }
           continue;
         }
      }
      cgraph.add_range(psp, m_psp - psp);
    }
   // prepare for next edge generation
   edge_gen++;
   if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
     break;
  }
  return res;
}