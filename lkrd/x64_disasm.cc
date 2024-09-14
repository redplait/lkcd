#include "x64_disasm.h"
#include "cf_graph.h"

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

int x64_disasm::is_cjimm(a64 &addr) const
{
  if ( (ud_obj.mnemonic == UD_Icall) &&
       (ud_obj.operand[0].type == UD_OP_JIMM) )
  {
    addr = ud_obj.pc + ud_obj.operand[0].lval.sdword;
    return 1;
  }
  return 0;
}

int x64_disasm::is_jxx_jimm() const
{
  if ( !is_jmp() )
    return 0;
  return (ud_obj.operand[0].type == UD_OP_JIMM);
}

int x64_disasm::find_return_notifier_list(a64 addr)
{
  used_regs<a64> regs;
  if ( !set(addr) )
    return 0;
  for ( int i = 0; i < 20; i++ )
  {
    if ( !ud_disassemble(&ud_obj) )
      return 0;
#ifdef _DEBUG
    printf("%p %s (I: %d size %d, II: %d size %d)\n", (void *)ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj),
      ud_obj.operand[0].type, ud_obj.operand[0].size,
      ud_obj.operand[1].type, ud_obj.operand[1].size
    );
#endif /* _DEBUG */
    if ( is_end() )
      break;
    // mov reg, imm
    if ( (ud_obj.mnemonic == UD_Imov) &&
         (ud_obj.operand[0].type == UD_OP_REG) &&
         (ud_obj.operand[1].type == UD_OP_IMM)
       )
    {
      regs.add(ud_obj.operand[0].base, ud_obj.operand[1].lval.udword);
      continue;
    }
    // add reg, [gs:xxx]
    if ( is_rmem(UD_Iadd) &&
         (ud_obj.pfx_seg == UD_R_GS)
       )
    {
      m_this_cpu_off = ud_obj.pc + (sa64)ud_obj.operand[1].lval.sdword;
      a64 v = 0;
      int tmp = regs.asgn(ud_obj.operand[0].base, v);
      m_return_notifier_list = v;
      return tmp;
    }
  }
  return 0;
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

a64 x64_disasm::process_bpf_target(a64 addr, a64 mlock)
{
  int state = 0;
  if ( !set(addr) )
    return 0;
  for ( ; ; )
  {
    if ( !ud_disassemble(&ud_obj) )
      break;
    if ( is_end() )
      break;
    a64 caddr;
    // check for call mutex_lock
    if ( !state && is_cjimm(caddr) )
    {
      if ( caddr == mlock )
        state = 1;
      continue;
    }
    // mov reg, [rip + mem]
    if ( state && is_mrip(UD_Imov) &&
         (ud_obj.operand[0].type == UD_OP_REG) &&
         (ud_obj.operand[0].size == 64)
       )
    {
      a64 daddr = ud_obj.pc + (sa64)ud_obj.operand[1].lval.sdword;
      if ( in_data(daddr) )
        return daddr;
      break;
    }
  }
  return 0;
}

int x64_disasm::is_mem(ud_mnemonic_code c, int idx) const
{
  return (ud_obj.mnemonic == c) &&
         (ud_obj.operand[idx].type == UD_OP_MEM)
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

int x64_disasm::find_kmem_cache_name(a64 addr, a64 kfree_const)
{
  if ( !set(addr) )
    return 0;
  used_regs<int> regs;
  for ( ; ;  )
  {
    if ( !ud_disassemble(&ud_obj) )
      break;
    if ( is_end() )
      break;
    if ( is_rmem(UD_Imov) )
    {
      regs.add(ud_obj.operand[0].base, ud_obj.operand[1].lval.sdword);
      continue;
    }
    a64 caddr;
    if ( is_cjimm(caddr) && caddr == kfree_const )
    {
      int res = 0;
      regs.asgn(UD_R_RDI, res);
      return res;
    }
  }
  return 0;
}

int x64_disasm::get_neg_off(int idx) const
{
  switch(ud_obj.operand[idx].offset)
  {
    case 8: return -ud_obj.operand[1].lval.sbyte;
    case 16: return -ud_obj.operand[1].lval.sword;
    case 32: return -ud_obj.operand[1].lval.sdword;
  }
  return 0;
}

int x64_disasm::is_neg_off(int idx) const
{
  switch(ud_obj.operand[idx].offset)
  {
    case 8: return ud_obj.operand[1].lval.sbyte < 0;
    case 16: return ud_obj.operand[1].lval.sword < 0;
    case 32: return ud_obj.operand[1].lval.sdword < 0;
  }
  return 0;
}

int x64_disasm::find_kmem_cache_next(a64 addr)
{
  if ( !set(addr) )
    return 0;
  for ( ; ;  )
  {
    if ( !ud_disassemble(&ud_obj) )
      break;
    if ( is_end() )
      break;
    // check lea rxx, [rsi-xx], rsi - second arg
    if ( is_rmem(UD_Ilea) && ud_obj.operand[1].base == UD_R_RSI && is_neg_off(1) )
      return get_neg_off(1);
  }
  return 0;
}

int x64_disasm::find_kmem_cache_ctor(a64 addr, int &flag_off)
{
  flag_off = 0;
  if ( !set(addr) )
    return 0;
  int state = 0;
  for ( ; ;  )
  {
    if ( !ud_disassemble(&ud_obj) )
      break;
    if ( is_end() )
      break;
    if ( !state && is_mem(UD_Itest, 0) )
    {
      state = 1;
      flag_off = ud_obj.operand[0].lval.sdword;
      continue;
    }
    if ( state && is_mem(UD_Icmp, 0) )
      return ud_obj.operand[0].lval.sdword;
  }
  return 0;
}

int x64_disasm::process_sl(lsm_hook &sl)
{
  if ( !set(sl.addr) )
    return 0;
  for ( ; ;  )
  {
    if ( !ud_disassemble(&ud_obj) )
      break;
    if ( is_end() )
      break;
    // mov reg, [mem + rip]
    if ( is_mrip(UD_Imov) &&
         (ud_obj.operand[0].type == UD_OP_REG) &&
         (ud_obj.operand[0].size == 64)
       )
    {
      a64 addr = ud_obj.pc + (sa64)ud_obj.operand[1].lval.sdword;
      if ( is_sec_heads(addr) )
      {
        sl.list = addr;
        return 1;
      }
    }
  }
  return 0;
}

int x64_disasm::process_trace_remove_event_call(a64 addr, a64 free_event_filter)
{
  cf_graph<a64> cgraph;
  std::list<a64> addr_list;
  addr_list.push_back(addr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
     for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
     {
       a64 psp = *iter;
       if ( cgraph.in_ranges(psp) )
          continue;
       if ( !set(psp) )
         continue;
       used_regs<int> regs;
#ifdef _DEBUG
       printf("%d - branch %p\n", edge_gen, (void *)psp);
#endif /* _DEBUG */
       for ( ; ;  )
       {
         if ( !ud_disassemble(&ud_obj) )
           break;
#ifdef _DEBUG
         printf("%p %s (I: %d size %d, II: %d size %d)\n", (void *)ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj),
          ud_obj.operand[0].type, ud_obj.operand[0].size,
          ud_obj.operand[1].type, ud_obj.operand[1].size
         );
#endif /* _DEBUG */
         // check jmp
         if ( is_jxx_jimm() )
         {
           a64 jaddr = ud_obj.pc;
           switch (ud_obj.operand[0].size)
           {
             case 8: jaddr += ud_obj.operand[0].lval.sbyte;
              break;
             case 16: jaddr += ud_obj.operand[0].lval.sword;
              break;
             case 32: jaddr += ud_obj.operand[0].lval.sdword;
              break;
           }
#ifdef _DEBUG
           printf("add branch at %p\n", (void *)jaddr);
#endif /* _DEBUG */
           cgraph.add(jaddr);
         }
         if ( is_end() )
          break;
         // check call jimm
         if ( (ud_obj.mnemonic == UD_Icall) &&
              (ud_obj.operand[0].type == UD_OP_JIMM)
            )
         {
            a64 addr = ud_obj.pc + ud_obj.operand[0].lval.sdword;
            if ( addr == free_event_filter )
            {
              int res = 0;
              regs.asgn(UD_R_RDI, res);
              return res;
            }
            continue;
         }
         // mov reg, [mem]
         if ( is_rmem(UD_Imov) &&
              (ud_obj.operand[0].size == 64) &&
              (ud_obj.operand[1].base != UD_R_RIP)
            )
         {
           regs.add(ud_obj.operand[0].base, ud_obj.operand[1].lval.sdword);
           continue;
         }
       }
       cgraph.add_range(psp, ud_obj.pc - psp);
     }
     // prepare for next edge generation
     edge_gen++;
     if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
       break;
  }
  return 0;
}

int x64_disasm::process(a64 addr, std::map<a64, a64> &skip, std::set<a64> &out_res)
{
  using Regs = used_regs<a64>;
  statefull_graph<a64, Regs> cgraph;
  std::list<std::pair<a64, Regs> > addr_list;
  Regs regs;
  auto curr = std::make_pair(addr, regs);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  int res = 0;
#ifdef _DEBUG
  printf("UD_OP_MEM: %d\n", UD_OP_MEM);
#endif
  while( edge_gen < 100 )
  {
     for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
     {
       a64 psp = iter->first;
       if ( cgraph.in_ranges(psp) )
          continue;
       if ( !set(psp) )
         continue;
#ifdef _DEBUG
       printf("%d - branch %p\n", edge_gen, (void *)psp);
#endif /* _DEBUG */
       for ( ; ;  )
       {
         if ( !ud_disassemble(&ud_obj) )
           break;
#ifdef _DEBUG
         printf("%p %s (I: %d size %d, II: %d size %d)\n", (void *)ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj),
          ud_obj.operand[0].type, ud_obj.operand[0].size,
          ud_obj.operand[1].type, ud_obj.operand[1].size
         );
#endif /* _DEBUG */
         // check jmp
         if ( is_jxx_jimm() )
         {
           a64 jaddr = ud_obj.pc;
           switch (ud_obj.operand[0].size)
           {
             case 8: jaddr += ud_obj.operand[0].lval.sbyte;
              break;
             case 16: jaddr += ud_obj.operand[0].lval.sword;
              break;
             case 32: jaddr += ud_obj.operand[0].lval.sdword;
              break;
           }
#ifdef _DEBUG
           printf("add branch at %p\n", (void *)jaddr);
#endif /* _DEBUG */
           cgraph.add(jaddr, iter->second);
         }
         if ( is_end() )
          break;
         // mov reg, [rip + xxx]
         if ( is_rmem(UD_Imov) &&
              (ud_obj.operand[0].size == 64) &&
              (ud_obj.operand[1].base == UD_R_RIP)
            )
         {
           a64 addr = ud_obj.pc + (sa64)ud_obj.operand[1].lval.sdword;
           if (in_data(addr))
             iter->second.add(ud_obj.operand[0].base, addr);
           else
             iter->second.erase(expand_reg(0));
           continue;
         }
         // check lea/pop reg
         if ( ((ud_obj.mnemonic == UD_Ilea) || (ud_obj.mnemonic == UD_Ipop)) &&
              (ud_obj.operand[0].type == UD_OP_REG)
            )
         {
           iter->second.erase(ud_obj.operand[0].base);
           continue;
         }
         // check mov reg
         if ( (ud_obj.mnemonic == UD_Imov) &&
              (ud_obj.operand[0].type == UD_OP_REG)
            )
         {
           if ( ud_obj.operand[1].type == UD_OP_REG )
             iter->second.mov(ud_obj.operand[1].base, ud_obj.operand[0].base);
           else
             iter->second.erase(expand_reg(0));
           continue;
         }
         // check call reg
         if ( (ud_obj.mnemonic == UD_Icall) &&
              (ud_obj.operand[0].type == UD_OP_REG)
            )
         {
           a64 tmp = 0;
           if ( iter->second.asgn(ud_obj.operand[0].base, tmp) && tmp )
           {
             auto was = skip.find(tmp);
             if ( was == skip.end() )
             {
               out_res.insert(tmp);
               res++;
             }
           }
         }
         // check call [rip + xxx]
         if ( (ud_obj.mnemonic == UD_Icall) &&
              (ud_obj.operand[0].type == UD_OP_MEM) && 
              (ud_obj.operand[0].base == UD_NONE)
            )
         {
           a64 addr = (ud_obj.pc & 0xffffffff00000000) + ud_obj.operand[0].lval.udword;
           if ( in_data(addr) )
           {
             auto was = skip.find(addr);
             if ( was == skip.end() )
             {
               out_res.insert(addr);
               res++;
             }
           }
         }
         // check call jimm
         if ( (ud_obj.mnemonic == UD_Icall) &&
              (ud_obj.operand[0].type == UD_OP_JIMM)
            )
         {
            a64 addr = ud_obj.pc + ud_obj.operand[0].lval.sdword;
            auto reg = check_thunk(addr);
            if ( reg != UD_NONE )
            {
              a64 tmp = 0;
              if ( iter->second.asgn(reg, tmp) && tmp )
              {
#ifdef _DEBUG
                if (0xFFFFFFFF826B9A08 == tmp)
                  printf("gotcha\n");
#endif /* _DEBUG */
                auto was = skip.find(tmp);
                if ( was == skip.end() )
                {
                  out_res.insert(tmp);
                  res++;
                }
              }
            }
         }
       }
       cgraph.add_range(psp, ud_obj.pc - psp);
     }
     // prepare for next edge generation
     edge_gen++;
     if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
       break;
  }
  return res;
}

int x64_jit_nops::skip(const char *body, unsigned long len)
{
   ud_init(&ud_obj);
   ud_set_mode(&ud_obj, 64);
   ud_set_input_buffer(&ud_obj, (uint8_t *)body, len);
   ud_set_pc(&ud_obj, (uint64_t)body);
   int curr_len, total = 0;
   for ( ; total < len; total += curr_len )
   {
     curr_len = ud_disassemble(&ud_obj);
     if ( !curr_len )
       return 0;
     if ( ud_obj.mnemonic == UD_Inop )
       continue;
     return total + curr_len;
   }
   return total;
}
