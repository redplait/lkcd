#pragma once
#include "dis_base.h"
#include "armadillo.h"
#include <algorithm>
#include <cstring>

// register scratchpad class
#ifdef _MSC_VER
typedef __int64  reg64_t;
#else
typedef long  reg64_t;
#endif /* _MSC_VER */

struct arm_reg
{
  reg64_t val;
  int ldr;

  arm_reg()
   : val(0),
     ldr(0)
   { }
  void reset()
  {
    val = 0;
    ldr = 0;
  }
};

class regs_pad
{
  public:
   regs_pad()
   {
     memset(m_regs, 0, sizeof(m_regs));
   }
   void reset()
   {
     memset(m_regs, 0, sizeof(m_regs));
   }
   bool operator<(const regs_pad& s) const
   {
     auto my = std::count_if(m_regs, m_regs + AD_REG_SP, [](const arm_reg &l) -> bool { return l.val != 0; });
     auto their = std::count_if(s.m_regs, s.m_regs + AD_REG_SP, [](const arm_reg &l) -> bool { return l.val != 0; });
     return (my < their);
   }
   // http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0802a/ADRP.html
   void adrp(int reg, reg64_t val)
   {
     if ( reg >= AD_REG_SP ) // hm
       return;
     m_regs[reg].val = val;
   }
   // http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0802a/a64_general_alpha.html
   reg64_t add(int reg1, int reg2, reg64_t val)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     if ( !m_regs[reg2].val )
       return 0;
     if ( m_regs[reg1].ldr )
     {
       m_regs[reg1].reset();
       return 0;
     }
     m_regs[reg1].val = m_regs[reg2].val + val;
     if ( reg1 != reg2 )
       m_regs[reg2].reset();
     return m_regs[reg1].val;
   }
   reg64_t add2(int reg1, int reg2, reg64_t val)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     if ( !m_regs[reg2].val )
       return 0;
     m_regs[reg1].val = m_regs[reg2].val + val;
     return m_regs[reg1].val;
   }
   int mov(int reg1, int reg2)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     if ( !m_regs[reg2].val )
       return 0;
     m_regs[reg1] = m_regs[reg2];
     return 1;
   }
   int ldar(int reg1, int reg2, reg64_t val)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     if ( m_regs[reg2].ldr )
     {
       m_regs[reg1].val = 0;
       return 0;
     }
     m_regs[reg1].val = m_regs[reg2].val + val;
     m_regs[reg1].ldr = 1;
     return 1;
   }
   inline reg64_t get(int reg)
   {
     if ( reg >= AD_REG_SP ) // hm
       return 0;
     return m_regs[reg].val;
   }
   inline void zero(int reg)
   {
     if ( reg >= AD_REG_SP ) // hm
       return;
     m_regs[reg].reset();
   }
#ifdef _DEBUG
   void dump() const
   {
     for ( int i = 0; i < AD_REG_SP; i++ )
     {
       if ( !m_regs[i].val )
         continue;
       printf("x%d %I64X %d\n", i, m_regs[i].val, m_regs[i].ldr);
     }
   }
#endif /* _DEBUG */
  protected:
   arm_reg m_regs[AD_REG_SP];
};

class arm64_disasm: public dis_base
{
  public:
    arm64_disasm(a64 text_base, size_t text_size, const char *text, a64 data_base, size_t data_size)
     : dis_base(text_base, text_size, text, data_base, data_size)
    {
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
    virtual ~arm64_disasm() = default;
  protected:
    int disasm();
    // Branch to Register, with pointer authentication
    // details https://developer.arm.com/documentation/dui0801/l/A64-General-Instructions/BRAA--BRAAZ--BRAB--BRABZ--A64-?lang=en
    inline int is_braa() const
    {
      return (m_dis.instr_id == AD_INSTR_BRAA) ||
       (m_dis.instr_id == AD_INSTR_BRAAZ) ||
       (m_dis.instr_id == AD_INSTR_BRAB) ||
       (m_dis.instr_id == AD_INSTR_BRABZ)
      ;
    }
    template <typename T>
    int check_jmps_stateless(T &graph)
    {
      PBYTE addr = NULL;
      if ( is_cbnz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_cbz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_tbz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_tbnz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_bxx_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      return 0;
    }
    template <typename T, typename S>
    int check_jmps(T &graph, S state)
    {
      PBYTE addr = NULL;
      if ( is_cbnz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_cbz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_tbz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_tbnz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_bxx_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      return 0;
    }
    // some shortcuts methods
    inline int get_reg(int idx) const
    {
      return m_dis.operands[idx].op_reg.rn;
    }
    inline size_t get_reg_size(int idx) const
    {
      return m_dis.operands[idx].op_reg.sz;
    }
    int is_adrp() const;
    int is_adr() const;
    inline int is_adr(regs_pad &used_regs) const
    {
      if ( !is_adr() )
        return 0;
      used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
      return 1;
    }
    int is_add() const;
    // must be called after is_add
    inline int is_add_r() const
    {
      return (m_dis.instr_id == AD_INSTR_ADD) && (m_dis.operands[0].type == AD_OP_REG);
    }
    inline int is_add_r(regs_pad &used_regs) const
    {
      if ( !is_add_r() )
        return 0;
      used_regs.zero(get_reg(0));
      return 1;
    }
    inline int is_adrp(regs_pad &used_regs) const
    {
      if ( !is_adrp() )
        return 0;
      used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
      return 1;
    }
    inline int is_mov_rr() const
    {
      return (m_dis.instr_id == AD_INSTR_MOV && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_REG);
    }
    inline int is_mov_rimm() const
    {
      return (m_dis.instr_id == AD_INSTR_MOV && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_IMM);
    }
    inline int is_dst_reg() const
    {
      if ( m_dis.operands[0].type != AD_OP_REG )
        return 0;
      switch(m_dis.instr_id)
      {
        case AD_INSTR_LDTR:
        case AD_INSTR_LDTRB:
        case AD_INSTR_LDTRH:
        case AD_INSTR_LDRSW:
        case AD_INSTR_LDRSH:
        case AD_INSTR_LDAR:
        case AD_INSTR_LDARB:
        case AD_INSTR_LDARH:
        case AD_INSTR_LDRB:
        case AD_INSTR_LDRSB:
        case AD_INSTR_LDRH:
        case AD_INSTR_LDP:
        case AD_INSTR_LDUR:
        case AD_INSTR_LDURB:
        case AD_INSTR_LDURH:
        case AD_INSTR_LDURSW:
        case AD_INSTR_ADRP:
        case AD_INSTR_EON:
        case AD_INSTR_EOR:
        case AD_INSTR_ORR:
        case AD_INSTR_ORN:
        case AD_INSTR_AND:
        case AD_INSTR_ANDS:
        case AD_INSTR_MSUB:
        case AD_INSTR_SUB:
        case AD_INSTR_UMSUBL:
        case AD_INSTR_SUBS:
        case AD_INSTR_MOVK:
        case AD_INSTR_MADD:
        case AD_INSTR_ADDS:
        case AD_INSTR_ADC:
        case AD_INSTR_ADCS:
        case AD_INSTR_CMN:
        case AD_INSTR_STADD:
        case AD_INSTR_UMADDL:
        case AD_INSTR_SMADDL:
        case AD_INSTR_UDIV:
        case AD_INSTR_SDIV:
        case AD_INSTR_MUL:
        case AD_INSTR_UMULL:
        case AD_INSTR_UMULH:
        case AD_INSTR_SMULL:
        case AD_INSTR_SMULH:
        case AD_INSTR_SBFX:
        case AD_INSTR_SXTW:
        case AD_INSTR_SXTB:
        case AD_INSTR_SXTH:
        case AD_INSTR_CSEL:
        case AD_INSTR_MRS:
        case AD_INSTR_LSL:
        case AD_INSTR_LSLV:
        case AD_INSTR_LSR:
        case AD_INSTR_LSRV:
        case AD_INSTR_CSET:
        case AD_INSTR_CSETM:
        case AD_INSTR_UBFIZ:
        case AD_INSTR_SBFIZ:
        case AD_INSTR_BIC:
        case AD_INSTR_ASR:
        case AD_INSTR_ASRV:
        case AD_INSTR_BFI:
        case AD_INSTR_CNEG:
        case AD_INSTR_NEG:
        case AD_INSTR_NEGS:
        case AD_INSTR_CSNEG:
        case AD_INSTR_CSINC:
        case AD_INSTR_CINC:
        case AD_INSTR_CSINV:
        case AD_INSTR_CINV:
        case AD_INSTR_UBFX:
        case AD_INSTR_BFXIL:
        case AD_INSTR_ROR:
        case AD_INSTR_MVN:
        case AD_INSTR_CLS:
        case AD_INSTR_CLZ:
        case AD_INSTR_RBIT:
        case AD_INSTR_REV:
        case AD_INSTR_REV16:
        case AD_INSTR_EXTR:
        case AD_INSTR_LDADDAL:
        case AD_INSTR_LDADDL:
         return 1;
      }
      return 0;
    }
    inline int is_mov_rim(regs_pad &used_regs) const
    {
      if ( !is_mov_rimm() && !is_dst_reg() )
        return 0;
      used_regs.zero(get_reg(0));
      return 1;
    }
    inline int is_mov_rr(regs_pad &used_regs) const
    {
      if ( !is_mov_rr() )
        return 0;
      return used_regs.mov(get_reg(0), get_reg(1));
    }
    inline int is_ldpsw(regs_pad &used_regs) const
    {
      if ( m_dis.instr_id == AD_INSTR_LDPSW || m_dis.instr_id == AD_INSTR_LDP)
      {
        used_regs.zero(get_reg(0));
        used_regs.zero(get_reg(1));
        return 1;
      }
      return 0;
    }
    inline int is_ldr_off() const
    {
      return ( (m_dis.instr_id == AD_INSTR_LDRAA || m_dis.instr_id == AD_INSTR_LDRAB || m_dis.instr_id == AD_INSTR_LDR)
               && m_dis.num_operands == 3 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_REG
             );
    }
    inline int is_ldraa() const
    {
      return ( (m_dis.instr_id == AD_INSTR_LDRAA || m_dis.instr_id == AD_INSTR_LDRAB || m_dis.instr_id == AD_INSTR_LDR)
               && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_REG
             );
    }
    inline int is_ldraa(regs_pad &used_regs) const
    {
      if ( is_ldraa() )
      {
        used_regs.zero(get_reg(0));
        used_regs.zero(get_reg(1));
        return 1;
      }
      return 0;
    }
    inline int is_ret() const
    {
      return (m_dis.instr_id == AD_INSTR_RET);
    }
    int is_b_jimm(PBYTE &addr) const;
    int is_bxx_jimm(PBYTE &addr) const;
    int is_bl_jimm(a64 &addr) const;
    int is_bl_jimm() const
    {
      return ( m_dis.instr_id == AD_INSTR_BL && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM );
    }
    inline int is_br_reg() const
    {
      return is_braa() ||
       (m_dis.instr_id == AD_INSTR_BR && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_REG);
    }
    inline int is_bl_reg() const
    {
      return (m_dis.instr_id == AD_INSTR_BLR && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_REG);
    }
    inline int is_tst() const
    {
      return (m_dis.instr_id == AD_INSTR_TST && m_dis.num_operands == 2) &&
        m_dis.operands[0].type == AD_OP_REG &&
        m_dis.operands[1].type == AD_OP_REG;
    }
    inline int is_sub_rri() const
    {
      return (m_dis.instr_id == AD_INSTR_SUB && m_dis.num_operands == 3) &&
        m_dis.operands[0].type == AD_OP_REG &&
        m_dis.operands[1].type == AD_OP_REG &&
        m_dis.operands[2].type == AD_OP_IMM;
    }
    int is_cbnz_jimm(PBYTE &addr) const;
    int is_cbz_jimm(PBYTE &addr) const;
    int is_tbz_jimm(PBYTE &addr) const;
    int is_tbnz_jimm(PBYTE &addr) const;
    int is_ldr() const;
    int is_ldr0() const;
    int is_ldr_lsl() const;
    int setup(PBYTE psp)
    {
      const PBYTE end = (const PBYTE)(m_text + m_text_size);
      if ( psp > end )
        return 0;
      m_psp = psp;
      return 1;
    }
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
    unsigned char *m_psp;
    struct ad_insn m_dis;
    // set of __noreturn functions
    std::set<a64> m_noreturn;
};