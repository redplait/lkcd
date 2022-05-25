#include "stdafx.h"
#include <assert.h>
#include "idaidp.hpp"
#include <idp.hpp>
#include <frame.hpp>
#include "disasm.h"

#define FCMP_LT   0b0001  /* fp0 < fp1 */
#define FCMP_EQ   0b0010  /* fp0 = fp1 */
#define FCMP_UN   0b0100  /* unordered */
#define FCMP_GT   0b1000  /* fp0 > fp1 */

extern int loongson_is_switch(switch_info_t *si, const insn_t &insn);

void loong_create_switch_table(ea_t insn_ea, const switch_info_t &si)
{
  int size = si.get_jtable_element_size();
  int tab_size = si.get_jtable_size();
  ea_t curr = si.jumps;
  for ( int i = 0; i < tab_size; i++, curr += size )
  {
    int64 off = 0;
    switch(size)
    {
      case 1: off = get_byte(curr);
              create_byte(curr, 1);
       break;
      case 2: off = get_word(curr);
              create_word(curr, 1);
       break;
      case 4: off = get_dword(curr);
              create_dword(curr, 1);
       break;
      case 8: off = get_qword(curr);
              create_qword(curr, 1);
       break;
    }
    ea_t add = si.jumps + off;
    add_dref(curr, add, dr_O);
  }
}

int is_retn(const insn_t *insn)
{
  if ( insn->itype != Loong_jirl )
    return 0;
#ifdef _DEBUG
   msg("is_retn: %a %a\n", insn->Op3.addr, insn->ea);
#endif /* _DEBUG */
  return /* insn->Op1.reg == 1 && !insn->Op2.reg && */ insn->Op3.addr == insn->ea;
}

inline bool is_stkreg(int r)
{
  return r == 3;
}

inline int is_add(const insn_t *insn)
{
  return (insn->itype == Loong_addi_w || insn->itype == Loong_addi_d) && (insn->Op1.reg == insn->Op2.reg) && !is_stkreg(insn->Op1.reg);
}

int is_pcadd(int itype)
{
  switch(itype)
  {
    case Loong_pcaddi:
    case Loong_pcalau12i:
    case Loong_pcaddu12i:
    case Loong_pcaddu18i:
      return 1;
  }
  return 0;
}

ea_t pcadd(int itype, ea_t pc, int imm)
{
  switch(itype)
  {
    case Loong_pcaddi:
      // see gen_pcaddi
      return pc + (imm << 2);
    case Loong_pcalau12i:
      // see gen_pcalau12i
      return (pc + (imm << 12)) & ~0xfff;
    case Loong_pcaddu12i:
      // see gen_pcaddu12i
      return pc + (imm << 12);
    case Loong_pcaddu18i:
      // see gen_pcaddu18i
      return pc + ((ea_t)(imm) << 18);
  }
  return 0;
}

// 1 - ld, 2 - st, 3 - Bound Check ld, 4 - Bound Check st
int is_ld_st(int itype)
{
  switch(itype)
  {
    case Loong_ldl_w:
    case Loong_ldl_d:
    case Loong_ldr_w:
    case Loong_ldr_d:
    case Loong_ld_bu:
    case Loong_ld_hu:
    case Loong_ld_wu:
    case Loong_ld_b:
    case Loong_ld_h:
    case Loong_ld_w:
    case Loong_ld_d:
    case Loong_ldptr_w:
    case Loong_ldptr_d:
    case Loong_ldx_bu:
    case Loong_ldx_hu:
    case Loong_ldx_wu:
    case Loong_ldx_b:
    case Loong_ldx_h:
    case Loong_ldx_w:
    case Loong_ldx_d:
    case Loong_fld_s:
    case Loong_fld_d:
    case Loong_fldx_s:
    case Loong_fldx_d:
      return 1;
    case Loong_stl_w:
    case Loong_stl_d:
    case Loong_str_w:
    case Loong_str_d:
    case Loong_st_b:
    case Loong_st_h:
    case Loong_st_w:
    case Loong_st_d:
    case Loong_stptr_w:
    case Loong_stptr_d:
    case Loong_stx_b:
    case Loong_stx_h:
    case Loong_stx_w:
    case Loong_stx_d:
    case Loong_fst_s:
    case Loong_fst_d:
    case Loong_fstx_s:
    case Loong_fstx_d:
     return 2;
    case Loong_ldgt_b:
    case Loong_ldgt_h:
    case Loong_ldgt_w:
    case Loong_ldgt_d:
    case Loong_ldle_b:
    case Loong_ldle_h:
    case Loong_ldle_w:
    case Loong_ldle_d:
    case Loong_fldgt_s:
    case Loong_fldgt_d:
    case Loong_fldle_s:
    case Loong_fldle_d:
     return 3;
    case Loong_stgt_b:
    case Loong_stgt_h:
    case Loong_stgt_w:
    case Loong_stgt_d:
    case Loong_stle_b:
    case Loong_stle_h:
    case Loong_stle_w:
    case Loong_stle_d:
    case Loong_fstgt_s:
    case Loong_fstgt_d:
    case Loong_fstle_s:
    case Loong_fstle_d:
     return 4;
  }
  return 0;
}

int is_sp_based(const insn_t *insn, const op_t *op)
{
  if ( is_ld_st(insn->itype) && is_stkreg(insn->Op2.reg) )
    return 1;
  return 0;
}

bool is_reg_alive(const insn_t *insn, int ridx)
{
  uint32 feature = insn->get_canon_feature(ph);
  if ( feature & CF_CHG1 )
  {
    if ( insn->Op1.type == o_reg && insn->Op1.reg == ridx )
      return false;
  }
  return true;
}

// some very clumsy and inefficient way to load 64bit ptr
// lu12i.w r12, 0       # 20 bit << 12
// ori r12, r12, 0x44   # 12 bit in low bits
// lu32i.d r12, 0       # 20 bit << 32
// lu52i.d r12, r12, 0  # 12 bit in high bits
// total 20 + 12 + 20 + 12 = 64
// I assume that this function called when lu52i.d was detected
bool track_clumsy64(func_item_iterator_t &fii, const insn_t &curr, ea_t &out_val)
{
  // lu52i.d - imm3
  int idxr = curr.Op1.reg;
  int hi = curr.Op3.value;
  insn_t prev;
  // lu32i.d - imm2
  if ( !fii.decode_prev_insn(&prev) )
    return false;
  if ( prev.itype != Loong_lu32i_d || prev.Op1.reg != idxr )
    return false;
  ea_t tmp = prev.Op2.value | (hi << 20);
  // ori - imm3
  if ( !fii.decode_prev_insn(&prev) )
    return false;
  if ( prev.itype != Loong_ori || prev.Op2.reg != idxr )
    return false;
  hi = prev.Op3.value & 0xfff;
  idxr = prev.Op1.reg;
  // lu12i - imm2
  if ( !fii.decode_prev_insn(&prev) )
    return false;
  if ( prev.itype != Loong_lu12i_w || prev.Op1.reg != idxr )
    return false;
  out_val = (hi | (prev.Op2.value << 12)) | (tmp << 32);
  return true;
}

bool track_back(const insn_t *insn, ea_t &addr)
{
  ea_t off = insn->Op3.value;
  int idxr = insn->Op2.reg;
  // find previous pair of pcadd/add
  insn_t prev;
  func_item_iterator_t fii(get_func(insn->ea), insn->ea);
  while ( fii.decode_prev_insn(&prev) )
  {
    if ( is_add(&prev) && prev.Op1.reg == idxr )
    {
      off += prev.Op3.value;
      continue;
    }
    if ( is_pcadd(prev.itype) && prev.Op1.reg == idxr )
    {
      addr = pcadd(prev.itype, prev.ea, prev.Op2.value) + off;
      return true;
    }
    if ( prev.itype == Loong_lu52i_d && prev.Op1.reg == idxr )
    {
      ea_t tmp = 0;
      if ( track_clumsy64(fii, prev, tmp) )
      {
        addr = tmp + off;
        return true;
      }
    }
    if ( !is_reg_alive(&prev, idxr) )
      return false;
  }
  return false;
}

bool is_loongson_basic_block_end(const insn_t *insn, bool call_insn_stops_block)
{
  uint32 feature = insn->get_canon_feature(ph);
  if ( feature & CF_STOP )
    return true;
  if ( feature & CF_CALL )
    return call_insn_stops_block;
  return false;
}

void find_function_end(ea_t ea)
{
  func_t *pfn = get_func(ea);
  if ( NULL == pfn )
    return;
   DisasContext dc;
   ea_t fea = ea += 4;
   for ( ; ; fea += 4 )
   {
      insn_t tmp;
      dc.pc = fea;
      dc.insn = &tmp;
      int res = LoongsonDisassemble(get_dword(fea), &dc);
      if ( !res )
        break;
      if ( is_loongson_basic_block_end(&tmp, false) )
      {
        fea += res;
        break;
      }
   }
   set_func_end(ea, fea);
}

void make_jmp(const insn_t *insn)
{
  if ( insn->Op1.type == o_far )
  {
    insn->add_cref(insn->Op1.addr, 0, fl_JF);
    if ( insn->itype == Loong_bl )
      add_func(insn->Op1.addr);
    return;
  }
  if ( insn->Op2.type == o_far )
  {
    insn->add_cref(insn->Op2.addr, 0, fl_JF);
    return;
  }
  if ( insn->Op3.type == o_far && !is_retn(insn) )
  {
    insn->add_cref(insn->Op3.addr, 0, fl_JF);
    return;
  }
}

void emu_insn(const insn_t *insn)
{
  make_jmp(insn);
  int is_end = is_loongson_basic_block_end(insn, false);
  if ( !is_end )
    add_cref(insn->ea, insn->ea + insn->size, fl_F);
  int sl = is_ld_st(insn->itype);
  if ( sl && is_stkreg(insn->Op2.reg) && insn->Op3.type == o_imm )
  {
    if ( insn_create_stkvar(*insn, insn->Op1, insn->Op3.value, 0) )
      op_stkvar(insn->ea, insn->Op1.n);
    return;
  }
  // check for stack adjusting
  if ( (insn->itype == Loong_addi_w || insn->itype == Loong_addi_d) && is_stkreg(insn->Op1.reg) && is_stkreg(insn->Op2.reg) )
  {
    func_t *pfn = get_func(insn->ea);
#ifdef _DEBUG
    msg("%a stack pfn %p\n", insn->ea, pfn);
#endif /* _DEBUG */
    if ( pfn != NULL )
      add_auto_stkpnt(pfn, insn->ea+insn->size, insn->Op3.value);
    return;
  }
  char comm[64];
  if ( is_add(insn) )
  {
    ea_t off = insn->Op3.value;
    int idxr = insn->Op2.reg;
    // find previous pcadd
    insn_t prev;
    func_item_iterator_t fii(get_func(insn->ea), insn->ea);
    while ( fii.decode_prev_insn(&prev) )
    {
      if ( is_pcadd(prev.itype) && prev.Op1.reg == idxr )
      {
        ea_t ea = pcadd(prev.itype, prev.ea, prev.Op2.value) + off;
        insn->add_dref(ea, 0, dr_O);
        qsnprintf(comm, sizeof(comm), "%a %X", ea, ea & 0xffffffff);
        set_cmt(insn->ea, comm, false);
        break;
      }
      if ( !is_reg_alive(&prev, idxr) )
        break;
    }
  }
  if ( Loong_lu52i_d == insn->itype )
  {
    func_item_iterator_t fii(get_func(insn->ea), insn->ea);
    ea_t off = NULL;
    if ( track_clumsy64(fii, *insn, off) )
    {
      qsnprintf(comm, sizeof(comm), "%a %X", off, off & 0xffffffff);
      set_cmt(insn->ea, comm, false);
    }
  }
  if ( sl && insn->Op3.type == o_imm )
  {
    ea_t addr;
    if ( track_back(insn, addr) )
    {
      qsnprintf(comm, sizeof(comm), "d%d: %a %X", insn->Op1.reg, addr, addr & 0xffffffff);
      set_cmt(insn->ea, comm, false);
      insn->add_dref(addr, 0, sl & 1 ? dr_R : dr_W);
    }
  }
  // check for patched r1 in Loong_jirl
  if ( Loong_jirl == insn->itype )
  {
    ea_t addr;
    if ( track_back(insn, addr) )
    {
      if ( addr == insn->ea + insn->size )
        add_cref(insn->ea, insn->ea + insn->size, fl_F);
      else
      {
        qsnprintf(comm, sizeof(comm), "r%d: %a", insn->Op2.reg, addr);
        set_cmt(insn->ea, comm, false);
        add_cref(insn->ea, addr, fl_JF);
      }
    } else {
      qsnprintf(comm, sizeof(comm), "r%d", insn->Op2.reg);
      set_cmt(insn->ea, comm, false);
      // check for switch jmp
      switch_info_t si;
      if ( loongson_is_switch(&si, *insn) )
      {
msg("switch at %a\n", insn->ea);
        set_switch_info(insn->ea, si);
        if ( !create_switch_table(insn->ea, si) )
          loong_create_switch_table(insn->ea, si);
        else
          create_switch_xrefs(insn->ea, si);
      }
    }
  }
}

static inline int plus_1(DisasContext *ctx, int x)
{
    return x + 1;
}

static inline int shl_2(DisasContext *ctx, int x)
{
    return x << 2;
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

#include "insns.inc"

op_dtype_t get_dtype(loong_insn_type_t op)
{
  switch(op)
  {
#include "dtype.inc"
  }
  return dt_void;
}

static void output_r_i(DisasContext *ctx, arg_r_i *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_imm;
  ctx->insn->Op2.value = a->imm;
  ctx->insn->Op2.dtype = dt_dword;
}

static void output_rrr(DisasContext *ctx, arg_rrr *a, loong_insn_type_t mnemonic)
{
  if ( ctx->insn->itype == Loong_or && !a->rk ) // or rd, rj, r0 eq mov rd, rj
  {
    ctx->num_ops = 2;
    ctx->insn->itype = Loong_mov;
  } else
    ctx->num_ops = 3;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  if ( ctx->num_ops > 2 )
  {
    ctx->insn->Op3.type = o_reg;
    ctx->insn->Op3.reg = a->rk;
    ctx->insn->Op3.dtype = dt_qword;
  }
}

static void output_rr_i(DisasContext *ctx, arg_rr_i *a, loong_insn_type_t mnemonic)
{
  // check for andi r0 - this is nop
  if ( mnemonic == Loong_andi && !a->rd )
  {
    ctx->num_ops = 0;
    ctx->insn->itype = Loong_nop;
    return;
  }

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  // addi.w reg, r0, imm - this is mov reg, imm
  if ( (mnemonic == Loong_addi_w || mnemonic == Loong_addi_d) && !a->rj )
  {
    ctx->num_ops = 2;
    ctx->insn->itype = Loong_mov;
    ctx->insn->Op2.type = o_imm;
    ctx->insn->Op2.value = a->imm;
    ctx->insn->Op2.dtype = dt_byte;
    return;
  }

  ctx->num_ops = 3;

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_imm;
  ctx->insn->Op3.value = a->imm;
  ctx->insn->Op3.dtype = dt_byte;
}

static void output_rrr_sa(DisasContext *ctx, arg_rrr_sa *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 4;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = a->rk;
  ctx->insn->Op3.dtype = dt_qword;

  ctx->insn->Op4.type = o_imm;
  ctx->insn->Op4.value = a->sa;
  ctx->insn->Op4.dtype = dt_byte;
}

static void output_rr(DisasContext *ctx, arg_rr *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;
}

static void output_rr_ms_ls(DisasContext *ctx, arg_rr_ms_ls *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 4;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_imm;
  ctx->insn->Op3.value = a->ms;
  ctx->insn->Op3.dtype = dt_byte;

  ctx->insn->Op4.type = o_imm;
  ctx->insn->Op4.value = a->ls;
  ctx->insn->Op4.dtype = dt_byte;
}

static void output_hint_r_i(DisasContext *ctx, arg_hint_r_i *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;

  ctx->insn->Op1.type = o_imm;
  ctx->insn->Op1.value = a->hint;
  ctx->insn->Op1.dtype = dt_word;

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_imm;
  ctx->insn->Op3.value = a->imm;
  ctx->insn->Op3.dtype = dt_word;
}

static void output_i(DisasContext *ctx, arg_i *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 1;

  ctx->insn->Op1.type = o_imm;
  ctx->insn->Op1.value = a->imm;
  ctx->insn->Op1.dtype = dt_dword;
}

static void output_rr_jk(DisasContext *ctx, arg_rr_jk *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rj;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rk;
  ctx->insn->Op2.dtype = dt_qword;
}

static void output_ff(DisasContext *ctx, arg_ff *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // floating regs 
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;
}

static void output_fff(DisasContext *ctx, arg_fff *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;

  // floating regs 
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = 32 + a->fk;
  ctx->insn->Op3.dtype = dt_double;
}

static void output_ffff(DisasContext *ctx, arg_ffff *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 4;

  // floating regs 
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = 32 + a->fk;
  ctx->insn->Op3.dtype = dt_double;

  ctx->insn->Op4.type = o_reg;
  ctx->insn->Op4.reg = 32 + a->fa;
  ctx->insn->Op4.dtype = dt_double;
}

static void output_fffc(DisasContext *ctx, arg_fffc *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;
  ctx->fcond = a->ca;
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = 32 + a->fk;
  ctx->insn->Op3.dtype = dt_double;
}

static void output_fr(DisasContext *ctx, arg_fr *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;
}

static void output_rf(DisasContext *ctx, arg_rf *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;
}

static void output_fcsrd_r(DisasContext *ctx, arg_fcsrd_r *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // fcsr
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 72 + a->rj;
  ctx->insn->Op1.dtype = dt_byte;

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;
}

static void output_r_fcsrs(DisasContext *ctx, arg_r_fcsrs *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);
  // fcsr
  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 72 + a->fcsrs;
  ctx->insn->Op2.dtype = dt_byte;
}

static void output_cf(DisasContext *ctx, arg_cf *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // fcc
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 64 + a->cd;
  ctx->insn->Op1.dtype = dt_byte;
  // floating reg
  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;
}

static void output_fc(DisasContext *ctx, arg_fc *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // floating reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);
  // fcc
  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 64 + a->cj;
  ctx->insn->Op2.dtype = dt_byte;
}

static void output_cr(DisasContext *ctx, arg_cr *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // fcc
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 64 + a->cd;
  ctx->insn->Op1.dtype = dt_byte;

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;
}

static void output_rc(DisasContext *ctx, arg_rc *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);
  // fcc
  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 64 + a->cj;
  ctx->insn->Op2.dtype = dt_byte;
}

static void output_frr(DisasContext *ctx, arg_frr *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;
  // floating reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = a->rk;
  ctx->insn->Op3.dtype = dt_qword;
}

static void output_fr_i(DisasContext *ctx, arg_fr_i *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;

  // floating reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 32 + a->fd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_imm;
  ctx->insn->Op3.value = a->imm;
  ctx->insn->Op3.dtype = dt_word;
}

static void output_r_offs(DisasContext *ctx, arg_r_offs *a,
                          loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rj;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);
  // imm dword
  ctx->insn->Op2.type = o_far;
  ctx->insn->Op2.addr = ctx->pc + a->offs;
//  ctx->insn->add_cref(ctx->pc, x.offb, ftype);
}

static void output_c_offs(DisasContext *ctx, arg_c_offs *a,
                          loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;

  // fcc
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 64 + a->cj;
  ctx->insn->Op1.dtype = dt_byte;
  // imm dword
  ctx->insn->Op2.type = o_far;
  ctx->insn->Op2.addr = ctx->pc + a->offs;
//  ctx->insn->add_cref(ctx->pc, x.offb, ftype);
}

static void output_offs(DisasContext *ctx, arg_offs *a,
                        loong_insn_type_t mnemonic)
{
  ctx->num_ops = 1;

  ctx->insn->Op1.type = o_far;
  ctx->insn->Op1.addr = ctx->pc + a->offs;
}

static void output_rr_offs(DisasContext *ctx, arg_rr_offs *a,
                           loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;
  int need_swap = (mnemonic == Loong_jirl);
  // reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = need_swap ? a->rd : a->rj;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = need_swap ? a->rj : a->rd;
  ctx->insn->Op2.dtype = dt_qword;

  // imm dword
  ctx->insn->Op3.type = o_far;
  ctx->insn->Op3.addr = ctx->pc + a->offs;
//  ctx->insn->add_cref(ctx->pc, x.offb, ftype);
}

static void output_r_csr(DisasContext *ctx, arg_r_csr *a,
                         loong_insn_type_t mnemonic)
{
  ctx->num_ops = 2;
  // reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);
  // csr
  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 104 + a->csr;
  ctx->insn->Op2.dtype = dt_qword;
}

static void output_rr_csr(DisasContext *ctx, arg_rr_csr *a,
                          loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;
  // reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rd;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;
  // csr
  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = 104 + a->csr;
  ctx->insn->Op3.dtype = dt_qword;
}

static void output_empty(DisasContext *ctx, arg_empty *a,
                         loong_insn_type_t mnemonic)
{
  ctx->num_ops = 0;
}

static void output_i_rr(DisasContext *ctx, arg_i_rr *a, loong_insn_type_t mnemonic)
{
  ctx->num_ops = 3;
  // imm byte
  ctx->insn->Op1.type = o_imm;
  ctx->insn->Op1.value = a->imm;
  ctx->insn->Op1.dtype = dt_byte;

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = a->rk;
  ctx->insn->Op3.dtype = dt_qword;
}

static void output_cop_r_i(DisasContext *ctx, arg_cop_r_i *a,
                           loong_insn_type_t mnemonic)
{

  // imm byte
  ctx->insn->Op1.type = o_imm;
  ctx->insn->Op1.value = a->cop;
  ctx->insn->Op1.dtype = dt_byte;

  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = a->rj;
  ctx->insn->Op2.dtype = dt_qword;

  ctx->insn->Op3.type = o_imm;
  ctx->insn->Op3.value = a->imm;
  ctx->insn->Op3.dtype = dt_word;
}

static void output_j_i(DisasContext *ctx, arg_j_i *a, loong_insn_type_t mnemonic)
{
  // reg
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = a->rj;
  ctx->insn->Op1.dtype = get_dtype(mnemonic);

  ctx->insn->Op3.type = o_imm;
  ctx->insn->Op3.value = a->imm;
  ctx->insn->Op3.dtype = dt_word;
}

#define INSN(insnt, type)                                    \
static bool trans_##insnt(DisasContext *ctx, arg_##type * a) \
{                                                           \
    ctx->insn->itype = Loong_##insnt;                        \
    output_##type(ctx, a, Loong_##insnt);                    \
    return true;                                            \
}

INSN(clo_w,        rr)
INSN(clz_w,        rr)
INSN(cto_w,        rr)
INSN(ctz_w,        rr)
INSN(clo_d,        rr)
INSN(clz_d,        rr)
INSN(cto_d,        rr)
INSN(ctz_d,        rr)
INSN(revb_2h,      rr)
INSN(revb_4h,      rr)
INSN(revb_2w,      rr)
INSN(revb_d,       rr)
INSN(revh_2w,      rr)
INSN(revh_d,       rr)
INSN(bitrev_4b,    rr)
INSN(bitrev_8b,    rr)
INSN(bitrev_w,     rr)
INSN(bitrev_d,     rr)
INSN(ext_w_h,      rr)
INSN(ext_w_b,      rr)
INSN(rdtimel_w,    rr)
INSN(rdtimeh_w,    rr)
INSN(rdtime_d,     rr)
INSN(cpucfg,       rr)
INSN(asrtle_d,     rr_jk)
INSN(asrtgt_d,     rr_jk)
INSN(alsl_w,       rrr_sa)
INSN(alsl_wu,      rrr_sa)
INSN(bytepick_w,   rrr_sa)
INSN(bytepick_d,   rrr_sa)
INSN(add_w,        rrr)
INSN(add_d,        rrr)
INSN(sub_w,        rrr)
INSN(sub_d,        rrr)
INSN(slt,          rrr)
INSN(sltu,         rrr)
INSN(maskeqz,      rrr)
INSN(masknez,      rrr)
INSN(nor,          rrr)
INSN(and,          rrr)
INSN(or,           rrr)
INSN(xor,          rrr)
INSN(orn,          rrr)
INSN(andn,         rrr)
INSN(sll_w,        rrr)
INSN(srl_w,        rrr)
INSN(sra_w,        rrr)
INSN(sll_d,        rrr)
INSN(srl_d,        rrr)
INSN(sra_d,        rrr)
INSN(rotr_w,       rrr)
INSN(rotr_d,       rrr)
INSN(mul_w,        rrr)
INSN(mulh_w,       rrr)
INSN(mulh_wu,      rrr)
INSN(mul_d,        rrr)
INSN(mulh_d,       rrr)
INSN(mulh_du,      rrr)
INSN(mulw_d_w,     rrr)
INSN(mulw_d_wu,    rrr)
INSN(div_w,        rrr)
INSN(mod_w,        rrr)
INSN(div_wu,       rrr)
INSN(mod_wu,       rrr)
INSN(div_d,        rrr)
INSN(mod_d,        rrr)
INSN(div_du,       rrr)
INSN(mod_du,       rrr)
INSN(crc_w_b_w,    rrr)
INSN(crc_w_h_w,    rrr)
INSN(crc_w_w_w,    rrr)
INSN(crc_w_d_w,    rrr)
INSN(crcc_w_b_w,   rrr)
INSN(crcc_w_h_w,   rrr)
INSN(crcc_w_w_w,   rrr)
INSN(crcc_w_d_w,   rrr)
INSN(break,        i)
INSN(syscall,      i)
INSN(alsl_d,       rrr_sa)
INSN(slli_w,       rr_i)
INSN(slli_d,       rr_i)
INSN(srli_w,       rr_i)
INSN(srli_d,       rr_i)
INSN(srai_w,       rr_i)
INSN(srai_d,       rr_i)
INSN(rotri_w,      rr_i)
INSN(rotri_d,      rr_i)
INSN(bstrins_w,    rr_ms_ls)
INSN(bstrpick_w,   rr_ms_ls)
INSN(bstrins_d,    rr_ms_ls)
INSN(bstrpick_d,   rr_ms_ls)
INSN(fadd_s,       fff)
INSN(fadd_d,       fff)
INSN(fsub_s,       fff)
INSN(fsub_d,       fff)
INSN(fmul_s,       fff)
INSN(fmul_d,       fff)
INSN(fdiv_s,       fff)
INSN(fdiv_d,       fff)
INSN(fmax_s,       fff)
INSN(fmax_d,       fff)
INSN(fmin_s,       fff)
INSN(fmin_d,       fff)
INSN(fmaxa_s,      fff)
INSN(fmaxa_d,      fff)
INSN(fmina_s,      fff)
INSN(fmina_d,      fff)
INSN(fscaleb_s,    fff)
INSN(fscaleb_d,    fff)
INSN(fcopysign_s,  fff)
INSN(fcopysign_d,  fff)
INSN(fabs_s,       ff)
INSN(fabs_d,       ff)
INSN(fneg_s,       ff)
INSN(fneg_d,       ff)
INSN(flogb_s,      ff)
INSN(flogb_d,      ff)
INSN(fclass_s,     ff)
INSN(fclass_d,     ff)
INSN(fsqrt_s,      ff)
INSN(fsqrt_d,      ff)
INSN(frecip_s,     ff)
INSN(frecip_d,     ff)
INSN(frsqrt_s,     ff)
INSN(frsqrt_d,     ff)
INSN(fmov_s,       ff)
INSN(fmov_d,       ff)
INSN(movgr2fr_w,   fr)
INSN(movgr2fr_d,   fr)
INSN(movgr2frh_w,  fr)
INSN(movfr2gr_s,   rf)
INSN(movfr2gr_d,   rf)
INSN(movfrh2gr_s,  rf)
INSN(movgr2fcsr,   fcsrd_r)
INSN(movfcsr2gr,   r_fcsrs)
INSN(movfr2cf,     cf)
INSN(movcf2fr,     fc)
INSN(movgr2cf,     cr)
INSN(movcf2gr,     rc)
INSN(fcvt_s_d,     ff)
INSN(fcvt_d_s,     ff)
INSN(ftintrm_w_s,  ff)
INSN(ftintrm_w_d,  ff)
INSN(ftintrm_l_s,  ff)
INSN(ftintrm_l_d,  ff)
INSN(ftintrp_w_s,  ff)
INSN(ftintrp_w_d,  ff)
INSN(ftintrp_l_s,  ff)
INSN(ftintrp_l_d,  ff)
INSN(ftintrz_w_s,  ff)
INSN(ftintrz_w_d,  ff)
INSN(ftintrz_l_s,  ff)
INSN(ftintrz_l_d,  ff)
INSN(ftintrne_w_s, ff)
INSN(ftintrne_w_d, ff)
INSN(ftintrne_l_s, ff)
INSN(ftintrne_l_d, ff)
INSN(ftint_w_s,    ff)
INSN(ftint_w_d,    ff)
INSN(ftint_l_s,    ff)
INSN(ftint_l_d,    ff)
INSN(ffint_s_w,    ff)
INSN(ffint_s_l,    ff)
INSN(ffint_d_w,    ff)
INSN(ffint_d_l,    ff)
INSN(frint_s,      ff)
INSN(frint_d,      ff)
INSN(slti,         rr_i)
INSN(sltui,        rr_i)
INSN(addi_w,       rr_i)
INSN(addi_d,       rr_i)
INSN(lu52i_d,      rr_i)
INSN(andi,         rr_i)
INSN(ori,          rr_i)
INSN(xori,         rr_i)
INSN(fmadd_s,      ffff)
INSN(fmadd_d,      ffff)
INSN(fmsub_s,      ffff)
INSN(fmsub_d,      ffff)
INSN(fnmadd_s,     ffff)
INSN(fnmadd_d,     ffff)
INSN(fnmsub_s,     ffff)
INSN(fnmsub_d,     ffff)
INSN(fsel,         fffc)
INSN(addu16i_d,    rr_i)
INSN(lu12i_w,      r_i)
INSN(lu32i_d,      r_i)
INSN(pcaddi,       r_i)
INSN(pcalau12i,    r_i)
INSN(pcaddu12i,    r_i)
INSN(pcaddu18i,    r_i)
INSN(ll_w,         rr_i)
INSN(sc_w,         rr_i)
INSN(ll_d,         rr_i)
INSN(sc_d,         rr_i)
INSN(ldptr_w,      rr_i)
INSN(stptr_w,      rr_i)
INSN(ldptr_d,      rr_i)
INSN(stptr_d,      rr_i)
INSN(ld_b,         rr_i)
INSN(ld_h,         rr_i)
INSN(ld_w,         rr_i)
INSN(ld_d,         rr_i)
INSN(st_b,         rr_i)
INSN(st_h,         rr_i)
INSN(st_w,         rr_i)
INSN(st_d,         rr_i)
INSN(ld_bu,        rr_i)
INSN(ld_hu,        rr_i)
INSN(ld_wu,        rr_i)
INSN(preld,        hint_r_i)
INSN(fld_s,        fr_i)
INSN(fst_s,        fr_i)
INSN(fld_d,        fr_i)
INSN(fst_d,        fr_i)
INSN(ldx_b,        rrr)
INSN(ldx_h,        rrr)
INSN(ldx_w,        rrr)
INSN(ldx_d,        rrr)
INSN(stx_b,        rrr)
INSN(stx_h,        rrr)
INSN(stx_w,        rrr)
INSN(stx_d,        rrr)
INSN(ldx_bu,       rrr)
INSN(ldx_hu,       rrr)
INSN(ldx_wu,       rrr)
INSN(fldx_s,       frr)
INSN(fldx_d,       frr)
INSN(fstx_s,       frr)
INSN(fstx_d,       frr)
INSN(amswap_w,     rrr)
INSN(amswap_d,     rrr)
INSN(amadd_w,      rrr)
INSN(amadd_d,      rrr)
INSN(amand_w,      rrr)
INSN(amand_d,      rrr)
INSN(amor_w,       rrr)
INSN(amor_d,       rrr)
INSN(amxor_w,      rrr)
INSN(amxor_d,      rrr)
INSN(ammax_w,      rrr)
INSN(ammax_d,      rrr)
INSN(ammin_w,      rrr)
INSN(ammin_d,      rrr)
INSN(ammax_wu,     rrr)
INSN(ammax_du,     rrr)
INSN(ammin_wu,     rrr)
INSN(ammin_du,     rrr)
INSN(amswap_db_w,  rrr)
INSN(amswap_db_d,  rrr)
INSN(amadd_db_w,   rrr)
INSN(amadd_db_d,   rrr)
INSN(amand_db_w,   rrr)
INSN(amand_db_d,   rrr)
INSN(amor_db_w,    rrr)
INSN(amor_db_d,    rrr)
INSN(amxor_db_w,   rrr)
INSN(amxor_db_d,   rrr)
INSN(ammax_db_w,   rrr)
INSN(ammax_db_d,   rrr)
INSN(ammin_db_w,   rrr)
INSN(ammin_db_d,   rrr)
INSN(ammax_db_wu,  rrr)
INSN(ammax_db_du,  rrr)
INSN(ammin_db_wu,  rrr)
INSN(ammin_db_du,  rrr)
INSN(dbar,         i)
INSN(ibar,         i)
INSN(fldgt_s,      frr)
INSN(fldgt_d,      frr)
INSN(fldle_s,      frr)
INSN(fldle_d,      frr)
INSN(fstgt_s,      frr)
INSN(fstgt_d,      frr)
INSN(fstle_s,      frr)
INSN(fstle_d,      frr)
INSN(ldgt_b,       rrr)
INSN(ldgt_h,       rrr)
INSN(ldgt_w,       rrr)
INSN(ldgt_d,       rrr)
INSN(ldle_b,       rrr)
INSN(ldle_h,       rrr)
INSN(ldle_w,       rrr)
INSN(ldle_d,       rrr)
INSN(ldl_w,        rr_i)
INSN(ldl_d,        rr_i)
INSN(ldr_w,        rr_i)
INSN(ldr_d,        rr_i)
INSN(stl_w,        rr_i)
INSN(stl_d,        rr_i)
INSN(str_w,        rr_i)
INSN(str_d,        rr_i)
INSN(stgt_b,       rrr)
INSN(stgt_h,       rrr)
INSN(stgt_w,       rrr)
INSN(stgt_d,       rrr)
INSN(stle_b,       rrr)
INSN(stle_h,       rrr)
INSN(stle_w,       rrr)
INSN(stle_d,       rrr)
INSN(beqz,         r_offs)
INSN(bnez,         r_offs)
INSN(bceqz,        c_offs)
INSN(bcnez,        c_offs)
INSN(jirl,         rr_offs)
INSN(b,            offs)
INSN(bl,           offs)
INSN(beq,          rr_offs)
INSN(bne,          rr_offs)
INSN(blt,          rr_offs)
INSN(bge,          rr_offs)
INSN(bltu,         rr_offs)
INSN(bgeu,         rr_offs)
INSN(csrrd,        r_csr)
INSN(csrwr,        r_csr)
INSN(csrxchg,      rr_csr)
INSN(iocsrrd_b,    rr)
INSN(iocsrrd_h,    rr)
INSN(iocsrrd_w,    rr)
INSN(iocsrrd_d,    rr)
INSN(iocsrwr_b,    rr)
INSN(iocsrwr_h,    rr)
INSN(iocsrwr_w,    rr)
INSN(iocsrwr_d,    rr)
INSN(tlbsrch,      empty)
INSN(tlbrd,        empty)
INSN(tlbwr,        empty)
INSN(tlbfill,      empty)
INSN(tlbclr,       empty)
INSN(tlbflush,     empty)
INSN(invtlb,       i_rr)
INSN(cacop,        cop_r_i)
INSN(lddir,        rr_i)
INSN(ldpte,        j_i)
INSN(ertn,         empty)
INSN(idle,         i)
INSN(dbcl,         i)

static bool output_cff_fcond(DisasContext *ctx, arg_cff_fcond * a, int is_s)
{
    bool ret = true;
    ctx->fcond = a->fcond;
    ctx->num_ops = 3;

  // fcc
  ctx->insn->Op1.type = o_reg;
  ctx->insn->Op1.reg = 64 + a->cd;
  ctx->insn->Op1.dtype = dt_byte;
  // floating regs
  ctx->insn->Op2.type = o_reg;
  ctx->insn->Op2.reg = 32 + a->fj;
  ctx->insn->Op2.dtype = dt_double;

  ctx->insn->Op3.type = o_reg;
  ctx->insn->Op3.reg = 32 + a->fk;
  ctx->insn->Op3.dtype = dt_double;

    switch (a->fcond) {
    case 0x0:
      ctx->insn->itype = is_s ? Loong_fcmp_caf_s: Loong_fcmp_caf_d;
        break;
    case 0x1:
      ctx->insn->itype = is_s ? Loong_fcmp_saf_s: Loong_fcmp_saf_d;
        break;
    case 0x2:
      ctx->insn->itype = is_s ? Loong_fcmp_clt_s: Loong_fcmp_clt_d;
        break;
    case 0x3:
      ctx->insn->itype = is_s ? Loong_fcmp_slt_s: Loong_fcmp_slt_d;
        break;
    case 0x4:
      ctx->insn->itype = is_s ? Loong_fcmp_ceq_s: Loong_fcmp_ceq_d;
        break;
    case 0x5:
      ctx->insn->itype = is_s ? Loong_fcmp_seq_s: Loong_fcmp_seq_d;
        break;
    case 0x6:
      ctx->insn->itype = is_s ? Loong_fcmp_cle_s: Loong_fcmp_cle_d;
        break;
    case 0x7:
      ctx->insn->itype = is_s ? Loong_fcmp_sle_s: Loong_fcmp_sle_d;
        break;
    case 0x8:
      ctx->insn->itype = is_s ? Loong_fcmp_cun_s: Loong_fcmp_cun_d;
        break;
    case 0x9:
      ctx->insn->itype = is_s ? Loong_fcmp_sun_s: Loong_fcmp_sun_d;
        break;
    case 0xA:
      ctx->insn->itype = is_s ? Loong_fcmp_cult_s: Loong_fcmp_cult_d;
        break;
    case 0xB:
      ctx->insn->itype = is_s ? Loong_fcmp_sult_s: Loong_fcmp_sult_d;
        break;
    case 0xC:
      ctx->insn->itype = is_s ? Loong_fcmp_cueq_s: Loong_fcmp_cueq_d;
        break;
    case 0xD:
      ctx->insn->itype = is_s ? Loong_fcmp_sueq_s: Loong_fcmp_sueq_d;
        break;
    case 0xE:
      ctx->insn->itype = is_s ? Loong_fcmp_cule_s: Loong_fcmp_cule_d;
        break;
    case 0xF:
      ctx->insn->itype = is_s ? Loong_fcmp_sule_s: Loong_fcmp_sule_d;
        break;
    case 0x10:
      ctx->insn->itype = is_s ? Loong_fcmp_cne_s: Loong_fcmp_cne_d;
        break;
    case 0x11:
      ctx->insn->itype = is_s ? Loong_fcmp_sne_s: Loong_fcmp_sne_d;
        break;
    case 0x14:
      ctx->insn->itype = is_s ? Loong_fcmp_cor_s: Loong_fcmp_cor_d;
        break;
    case 0x15:
      ctx->insn->itype = is_s ? Loong_fcmp_sor_s: Loong_fcmp_sor_d;
        break;
    case 0x18:
      ctx->insn->itype = is_s ? Loong_fcmp_cune_s: Loong_fcmp_cune_d;
        break;
    case 0x19:
      ctx->insn->itype = is_s ? Loong_fcmp_sune_s: Loong_fcmp_sune_d;
        break;
    default:
        return false;
    }
    return ret;
}

#define FCMP_INSN(suffix, is_s)                         \
static bool trans_fcmp_cond_##suffix(DisasContext *ctx, \
                                     arg_cff_fcond * a) \
{                                                       \
    return output_cff_fcond(ctx, a, is_s);              \
}

FCMP_INSN(s, 1)
FCMP_INSN(d, 0)

int LoongsonDisassemble(unsigned int opcode, DisasContext *out)
{
  out->fcond = 0;
  out->num_ops = 0;
  out->value = opcode;
  if (!decode(out, out->value))
    return 0;
  return 4;
}