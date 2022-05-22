#pragma once

// derived from jump_pattern_t class for switch tables reconstruction under loongson

// jump pattern #1
// 7  mov rMax, imm
// 6  bltu rMax, rIdx default addr
// 5  pcadduXXi rBase2, base
// 4  addi.d rBase, rBase2, offset
// 3  alsl.d rS, rIdx, rBase, size
// 2  ldptr.d rJ, rS, 0
// 1  add.d regA, regA, rJ
// 0  ret regA
static const char lsw1_depends[][4] =
{
  { 1 },  // 0
  { 2 },  // 1
  { 3 },  // 2
  { 4 },  // 3
  { 5 },  // 4
  { 6 },  // 5
  { 7 },  // 6
  { 0 },
};

// jump pattern #2
// 7  pcadduXXi rBase2, base
// 6  addi.d rBase, rBase2, offset
// 5  mov rMax, imm
// 4  bltu rMax, rIdx default addr
// 3  alsl.d rS, rBase, rIdx, size
// 2  ldptr.d regA, rS, 0
// 1  add.d regA, rBase, regA
// 0  ret regA

class loongson_jump_pattern_t : public jump_pattern_t
{
protected:
  enum {
   regA, rJ, rS, rIdx, rBase, rBase2, rMax
  };
  ea_t add_off;
  int is_ge; // for bge(u)
  // common methods
  bool is_ret();
  bool is_add();
  bool is_add_base();
  bool is_ldptr();
  bool is_ldptrA();
  bool is_alsl();
  bool is_alsl_base();
  bool is_addi();
  bool is_pcadduXXi();
  bool is_bxx();
  bool is_rimm();
public:
  loongson_jump_pattern_t(switch_info_t *_si)
   : jump_pattern_t(_si, lsw1_depends, rMax)
  {
    add_off = NULL;
    is_ge = 0;
  }
  virtual bool handle_mov(tracked_regs_t &_regs) override;
  bool finish();
  virtual bool jpi0(void) override { return is_ret(); }
};

class loongson_jump_pattern_t1: public loongson_jump_pattern_t
{
 public:
   loongson_jump_pattern_t1(switch_info_t *_si)
     : loongson_jump_pattern_t(_si)
   {}
  // 1..7
  virtual bool jpi7(void) override { return is_rimm(); }
  virtual bool jpi6(void) override { return is_bxx(); }
  virtual bool jpi5(void) override { return is_pcadduXXi(); }
  virtual bool jpi4(void) override { return is_addi(); }
  virtual bool jpi3(void) override { return is_alsl(); }
  virtual bool jpi2(void) override { return is_ldptr(); }
  virtual bool jpi1(void) override { return is_add(); }
};

class loongson_jump_pattern_t2: public loongson_jump_pattern_t
{
 public:
   loongson_jump_pattern_t2(switch_info_t *_si)
     : loongson_jump_pattern_t(_si)
   {}
  // 1..7
  virtual bool jpi7(void) override { return is_pcadduXXi(); }
  virtual bool jpi6(void) override { return is_addi(); }
  virtual bool jpi5(void) override { return is_rimm(); }
  virtual bool jpi4(void) override { return is_bxx(); }
  virtual bool jpi3(void) override { return is_alsl(); }
  virtual bool jpi2(void) override { return is_ldptr(); }
  virtual bool jpi1(void) override { return is_add_base(); }
};

class loongson_jump_pattern_t3: public loongson_jump_pattern_t
{
 public:
   loongson_jump_pattern_t3(switch_info_t *_si)
     : loongson_jump_pattern_t(_si)
   {}
  // 1..7
  virtual bool jpi7(void) override { return is_rimm(); }
  virtual bool jpi6(void) override { return is_bxx(); }
  virtual bool jpi5(void) override { return is_pcadduXXi(); }
  virtual bool jpi4(void) override { return is_addi(); }
  virtual bool jpi3(void) override { return is_alsl(); }
  virtual bool jpi2(void) override { return is_ldptr(); }
  virtual bool jpi1(void) override { return is_add_base(); }
};

// jump pattern #4
// 8  mov rMax, imm
// 7  bltu rMax, rIdx default addr
// 6  pcadduXXi rBase2, base
// 5  addi.d rBase, rBase2, offset
// 4  bstrpick rIdx2, rIdx
// 3  alsl.d rS, rIdx2, r0, size
// 2  ldx.d rJ, rBase, rS
// 1  add.d regA, rBase, rJ
// 0  ret regA
static const char lsw2_depends[][4] =
{
  { 1 },  // 0
  { 2 },  // 1
  { 3 },  // 2
  { 4 },  // 3
  { 5 },  // 4
  { 6 },  // 5
  { 7 },  // 6
  { 8 },  // 7
  { 0 },
};

class loongson_jump_pattern9ops : public jump_pattern_t
{
protected:
  enum {
   regA, rJ, rS, rIdx, rIdx2, rBase, rBase2, rMax
  };
  ea_t add_off;
  int is_ge; // for bge(u)
  // common methods
  bool is_ret();
  bool is_add();
  bool is_ldx();
  bool is_alsl0();
  bool is_bstrpick();
  bool is_addi();
  bool is_pcadduXXi();
  bool is_bxx();
  bool is_rimm();
public:
  loongson_jump_pattern9ops(switch_info_t *_si)
   : jump_pattern_t(_si, lsw2_depends, rMax)
  {
    add_off = NULL;
    is_ge = 0;
  }
  virtual bool handle_mov(tracked_regs_t &_regs) override;
  bool finish();
  virtual bool jpi0(void) override { return is_ret(); }
};

class loongson_jump_pattern_t4: public loongson_jump_pattern9ops
{
 public:
   loongson_jump_pattern_t4(switch_info_t *_si)
     : loongson_jump_pattern9ops(_si)
   {}
  // 1..8
  virtual bool jpi8(void) override { return is_rimm(); }
  virtual bool jpi7(void) override { return is_bxx(); }
  virtual bool jpi6(void) override { return is_pcadduXXi(); }
  virtual bool jpi5(void) override { return is_addi(); }
  virtual bool jpi4(void) override { return is_bstrpick(); }
  virtual bool jpi3(void) override { return is_alsl0(); }
  virtual bool jpi2(void) override { return is_ldx(); }
  virtual bool jpi1(void) override { return is_add(); }
};
