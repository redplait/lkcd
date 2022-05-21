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
  { 3 },  // 2 if and only if not using bi/bih
  { 4 },  // 3
  { 5 },  // 4
  { 6 },  // 5
  { 7 },  // 6
  { 0 },
};

class loongson_jump_pattern_t : public jump_pattern_t
{
protected:
  enum {
   regA, rJ, rS, rIdx, rBase, rBase2, rMax
  };
  ea_t add_off;
  int is_ge; // for bge(u)
public:
  loongson_jump_pattern_t(switch_info_t *_si)
   : jump_pattern_t(_si, lsw1_depends, rMax)
  {
    add_off = NULL;
    is_ge = 0;
  }
  virtual bool handle_mov(tracked_regs_t &_regs) override;
  bool finish();
  // 0..7
  virtual bool jpi7(void) override;
  virtual bool jpi6(void) override;
  virtual bool jpi5(void) override;
  virtual bool jpi4(void) override;
  virtual bool jpi3(void) override;
  virtual bool jpi2(void) override;
  virtual bool jpi1(void) override;
  virtual bool jpi0(void) override;
};
