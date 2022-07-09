#include <map>
#include <list>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "ebpf_disasm.h"

// most of code ripped from https://github.com/cylance/eBPF_processor
struct bpf_op
{
  const char *name;
  void (*dump)(FILE *, const char *, const struct bpf_insn *);
};

static void reg_imm64(FILE *fp, const char *name, const struct bpf_insn *op)
{
  unsigned int vlow = (unsigned int)op->imm;
  unsigned long vhigh = (unsigned long)op[1].imm << 32;
  unsigned long val = vlow | vhigh;
  fprintf(fp, "%s r%d, %lX\n", name, op->dst_reg, val);
}

static void reg_imm(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s r%d, %d\n", name, op->dst_reg, op->imm);
}

static void reg1(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s r%d\n", name, op->dst_reg);
}

static void reg2(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s r%d, r%d\n", name, op->dst_reg, op->src_reg);
}

static void phrase_imm(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s r0, [%d]\n", name, op->imm);
}

static void reg_regdisp(FILE *fp, const char *name, const struct bpf_insn *op)
{
  if ( op->code == 0x40 || op->code == 0x48 || op->code == 0x50 || op->code == 0x58 )
    fprintf(fp, "%s r0, [r%d + %d]\n", name, op->src_reg, op->imm);
  else
    fprintf(fp, "%s r%d, [r%d + %d]\n", name, op->dst_reg, op->src_reg, op->off);
}

static void regdisp_reg(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s [r%d + %d], r%d\n", name, op->dst_reg, op->off, op->src_reg);
}

static void lock(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s [r%d + %d], r%d, %d\n", name, op->dst_reg, op->off, op->src_reg, op->imm);
}

static void nop(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s\n", name);
}

static void jmp(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s %d\n", name, op->off);
}

static void call(FILE *fp, const char *op_name, const struct bpf_insn *op)
{
  a64 base = get_addr("__bpf_call_base");
  if ( base )
  {
    a64 addr = base + (int)op->imm;
    const char *name = name_by_addr(addr);
    if ( name != NULL )
      fprintf(fp, "%s 0x%X ; %s\n", op_name, op->imm, name);
    else
      fprintf(fp, "%s 0x%X ; %lX\n", op_name, op->imm, addr);
  } else
    fprintf(fp, "%s 0x%X\n", op_name, op->imm);
}

static void jmp_reg_imm(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s r%d, %d, %d\n", name, op->dst_reg, op->imm, op->off);
}

static void jmp_reg_reg(FILE *fp, const char *name, const struct bpf_insn *op)
{
  fprintf(fp, "%s r%d, r%d, %d\n", name, op->dst_reg, op->src_reg, op->off);
}

std::map<int, bpf_op> s_ops;

void init_ops()
{
  // alu
  s_ops[0x07] = { "add", reg_imm };
  s_ops[0x0f] = { "add", reg2 };
  s_ops[0x17] = { "sub", reg_imm };
  s_ops[0x1f] = { "sub", reg2 };
  s_ops[0x27] = { "mul", reg_imm };
  s_ops[0x2f] = { "mul", reg2 };
  s_ops[0x37] = { "div", reg_imm };
  s_ops[0x3f] = { "div", reg2 };
  s_ops[0x47] = { "or", reg_imm };
  s_ops[0x4f] = { "or", reg2 };
  s_ops[0x57] = { "and", reg_imm };
  s_ops[0x5f] = { "and", reg2 };
  s_ops[0x67] = { "lsh", reg_imm };
  s_ops[0x6f] = { "lsh", reg2 };
  s_ops[0x77] = { "rsh", reg_imm };
  s_ops[0x7f] = { "rsh", reg2 };
  s_ops[0x87] = { "neg", reg1 };
  s_ops[0x97] = { "mod", reg_imm };
  s_ops[0x9f] = { "mod", reg2 };
  s_ops[0xa7] = { "xor", reg_imm };
  s_ops[0xaf] = { "xor", reg2 };
  s_ops[0xb7] = { "mov", reg_imm };
  s_ops[0xbf] = { "mov", reg2 };
  s_ops[0xc7] = { "arsh", reg_imm };
  s_ops[0xcf] = { "arsh", reg2 };
  // alu32
  s_ops[0x04] = { "add", reg_imm };
  s_ops[0x14] = { "sub", reg_imm };
  s_ops[0x24] = { "mul", reg_imm };
  s_ops[0x34] = { "div", reg_imm };
  s_ops[0x44] = { "or", reg_imm };
  s_ops[0x54] = { "and", reg_imm };
  s_ops[0x64] = { "lsh", reg_imm };
  s_ops[0x74] = { "rsh", reg_imm };
  s_ops[0x84] = { "neg", reg1 };
  s_ops[0x94] = { "mod", reg_imm };
  s_ops[0xa4] = { "xor", reg_imm };
  s_ops[0xb4] = { "mov", reg_imm };
  // byteswap
  s_ops[0xd4] = { "le", reg_imm };
  s_ops[0xdc] = { "be", reg_imm };
  // mem
  s_ops[0x18] = { "lddw", reg_imm64 };
  s_ops[0x20] = { "ldaw", phrase_imm },
  s_ops[0x28] = { "ldah", phrase_imm },
  s_ops[0x30] = { "ldab", phrase_imm },
  s_ops[0x38] = { "ldadw", phrase_imm };
  // indirect loads
  s_ops[0x40] = { "ldinw", reg_regdisp };
  s_ops[0x48] = { "ldinh", reg_regdisp };
  s_ops[0x50] = { "ldinb", reg_regdisp };
  s_ops[0x58] = { "ldindw", reg_regdisp };
  s_ops[0x61] = { "ldxw", reg_regdisp };
  s_ops[0x69] = { "ldxh", reg_regdisp };
  s_ops[0x71] = { "ldxb", reg_regdisp };
  s_ops[0x79] = { "ldxdw", reg_regdisp };

  s_ops[0x62] = { "stw", regdisp_reg };
  s_ops[0x6a] = { "sth", regdisp_reg };
  s_ops[0x72] = { "stb", regdisp_reg };
  s_ops[0x7a] = { "stdw", regdisp_reg };
  s_ops[0x63] = { "stxw", regdisp_reg };
  s_ops[0x6b] = { "stxh", regdisp_reg };
  s_ops[0x73] = { "stxb", regdisp_reg };
  s_ops[0x7b] = { "stxdw", regdisp_reg };
  // lock
  s_ops[0xc3] = { "lock", lock };
  s_ops[0xdb] = { "lock", lock };
  // jumps
  s_ops[0x05] = { "ja", jmp };
  s_ops[0x15] = { "jeq", jmp_reg_imm };
  s_ops[0x1d] = { "jeq", jmp_reg_reg };
  s_ops[0x25] = { "jgt", jmp_reg_imm };
  s_ops[0x2d] = { "jgt", jmp_reg_reg };
  s_ops[0x35] = { "jge", jmp_reg_imm };
  s_ops[0x3d] = { "jge", jmp_reg_reg };
  s_ops[0x45] = { "jset", jmp_reg_imm };
  s_ops[0x4d] = { "jset", jmp_reg_reg };
  s_ops[0x55] = { "jne", jmp_reg_imm };
  s_ops[0x5d] = { "jne", jmp_reg_reg };
  s_ops[0x65] = { "jsgt", jmp_reg_imm };
  s_ops[0x6d] = { "jsgt", jmp_reg_reg };
  s_ops[0x75] = { "jsge", jmp_reg_imm };
  s_ops[0x7d] = { "jsge", jmp_reg_reg };
  s_ops[0xa5] = { "jlt", jmp_reg_imm };
  s_ops[0xad] = { "jlt", jmp_reg_reg };
  s_ops[0xc5] = { "jslt", jmp_reg_imm };
  s_ops[0xcd] = { "jslt", jmp_reg_reg };
  s_ops[0xd5] = { "jsle", jmp_reg_imm };
  s_ops[0xdd] = { "jsle", jmp_reg_reg };
  // call
  s_ops[0x85] = { "call", call };
  // retn
  s_ops[0x95] = { "ret", nop };
}

void ebpf_disasm(unsigned char *buf, long len, FILE *out_fp)
{
  if ( s_ops.empty() )
    init_ops();
  for ( long i = 0; i < len; i++, buf += sizeof(bpf_insn) )
  {
     bpf_insn *op = (bpf_insn *)buf;
     auto li = s_ops.find(op->code);
     if ( li == s_ops.end() )
       fprintf(out_fp, "%ld %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X invalid opcode %X\n", i, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], op->code);
     else {
       if ( op->code == 0x18 )
       {
         fprintf(out_fp, "%ld %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X ", i, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
           buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
         );
         li->second.dump(out_fp, li->second.name, op);
         ++i;
         buf += sizeof(bpf_insn);
       } else
       {
         fprintf(out_fp, "%ld %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X %2.2X ", i, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
         li->second.dump(out_fp, li->second.name, op);
       }
     }
  }
}