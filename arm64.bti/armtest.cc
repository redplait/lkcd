#include <stdio.h>
#include <stdlib.h>
#include "armadillo.h"
#include "arm64thunk.h"

extern "C" const char *decode_cond(unsigned int cond);

static const char *const AD_TYPE_TABLE[] = {
    "AD_OP_REG", "AD_OP_IMM", "AD_OP_SHIFT"
};

static const char *const AD_SHIFT_TABLE[] = {
    "AD_SHIFT_LSL", "AD_SHIFT_LSR", "AD_SHIFT_ASR", "AD_SHIFT_ROR", "AD_SHIFT_MSL"
};

static const char *const AD_IMM_TYPE_TABLE[] = {
    "AD_IMM_INT", "AD_IMM_UINT", "AD_IMM_LONG", "AD_IMM_ULONG", "AD_IMM_FLOAT"
};

static const char *const AD_GROUP_TABLE[] = {
    "AD_G_Reserved", "AD_G_DataProcessingImmediate", "AD_G_BranchExcSys", "AD_G_LoadsAndStores",
    "AD_G_DataProcessingRegister", "AD_G_DataProcessingFloatingPoint", "AD_G_SVE"
};

static const char *GET_GEN_REG(const char *const *rtbl, unsigned int idx,
        int prefer_zr){
    if(idx > 31)
        return "reg idx oob";

    if(idx == 31 && prefer_zr)
        idx++;

    return rtbl[idx];
}

static const char *GET_FP_REG(const char *const *rtbl, unsigned int idx)
{
    if(idx > 31)
        return "reg idx oob";

    return rtbl[idx];
}

static void disp_operand(struct ad_operand operand)
{
    printf("\t\tThis operand is of type %s\n", AD_TYPE_TABLE[operand.type]);

    if(operand.type == AD_OP_REG){
        if(operand.op_reg.sysreg != AD_NONE)
            printf("\t\t\tSystem register: %d\n", operand.op_reg.sysreg);
        else{
            printf("\t\t\tRegister: ");

            if(operand.op_reg.fp)
                printf("%s size %lX\n", GET_FP_REG(operand.op_reg.rtbl, operand.op_reg.rn), operand.op_reg.sz);
            else{
                const char *reg = GET_GEN_REG(operand.op_reg.rtbl, operand.op_reg.rn, operand.op_reg.zr);
                printf("%s size %lX\n", reg, operand.op_reg.sz);
            }
        }
    }
    else if(operand.type == AD_OP_SHIFT){
        printf("\t\t\tShift type: %s\n\t\t\tAmount: %d\n",
                AD_SHIFT_TABLE[operand.op_shift.type], operand.op_shift.amt);
    }
    else if(operand.type == AD_OP_IMM){
        printf("\t\t\tImmediate type: %s\n\t\t\tValue: ", AD_IMM_TYPE_TABLE[operand.op_imm.type]);

        if(operand.op_imm.type == AD_IMM_INT){
            int v = (int)operand.op_imm.bits;
            printf("%s%#x\n", v < 0 ? "-" : "", v < 0 ? -v : v);
        }
        else if(operand.op_imm.type == AD_IMM_UINT)
            printf("%#x\n", (unsigned int)operand.op_imm.bits);
        else if(operand.op_imm.type == AD_IMM_LONG){
            long v = (long)operand.op_imm.bits;
            printf("%s%#lx\n", v < 0 ? "-" : "", v < 0 ? -v : v);
        }
        else if(operand.op_imm.type == AD_IMM_ULONG)
#ifdef _MSC_VER
            printf("%#I64x\n", operand.op_imm.bits);
#else
            printf("%#lx\n", (unsigned long)operand.op_imm.bits);
#endif /* _MSC_VER */
        else if(operand.op_imm.type == AD_IMM_FLOAT)
            printf("%f\n", *(float *)&operand.op_imm.bits);
        else{
            printf("Unknown immediate type and didn't crash?\n");
            abort();
        }
    }
    else{
        printf("\t\t\tUnknown type and didn't crash?\n");
        abort();
    }
}

static void disp_insn(struct ad_insn *insn){
    printf("Disassembled: %s\n", insn->decoded);

    if(insn->group == AD_NONE)
        return;

    printf("\tThis instruction has %d decode fields (from left to right):\n", insn->num_fields);

    printf("\t\t");
    for(int i=0; i<insn->num_fields-1; i++)
        printf("%#x, ", insn->fields[i]);

    printf("%#x\n", insn->fields[insn->num_fields - 1]);

    printf("\tThis instruction has %d operands (from left to right):\n", insn->num_operands);

    for(int i=0; i<insn->num_operands; i++)
        disp_operand(insn->operands[i]);

    if(insn->cc != AD_NONE){
        const char *cc = decode_cond(insn->cc);
        printf("\tCode condition: %s\n", cc);
    }
}

void dump_decode(struct ad_insn *insn, unsigned char *body)
{
  armadillo_init(insn);
  ArmadilloDisassemble(*(unsigned int *)body, (unsigned long)body, insn);
  disp_insn(insn);
}

int check_thunk(unsigned char *body, unsigned char *off)
{
  int res = arm64_make_thunk(body, off);
  if ( res )
  {
    printf("arm64_make_thunk return %d\n", res);
    return res;
  }
  // decode and dump 2 instruction in thunk
  struct ad_insn insn;
  dump_decode(&insn, body);
  dump_decode(&insn, body + 4);
  // for last instruction check first operand
  if ( insn.operands[0].type == AD_OP_IMM && insn.operands[0].op_imm.bits == (unsigned long)off )
    printf("test passed\n");
  else
    printf("test failed, must be %lX but operand is %lX\n", (unsigned long)off, insn.operands[0].op_imm.bits);
  return 0;
}

int main()
{
  unsigned char *body = (unsigned char *)malloc(8);
  printf("body at %p\n", body);
  printf("test b %p\n", body + 0x120);
  check_thunk(body, body + 0x120);
  printf("test b %p\n", body - 0x120);
  check_thunk(body, body - 0x120);
  printf("test b %p\n", body + 0x72345678);
  check_thunk(body, body + 0x72345678);
  printf("test b %p\n", body - 0x72345678);
  check_thunk(body, body - 0x72345678);
  free(body);
}