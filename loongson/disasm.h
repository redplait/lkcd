#pragma once
#include <ua.hpp>
#include "ops.inc"

typedef struct {
    ea_t pc;
    uint32_t value;
    int fcond;
    int num_ops; // max 4
    insn_t *insn;
} DisasContext;

int LoongsonDisassemble(unsigned int opcode, DisasContext *out);