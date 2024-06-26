#!make -f
ELFIO=../../ELFIO
SRCS=injparams.cc injparams2.cc hd.cc test.cc
TLIBS=-lstdc++ -ldl
GOPT=-g -gdwarf-4
A64FLAGS=-I $(ELFIO) -Os -fpic

all: a.out test.so

test.so: payload.c
	gcc -g -O -o test.so -fpic -shared payload.c

# don`t remove -fpic options, see details https://maskray.me/blog/2021-01-09-copy-relocations-canonical-plt-entries-and-protected
a.out: hm.inc
	gcc -I $(ELFIO) -fpic $(GOPT) $(SRCS) $(TLIBS)

hack.o: hack.asm
	yasm -f elf64 -o $@ $^

hm: hm.asm
	yasm -o hm hm.asm

hm.inc: hm
	perl ./bin.pl hm > hm.inc

dis: test.so
	objdump -d test.so -M intel --disassemble=inject

# aarch64 related stuff
a64.out: a64.ainc a64_nobti.ainc $(SRCS)
	aarch64-linux-gnu-g++-9 $(A64FLAGS) -o $@ $(SRCS) $(TLIBS)

# test a64.pl and compare it's results with a64.out
a64.patched: a64.ainc a64_nobti.ainc $(SRCS)
	aarch64-linux-gnu-g++-9 -S $(A64FLAGS) $(SRCS)
	perl ../scripts/a64.pl -mg -F alist $(SRCS:.cc=.s)
	aarch64-linux-gnu-as -o injparams.o injparams.s
	aarch64-linux-gnu-as -o injparams2.o injparams2.s
	aarch64-linux-gnu-as -o hd.o hd.s
	aarch64-linux-gnu-as -o test.o test.s
	aarch64-linux-gnu-g++-9 -o $@ $(SRCS:.cc=.o) $(TLIBS)

a64_nobti.S: a64.S
	grep -v "BTI marker" $^ > $@

# awful looking pattern match rule to make .ainc from aarch64 .S file
%.ainc: %.S
	aarch64-linux-gnu-as -o $@.o $^
	aarch64-linux-gnu-ld -Ttext 200000 -o $@.bin $@.o
	aarch64-linux-gnu-objcopy --dump-section .text=a64 $@.bin
	perl ./bin.pl a64 > $@
	-rm $@.o $@.bin

# loongarch related stuff
l64.o: loongarch.S
	~/disc/src/binutils-gdb/gas/as-new -o $@ $^

l64.bin: l64.o
	~/disc/src/binutils-gdb/ld/ld-new -Ttext 200000 -o $@ $^

l64: l64.bin
	~/disc/src/binutils-gdb/binutils/objcopy --dump-section .text=$@ $^

l64.inc: l64
	perl ./bin.pl a64 > $@
#	-rm l64

