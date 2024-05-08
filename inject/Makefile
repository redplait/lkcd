#!make -f
ELFIO=../../ELFIO

all: a.out test.so

test.so: payload.c
	gcc -g -O -o test.so -fpic -shared payload.c

# don`t remove -fpic options, see details https://maskray.me/blog/2021-01-09-copy-relocations-canonical-plt-entries-and-protected
a.out: test.cc hm.inc injparams.cc injparams2.cc hd.cc
	gcc -I $(ELFIO) -fpic -g -gdwarf-4 injparams.cc injparams2.cc hd.cc test.cc -lstdc++ -ldl

hack.o: hack.asm
	yasm -f elf64 -o $@ $^

hm: hm.asm
	yasm -o hm hm.asm

hm.inc: hm
	perl ./bin.pl hm > hm.inc

dis: test.so
	objdump -d test.so -M intel --disassemble=inject

# aarch64 related stuff
a64.o: a64.S
	aarch64-linux-gnu-as -o $@ $^

a64.bin: a64.o
	aarch64-linux-gnu-ld -Ttext 200000 -o $@ $^

a64: a64.bin
	aarch64-linux-gnu-objcopy --dump-section .text=$@ $^

a64.inc: a64
	perl ./bin.pl a64 > $@
	-rm a64.o a64.bin

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

