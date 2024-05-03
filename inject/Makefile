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
# I can't use aarch64-linux-gnu-as --version
# > GNU assembler (GNU Binutils for Ubuntu) 2.34
# during compilation I got
# > Error: selected processor does not support `bti c'
a64.o: a64.S
	~/disc/src/binutils-gdb/gas/as-new -o $@ $^

a64.bin: a64.o
	aarch64-linux-gnu-ld -Ttext 200000 -o $@ $^

a64: a64.bin
	aarch64-linux-gnu-objcopy --dump-section .text=$@ $^

a64.inc: a64
	perl ./bin.pl a64 > $@
	-rm a64.o a64.bin
