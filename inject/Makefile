#!make -f
ELFIO=../../ELFIO

all: a.out test.so

test.so: payload.c
	gcc -o test.so -fpic -shared payload.c

# don`t remove -fpic options, see details https://maskray.me/blog/2021-01-09-copy-relocations-canonical-plt-entries-and-protected
a.out: test.cc hm.inc injparams.cc injparams2.cc
	gcc -I $(ELFIO) -fpic -g -gdwarf-4 injparams.cc injparams2.cc test.cc -lstdc++ -ldl

hack.o: hack.asm
	yasm -f elf64 -o $@ $^

hm: hm.asm
	yasm -o hm hm.asm

hm.inc: hm
	perl ./bin.pl hm > hm.inc
