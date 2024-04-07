#!make -f
all: a.out test.so

test.so: payload.c
	gcc -o test.so -fpic -shared payload.c

a.out: test.cc hm.inc
	gcc -g -gdwarf-4 test.cc -lstdc++ -ldl

hm: hm.asm
	yasm -o hm hm.asm

hm.inc: hm
	perl ./bin.pl hm > hm.inc
