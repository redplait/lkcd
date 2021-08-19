INCLUDE=..

all: dtest

ksyms.o: ksyms.cc

kmods.o: kmods.cc

kopts.o: kopts.cc

dtest: dtest.c kmods.o kopts.o ksyms.o
	g++ -lstdc++ -o dtest -I $(INCLUDE) $^
