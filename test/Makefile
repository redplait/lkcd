INCLUDE=..

all: dtest ktest

ksyms.o: ksyms.cc

kmods.o: kmods.cc

kopts.o: kopts.cc

lk.o: lk.c
	$(COMPILE.c) -I $(INCLUDE) $(OUTPUT_OPTION) $<

ktest: ktest.c
	gcc -o ktest -I $(INCLUDE) $(OUTPUT_OPTION) $<

dtest: dtest.c kmods.o kopts.o ksyms.o lk.o
	g++ -lstdc++ -o dtest -I $(INCLUDE) $^
