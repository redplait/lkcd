INCLUDE=-I../test -I../../ELFIO -I../../udis86 -DHAS_ELFIO
LIBPATH=../../udis86/libudis86

%.o: %.cc
	$(COMPILE.cc) $(INCLUDE) $(OUTPUT_OPTION) $<

%.o: %.c
	$(COMPILE.c) -I .. $(OUTPUT_OPTION) $<

lkmem: lkmem.o x64_disasm.o ../test/ksyms.o ../test/lk.o ../test/kmods.o
	g++ -lstdc++ -o lkmem -I $(INCLUDE) $^ $(LIBPATH)/libudis86.a
