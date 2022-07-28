INCLUDE=-I../../../ELFIO -I../../../udis86 -I../../../arm64 -DHAS_ELFIO
UDIS86PATH=../../../udis86/libudis86
ARM64PATH=../../../arm64

%.o: %.cc
	$(COMPILE.cc) $(INCLUDE) $(OUTPUT_OPTION) $<

%.o: %.c
	$(COMPILE.c) -I .. $(OUTPUT_OPTION) $<

ldso: ldso.o x64_disasm.o bm_search.o dis_base.o ldso.o main.o
	g++ -o $@ -I $(INCLUDE) $^ $(UDIS86PATH)/libudis86.a -ldl -lstdc++

clean:
	rm *.o
