INCLUDE=-I../test -I../../ELFIO -I../../udis86 -I../../arm64 -DHAS_ELFIO
UDIS86PATH=../../udis86/libudis86
ARM64PATH=../../arm64
# comment this for release version
DEBUGOPTS=-g -gdwarf-4

%.o: %.cc
	$(COMPILE.cc) $(INCLUDE) $(OUTPUT_OPTION) $<

%.o: %.c
	$(COMPILE.c) -I .. $(OUTPUT_OPTION) $<

lkmem: lkmem.o minfo.o x64_disasm.o arm64_disasm.o ebpf_disasm.o ujit.o ../test/ksyms.o ../test/lk.o ../test/kmods.o
	g++ $(DEBUGOPTS) -lstdc++ -o lkmem -I $(INCLUDE) $^ $(UDIS86PATH)/libudis86.a $(ARM64PATH)/libarm64.a -ldl

vmtest: vmtest.cc x64_disasm.o arm64_disasm.o ../test/ksyms.o
	g++ $(DEBUGOPTS) -lstdc++ -o $@ $(INCLUDE) $^ $(UDIS86PATH)/libudis86.a $(ARM64PATH)/libarm64.a

../test/ksyms.o: ../test/ksyms.cc

kdps: kdps.o ../test/ksyms.o ../test/lk.o ../test/kmods.o
	g++ -lstdc++ -o kdps -I $(INCLUDE) $^

clean:
	rm *.o
