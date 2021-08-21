INCLUDE=-I../test -I../../ELFIO -DHAS_ELFIO

%.o: %.cc
	$(COMPILE.cc) $(INCLUDE) $(OUTPUT_OPTION) $<

lkmem: lkmem.o ../test/ksyms.o
	g++ -lstdc++ -o lkmem -I $(INCLUDE) $^
