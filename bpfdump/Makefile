#!make -f
INCLUDE=-I /usr/lib/llvm-10/include
LIBS=-L /usr/lib/llvm-10/lib -lLLVM-10 -lstdc++

%.o: %.cpp
	clang $(INCLUDE) -c $<

lo: llvm-objdump.o ELFDump.o COFFDump.o
	clang $(INCLUDE) $(LIBS) -o lo $^
