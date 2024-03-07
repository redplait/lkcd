INC = ../../../ELFIO/

%.o: %.cc
	$(COMPILE.cc) -I $(INC) $(OUTPUT_OPTION) $<

etest: libprelf.so lditer.o test.o
	g++ -g -o $@ $^ -L . -lprelf -lstdc++

libprelf_p.so: eread.cc
	g++ -shared -o $@ -I $(INC) -fpic -g -pg $^ -lstdc++

libprelf.so: eread.cc
	g++ -shared -o $@ -I $(INC) -fpic -finstrument-functions $^ -lstdc++
