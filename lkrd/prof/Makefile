INC = ../../../ELFIO/

%.o: %.cc
	$(COMPILE.cc) -I $(INC) $(OUTPUT_OPTION) $<

etest: eread.o lditer.o test.o
	g++ -g -o $@ $^ -lstdc++

test_p.so: eread.cc
	g++ -shared -o $@ -I $(INC) -fpic -pg $^ -lstdc++

test.so: eread.cc
	g++ -shared -o $@ -I $(INC) -fpic -finstrument-functions $^ -lstdc++
