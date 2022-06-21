INCLUDE=-Itest -g

%.o: %.cc
	$(COMPILE.cc) $(INCLUDE) $(OUTPUT_OPTION) $<

jtest: jtest.o ujit.o
	g++ -g -lstdc++ -o $@ $^ -ldl
