libjarm64.so: bpf_jit_comp.o arm64.o ../jshared.o ../jmem.o
	gcc -shared -o $@ $^ -lstdc++

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

%.o: %.c
	$(COMPILE.c) -fPIC $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE.cc) -fPIC $(OUTPUT_OPTION) $<

clean:
	rm -f *.o *.so