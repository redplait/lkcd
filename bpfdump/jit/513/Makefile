libjx64.so: bpf_jit_comp.o ../jshared.o sort.o j64.o ../jmem.o
	gcc -shared -o $@ $^ -lstdc++

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

%.o: %.c
	$(COMPILE.c) -fPIC -D_DEBUG $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE.cc) -fPIC $(OUTPUT_OPTION) $<

clean:
	rm -f *.o *.so