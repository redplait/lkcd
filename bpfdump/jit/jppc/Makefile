libjppc.so: bpf_jit_comp64.o ../jshared.o ../jmem.o
	gcc -shared -o $@ $^ -lstdc++

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

%.o: %.cc
	$(COMPILE.cc) -fPIC $(OUTPUT_OPTION) $<

bpf_jit_comp64.o: bpf_jit_comp64.c
	gcc -c -fPIC $^

clean:
	rm -f *.o *.so