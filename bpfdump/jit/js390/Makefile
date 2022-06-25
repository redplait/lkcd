libjs390.so: bpf_jit_comp.o ../jshared.o ../jmem.o
	gcc -shared -o $@ $^

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

bpf_jit_comp.o: bpf_jit_comp.c
	gcc -c -fPIC bpf_jit_comp.c

%.o: %.cc
	$(COMPILE.cc) -fPIC $(OUTPUT_OPTION) $<

clean:
	rm -f *.o *.so