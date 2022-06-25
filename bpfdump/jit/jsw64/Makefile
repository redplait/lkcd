libjsw64.so: bpf_jit_comp.o ../jshared.o ../jmem.o
	gcc -shared -o $@ $^ -lstdc++

../jshared.o: ../jshared.c
	gcc -g -c -fPIC ../jshared.c -o $@

bpf_jit_comp.o: bpf_jit_comp.c
	gcc -g -c -fPIC bpf_jit_comp.c

%.o: %.cc
	$(COMPILE.cc) -fPIC $(OUTPUT_OPTION) $<

clean:
	rm -f *.o *.so