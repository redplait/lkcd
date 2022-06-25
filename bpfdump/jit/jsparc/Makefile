libjsparc.so: bpf_jit_comp_64.o ../jshared.o ../jmem.o
	gcc -shared -o $@ $^ -lstdc++

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

bpf_jit_comp_64.o: bpf_jit_comp_64.c
	gcc -c -fPIC $^

%.o: %.cc
	$(COMPILE.cc) -fPIC $(OUTPUT_OPTION) $<

clean:
	rm -f *.o *.so