libjx64.so: bpf_jit_comp.o ../jshared.o sort.o j64.o
	gcc -shared -o $@ $^

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

%.o: %.c
	$(COMPILE.c) -fPIC $(OUTPUT_OPTION) $<

clean:
	rm -f *.o *.so