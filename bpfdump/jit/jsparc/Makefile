libjsparc.so: bpf_jit_comp_64.o ../jshared.o
	gcc -shared -o $@ $^

../jshared.o: ../jshared.c
	gcc -c -fPIC ../jshared.c -o $@

bpf_jit_comp_64.o: bpf_jit_comp_64.c
	gcc -c -fPIC $^

clean:
	rm -f *.o *.so