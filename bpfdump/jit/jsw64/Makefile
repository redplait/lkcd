libjsw64.so: bpf_jit_comp.o ../jshared.o
	gcc -shared -o $@ $^

../jshared.o: ../jshared.c
	gcc -g -c -fPIC ../jshared.c -o $@

bpf_jit_comp.o: bpf_jit_comp.c
	gcc -g -c -fPIC bpf_jit_comp.c

clean:
	rm -f *.o *.so