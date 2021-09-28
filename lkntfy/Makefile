obj-m += lkntfy.o 
lkntfy-objs += lkntfy_km.o

MACHINE ?= $(shell uname -m)
ifeq ($(MACHINE),x86_64)
lkntfy-objs += cr0.o 
add-target := cr0.o
endif

all: $(add-target)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

cr0.o: cr0.asm
	nasm -f elf64 -o cr0.o cr0.asm
	touch .cr0.o.cmd

clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
