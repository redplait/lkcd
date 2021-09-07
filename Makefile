obj-m += lkcd.o 
lkcd-objs += lkcd_km.o

MACHINE ?= $(shell uname -m)
ifeq ($(MACHINE),x86_64)
lkcd-objs += getgs.o 
add-target := getgs.o
endif

all: $(add-target)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

getgs.o: getgs.asm
	nasm -f elf64 -o getgs.o getgs.asm
	touch .getgs.o.cmd
  
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean