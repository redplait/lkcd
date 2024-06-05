obj-m += lkcd.o 
lkcd-objs += lkcd_km.o

ifneq ($(ARCH), mips)
ifneq ($(ARCH), arm64)
MACHINE ?= $(shell uname -m)
ifeq ($(MACHINE),x86_64)
lkcd-objs += getgs.o arm64.bti/arm64bti.o
add-target := getgs.o
endif
else
lkcd-objs += arm64.bti/arm64bti.o
endif
endif

all: $(add-target)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

getgs.o: getgs.asm
	nasm -f elf64 -o getgs.o getgs.asm
	touch .getgs.o.cmd
  
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean