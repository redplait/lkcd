obj-m += lkntfy.o 
lkntfy-objs += lkntfy_km.o

all: $(add-target)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
