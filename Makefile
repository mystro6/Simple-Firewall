obj-m += hook.o
#KBUILD_EXTRA_SYMBOLS := /home/ercantunc/firewall/Module.symvers
all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean