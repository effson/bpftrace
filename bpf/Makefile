obj-m := kernel_module.o

KERNELBUILD := /lib/modules/$(shell uname -r)/build

default:
        make -C $(KERNELBUILD) M=$(shell pwd) modules
