obj-m += main.o
KDIR = /usr/src/linux-$(shell uname -r)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
