#
# Makefile for the Linux minix filesystem routines.
#

obj-$(CONFIG_MINIX_FS) += minix.o

minix-objs := bitmap.o itree_v1.o itree_v2.o namei.o inode.o file.o dir.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Werror -Werror=implicit-function-declaration

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm bitmap.o.ur-safe

