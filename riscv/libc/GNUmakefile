CC = riscv64-unknown-elf-gcc
AR = riscv64-unknown-elf-ar

CFLAGS = -march=rv64im -mabi=lp64 -nostdlib -ffreestanding -O2 -Wall -Wextra -Iinclude
LDFLAGS = -nostdlib -T linker/linker.ld

SRC = \
	src/syscall/syscall.c \
	src/string/strlen.c \
	src/string/memcpy.c \
	src/string/memset.c

OBJ = $(SRC:.c=.o)

all: libc.a crt0.o

libc.a: $(OBJ)
	$(AR) rcs $@ $^

crt0.o:
	$(CC) $(CFLAGS) -c src/crt/crt0.S -o crt0.o

hello: examples/hello.c
	$(CC) $(CFLAGS) examples/hello.c crt0.o libc.a $(LDFLAGS) -o hello

run: example
	qemu-riscv64 ./hello

clean:
	rm -f $(OBJ) libc.a crt0.o hello
