CC = riscv64-unknown-elf-gcc
AR = riscv64-unknown-elf-ar

CFLAGS = -march=rv64im -mabi=lp64 -nostdlib -ffreestanding -O2 -Wall -Wextra -Iinclude
LDFLAGS = -nostdlib -T linker/linker.ld

LIBCSRC = $(wildcard src/string/*.c) $(wildcard src/syscall/*.c)

OBJ = $(patsubst %.c,%.o,$(LIBCSRC))

all: libc.a crt0.o

libc.a: $(OBJ)
	$(AR) rcs $@ $^

crt0.o:
	$(CC) $(CFLAGS) -c src/crt/crt0.S -o crt0.o

hello: examples/hello.c libc.a crt0.o
	$(CC) $(CFLAGS) examples/hello.c crt0.o -L. -lc $(LDFLAGS) -o hello

run: hello
	qemu-riscv64 ./hello

objdump:
	riscv64-unknown-elf-objdump -d hello

clean:
	rm -f $(OBJ) libc.a crt0.o hello
