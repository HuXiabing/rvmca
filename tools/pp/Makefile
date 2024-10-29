SRC = pp.c profile.S init.S
TOOLCHAIN := riscv64-unknown-linux-gnu-gcc

pp:
	cd src && $(TOOLCHAIN) -march=rv64gv $(SRC) -O2 --static -o ../pp

clean:
	rm pp
