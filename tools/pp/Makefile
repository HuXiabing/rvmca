SRC = src/pp.c src/profile.S src/init.S
TOOLCHAIN := riscv64-unknown-linux-gnu-gcc

pp: $(SRC) src/count.h src/pp.h
	$(TOOLCHAIN) -march=rv64gv $(SRC) -O2 --static -o pp

clean:
	rm pp
