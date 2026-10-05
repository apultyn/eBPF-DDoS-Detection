CLANG    ?= clang
CFLAGS   ?= -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu

# HeavyKeeper decay base b: a bucket decays with probability b^-count
HK_DECAY ?= 1.08
LUT_SIZE  = 64

SRC = heavy_keeper.xdp.c
OBJ = heavy_keeper.xdp.o
LUT = hk_decay_lut.h

all: $(OBJ)

$(OBJ): $(SRC) heavy_keeper.h $(LUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

# lut[c] = b^-c * 2^32, compared against bpf_get_prandom_u32()
$(LUT): Makefile
	python3 -c 'print("\n".join("0x%08xu," % min(int($(HK_DECAY) ** -c * 2**32), 0xffffffff) for c in range($(LUT_SIZE))))' > $@

clean:
	rm -f $(OBJ) $(LUT)

.PHONY: all clean
