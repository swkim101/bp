CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=

BINS := bp

all: $(BINS)

bp: bp.c prepare.c apply.c
	$(CC) $(CFLAGS) -o $@ bp.c prepare.c apply.c $(LDFLAGS)

clean:
	rm -f $(BINS)

.PHONY: all clean
