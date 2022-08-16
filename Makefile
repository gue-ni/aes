# @file Makefile
# @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
# @date 10.01.2020

CC 	   = gcc
CFLAGS = -std=c99 -Wall -fopenmp -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_SVID_SOURCE -D_POSIX_C_SOURCE=200809L -g
LFLAGS = -lm -fopenmp

PROGS  = aes pkcs7 aes-128-cbc aes_omp
DEPS   = common 

.PHONY: all clean debug

all: $(PROGS)

debug: clean
debug: CFLAGS+=-DDEBUG
debug: all

$(PROGS): %: %.o $(DEPS:=.o)
	$(CC) -o $@ $^ $(LFLAGS)

%.o: %.c $(DEPS:=.h)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o $(PROGS)
