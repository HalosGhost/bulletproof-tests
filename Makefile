INCDIR = ../../bulletproofs/elements/include
LIBDIR = ../../bulletproofs/elements/.libs
CFLAGS = -O0 -ggdb -g -Wall -Wextra -Wpedantic -std=c18
LDFLAGS = -L $(LIBDIR) -I $(INCDIR) -lsecp256k1
SOURCES = $(wildcard *.c)
SINKS = $(patsubst %.c,%,$(SOURCES))

RM = rm -rf --

.PHONY: all run clean

all: run

clean:
	$(RM) $(SINKS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: $(SINKS)
	for i in $(SINKS); do LD_LIBRARY_PATH=$(LIBDIR) ./$$i; done

$(V).SILENT:
