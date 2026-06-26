# Builds the C test-bench against the Rust static library.

ROOT    := ../..
INCLUDE := $(ROOT)/include
LIBDIR  := $(ROOT)/target/release
STATIC  := $(LIBDIR)/libnetflow_analyzer_ffi.a

CC      ?= cc
CFLAGS  := -Wall -Wextra -O2 -I$(INCLUDE)
# Rust staticlibs need the system threading / dynamic-loader / math libs.
LDLIBS  := -lpthread -ldl -lm

.PHONY: all lib clean run

all: demo

# Build the FFI crate's static archive.
lib:
	cargo build --release -p netflow_analyzer_ffi --manifest-path $(ROOT)/Cargo.toml

demo: lib main.c
	$(CC) $(CFLAGS) main.c $(STATIC) $(LDLIBS) -o demo

run: demo
	./demo

clean:
	rm -f demo
