# Builds the C test-bench against the Rust static library.

ROOT    := ../..
INCLUDE := $(ROOT)/ffi/include
LIBDIR  := $(ROOT)/target/release
STATIC  := $(LIBDIR)/libnetflow_analyzer_ffi.a

CC       ?= cc
CXX      ?= c++
CFLAGS   := -Wall -Wextra -O2 -I$(INCLUDE)
CXXFLAGS := -Wall -Wextra -O2 -std=c++11 -I$(INCLUDE)
# Rust staticlibs need the system threading / dynamic-loader / math libs.
LDLIBS  := -lpthread -ldl -lm

.PHONY: all lib clean run check

all: demo

# Build the FFI crate's static archive.
lib:
	cargo build --release -p netflow_analyzer_ffi --manifest-path $(ROOT)/Cargo.toml

# Build the demo, linking in abi_checks.o. Compiling abi_checks.c as C11 fires
# its struct size/alignment/layout `static_assert`s; linking it pulls in the
# export probe, so the linker must resolve every public symbol from the archive.
demo: lib main.c abi_checks.c
	$(CC) $(CFLAGS) -std=c11 -c abi_checks.c -o abi_checks.o
	$(CC) $(CFLAGS) main.c abi_checks.o $(STATIC) $(LDLIBS) -o demo

# The header must also compile as C++11 (re-firing the layout asserts under
# C++), and the static library must export exactly the public symbols.
check: lib abi_checks.c
	$(CXX) $(CXXFLAGS) -x c++ -fsyntax-only abi_checks.c
	$(ROOT)/tools/check_symbols.sh

run: demo check
	./demo

clean:
	rm -f demo abi_checks.o
