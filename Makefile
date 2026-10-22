# Automation for the NetFlow/IPFIX analyzer workspace.

CARGO  ?= cargo
HEADER := ffi/include/netflow-analyzer.h

.PHONY: all build release test check header c-example bench fuzz sanitize clean deny install uninstall

all: build

# Debug build of the whole workspace.
build:
	$(CARGO) build

# Optimized build (produces the staticlib/cdylib used by the C example).
release:
	$(CARGO) build --release

# Run the Rust test suite.
test:
	$(CARGO) test

# Run dependency and security checks (licenses, bans, sources, advisories).
deny:
	$(CARGO) deny --locked check

# Full local verification, including formatting, Clippy, release tests, and
# the C ABI smoke test.
check:
	./tools/test.sh

# Regenerate the C header from the Rust sources (requires cbindgen).
# Install with: cargo install cbindgen
header:
	cbindgen --config ffi/cbindgen.toml --crate netflow_analyzer_ffi --output $(HEADER)

# Build and run the C integration test-bench against the release staticlib.
c-example: release
	$(MAKE) -C examples/c_integration run

bench:
	./tools/bench.sh

# Run every fuzz target for FUZZ_SECONDS each (requires cargo-fuzz and the
# nightly toolchain pinned in fuzz/rust-toolchain.toml).
FUZZ_SECONDS ?= 60
fuzz:
	./tools/fuzz.sh $(FUZZ_SECONDS)

# Run the tests under Miri and the Address/Thread sanitizers (requires the
# nightly toolchain with the miri and rust-src components).
sanitize:
	./tools/sanitize.sh

# Install the C header, the static and shared libraries, and a pkg-config file
# (netflow-analyzer.pc) so C projects can consume the library as an external
# dependency. Honors PREFIX, LIBDIR, INCLUDEDIR and DESTDIR.
PREFIX     ?= /usr/local
LIBDIR     ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
VERSION    := $(shell sed -n 's/^version = "\(.*\)"/\1/p' ffi/Cargo.toml)

install: release
	install -d $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR)/pkgconfig
	install -m 644 $(HEADER) $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 target/release/libnetflow_analyzer_ffi.a $(DESTDIR)$(LIBDIR)/
	install -m 755 target/release/libnetflow_analyzer_ffi.so $(DESTDIR)$(LIBDIR)/
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@LIBDIR@|$(LIBDIR)|' \
	    -e 's|@INCLUDEDIR@|$(INCLUDEDIR)|' -e 's|@VERSION@|$(VERSION)|' \
	    ffi/netflow-analyzer.pc.in > $(DESTDIR)$(LIBDIR)/pkgconfig/netflow-analyzer.pc

uninstall:
	rm -f $(DESTDIR)$(INCLUDEDIR)/netflow-analyzer.h \
	    $(DESTDIR)$(LIBDIR)/libnetflow_analyzer_ffi.a \
	    $(DESTDIR)$(LIBDIR)/libnetflow_analyzer_ffi.so \
	    $(DESTDIR)$(LIBDIR)/pkgconfig/netflow-analyzer.pc

# Run the reference UDP listener (Ctrl-C to stop). ADDR overrides the bind addr.
ADDR ?= 0.0.0.0:2055
udp-listener:
	$(CARGO) run -p netflow_analyzer_core --example udp_listener -- $(ADDR)

clean:
	$(CARGO) clean
	rm -f examples/c_integration/demo
