# Automation for the NetFlow/IPFIX analyzer workspace.

CARGO  ?= cargo
HEADER := include/netflow-analyzer.h

.PHONY: all build release test header c-example clean

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

# Regenerate the C header from the Rust sources (requires cbindgen).
# Install with: cargo install cbindgen
header:
	cbindgen --config ffi/cbndgen.toml --crate netflow_analyzer_ffi --output $(HEADER)

# Build and run the C integration test-bench against the release staticlib.
c-example: release
	$(MAKE) -C examples/c_integration run

# Run the reference UDP listener (Ctrl-C to stop). ADDR overrides the bind addr.
ADDR ?= 0.0.0.0:2055
udp-listener:
	$(CARGO) run -p netflow_analyzer_core --example udp_listener -- $(ADDR)

clean:
	$(CARGO) clean
	rm -f examples/c_integration/demo
