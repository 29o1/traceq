PYTHON ?= python3
RUST_CLI := ../.deps/rust/target/release/traceq
RUST_SOURCES := $(shell find ../rust/traceq-cli ../rust/traceq-query ../rust/traceq-core -type f \( -name '*.rs' -o -name '*.json' -o -name '*.txt' -o -name 'Cargo.toml' \))
RUST_SOURCES += ../rust/Cargo.toml ../rust/Cargo.lock ../tools/rust_workspace.py

all: traceq

$(RUST_CLI): $(RUST_SOURCES)
	$(PYTHON) ../tools/rust_workspace.py build --locked --release -p traceq-cli

traceq: $(RUST_CLI) Makefile
	cp $(RUST_CLI) $@.new
	chmod 755 $@.new
	mv $@.new $@

clean:
	rm -f traceq gt

.PHONY: all clean
