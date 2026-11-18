PYTHON ?= python3
RUST_CLI := ../.deps/rust/target/release/traceq
all: traceq

build-rust:
	$(PYTHON) ../tools/rust_workspace.py build --locked --release -p traceq-cli

traceq: build-rust
	@if ! test -x "$@" || ! cmp -s "$(RUST_CLI)" "$@"; then \
		set -e; staged=$$(mktemp "$@.XXXXXX"); \
		trap 'rm -f "$$staged"' EXIT; \
		install -m 755 "$(RUST_CLI)" "$$staged"; \
		mv "$$staged" "$@"; \
	fi

clean:
	rm -f traceq

.PHONY: all build-rust clean
