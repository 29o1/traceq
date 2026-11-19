# traceq — libtraceq and the `traceq` CLI.

all: cli

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

cli:
	$(MAKE) -C cli

# Install the product CLI on the current user's PATH without sudo.
install: cli
	mkdir -p "$(BINDIR)"
	install -m 755 cli/traceq "$(BINDIR)/traceq"

clean:
	$(MAKE) -C cli clean

distclean: clean

.PHONY: all cli install clean distclean

# Unified workspace entry points. Capture builds do not load anything on a device.
PYTHON ?= python3

deps-cli:
	rustup toolchain install 1.95.0 --profile minimal
	$(PYTHON) tools/rust_workspace.py fetch --locked

capture-android:
	$(PYTHON) tools/build_capture.py android

.PHONY: deps-cli capture-android

-include tests/Makefile evaluation/Makefile release/Makefile
