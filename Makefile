# traceq — libtraceq and the `traceq` CLI.

all: cli

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

cli:
	$(MAKE) -C cli

# Install the agent-facing CLI on the current user's PATH without sudo.
install: cli
	mkdir -p "$(BINDIR)"
	install -m 755 cli/traceq "$(BINDIR)/traceq"
	ln -sfn traceq "$(BINDIR)/gt"

clean:
	$(MAKE) -C cli clean

distclean: clean

.PHONY: all cli install clean distclean

# Unified workspace entry points. Capture builds do not load anything on a device.
PYTHON ?= python3

deps-host:
	$(PYTHON) tools/dependencies.py host

capture-host:
	$(PYTHON) tools/build_capture.py host

capture-android:
	$(PYTHON) tools/build_capture.py android

capture-ios:
	$(PYTHON) tools/build_capture.py ios

check-cli: cli
	$(PYTHON) tests/test_write_stream.py
	$(PYTHON) tests/test_state_stream.py

check: check-cli
	$(PYTHON) tools/build_capture.py host --tests
	$(PYTHON) tests/integration/check_capture.py
	$(PYTHON) tests/integration/check_state.py
	$(PYTHON) tests/integration/check_owner.py

.PHONY: deps-host capture-host capture-android capture-ios check-cli check
