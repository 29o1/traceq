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

clean:
	$(MAKE) -C cli clean

distclean: clean

.PHONY: all cli install clean distclean

# Unified workspace entry points. Capture builds do not load anything on a device.
PYTHON ?= python3

deps-cli:
	rustup toolchain install 1.95.0 --profile minimal
	$(PYTHON) tools/rust_workspace.py fetch --locked

deps-host:
	$(PYTHON) tools/dependencies.py host

capture-host:
	$(PYTHON) tools/build_capture.py host

capture-android:
	$(PYTHON) tools/build_capture.py android

capture-ios:
	$(PYTHON) tools/build_capture.py ios

check-capture-build:
	$(PYTHON) tests/test_capture_build.py

check-cli: cli
	$(PYTHON) tests/test_native_cli.py
	$(PYTHON) tests/test_retired_formats.py
	$(PYTHON) tests/test_scope_ranges.py
	$(PYTHON) tools/rust_workspace.py test --locked -p traceq-core --test encode_capacity
	$(PYTHON) tests/test_write_stream.py
	$(PYTHON) tests/test_state_stream.py
	$(PYTHON) tests/test_find_value_stream.py

check-cli-clean:
	$(PYTHON) tools/check_cli_clean.py

check-find-value: cli
	$(PYTHON) tests/test_find_value_stream.py

check-multiply: cli capture-host
	$(PYTHON) tests/integration/check_multiply.py

check-literal: cli capture-host
	$(PYTHON) tests/integration/check_literal.py

check-registers:
	$(PYTHON) tests/integration/check_registers.py

check-transpose: cli capture-host
	$(PYTHON) tests/integration/check_transpose.py

check-polymul: cli capture-host
	$(PYTHON) tests/integration/check_polymul.py

check-aes: cli capture-host
	$(PYTHON) tests/integration/check_aes.py

check-bitops: cli capture-host
	$(PYTHON) tests/integration/check_bitops.py

check-prefetch: cli capture-host
	$(PYTHON) tests/integration/check_prefetch.py

check-st2: cli capture-host
	$(PYTHON) tests/integration/check_st2.py

check-structure: cli capture-host
	$(PYTHON) tests/integration/check_structure.py

check-simd: cli capture-host
	$(PYTHON) tests/integration/check_simd.py

check-invoke-android: cli capture-android
	$(PYTHON) tests/integration/check_invoke.py

check: check-cli check-capture-build
	$(PYTHON) tools/build_capture.py host --tests
	$(PYTHON) tests/integration/check_capture.py
	$(PYTHON) tests/integration/check_state.py
	$(PYTHON) tests/integration/check_owner.py
	$(PYTHON) tests/integration/check_scope.py
	$(PYTHON) tests/integration/check_multiply.py
	$(PYTHON) tests/integration/check_literal.py
	$(PYTHON) tests/integration/check_registers.py
	$(PYTHON) tests/integration/check_bitops.py
	$(PYTHON) tests/integration/check_prefetch.py
	$(PYTHON) tests/integration/check_st2.py
	$(PYTHON) tests/integration/check_structure.py
	$(PYTHON) tests/integration/check_simd.py

# Explicit device check; the normal build only prepares local artifacts.
check-gum-context-android: capture-android
	$(PYTHON) tests/integration/check_gum_context.py

.PHONY: deps-cli deps-host capture-host capture-android capture-ios
.PHONY: check check-cli check-cli-clean check-capture-build check-find-value
.PHONY: check-multiply check-literal check-registers check-transpose check-polymul +	check-aes check-bitops check-prefetch check-st2 check-structure check-simd
.PHONY: check-invoke-android check-gum-context-android
