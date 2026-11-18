# Local regression and native lab entry points.
deps-host:
	$(PYTHON) tools/dependencies.py host

capture-host:
	$(PYTHON) tests/integration/build_host.py

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
	$(PYTHON) tests/check_cli_clean.py

RELEASE_REF ?= HEAD
RELEASE_ARCHIVE ?= build/release/traceq-source.tar.gz
check-source-release:
	$(PYTHON) tests/test_source_release.py
	$(PYTHON) tests/check_source_release.py "$(RELEASE_REF)"

source-release:
	$(PYTHON) tests/check_source_release.py "$(RELEASE_REF)" --output "$(RELEASE_ARCHIVE)"

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

check-allocator-android: cli capture-android
	$(PYTHON) tests/integration/check_allocator.py

check: check-cli check-capture-build
	$(PYTHON) tests/integration/build_host.py --tests
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

.PHONY: deps-host capture-host
.PHONY: check check-cli check-cli-clean check-source-release source-release check-capture-build check-find-value
.PHONY: check-multiply check-literal check-registers check-transpose check-polymul
.PHONY: check-aes check-bitops check-prefetch check-st2 check-structure check-simd
.PHONY: check-invoke-android check-allocator-android check-gum-context-android
