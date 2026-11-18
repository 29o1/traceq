# Evaluation is opt-in and has its own Cargo workspace and binary.
eval-cli:
	$(PYTHON) tools/rust_workspace.py build --locked --release --manifest-path ../evaluation/runner/Cargo.toml
	mkdir -p build/evaluation
	install -m 755 .deps/rust/target/release/traceq-eval build/evaluation/traceq-eval

check-eval: cli eval-cli
	$(PYTHON) tools/rust_workspace.py test --locked --manifest-path ../evaluation/runner/Cargo.toml
	$(PYTHON) evaluation/test_entry.py

.PHONY: eval-cli check-eval
