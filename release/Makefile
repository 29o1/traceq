# Source packaging runs from the developer checkout against an explicit Git snapshot.
RELEASE_ARCHIVE ?= build/release/traceq-source.tar.gz

check-source-release:
	$(PYTHON) tests/test_source_release.py
	$(PYTHON) release/source_archive.py "$(or $(RELEASE_REF),HEAD)"

source-release:
	$(PYTHON) release/source_archive.py "$(RELEASE_REF)" --output "$(RELEASE_ARCHIVE)"

.PHONY: check-source-release source-release
