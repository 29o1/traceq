# traceq — two independent subprojects.
#
#   cli/    the product: libtraceq + the `gt` CLI.
#           Knows nothing about benchmarks.
#   bench/  product-self benchmarks: a python driver that measures the
#           shipping `gt` binary from the outside, on real trace files only
#           (bench/traces/). Nothing to compile here.

all: cli

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

cli:
	$(MAKE) -C cli

# correctness: the cli test suite (upstream-log fixtures through import/query)
test:
	$(MAKE) -C cli test

# Install the agent-facing CLI on the current user's PATH without sudo.
install: cli
	mkdir -p "$(BINDIR)"
	install -m 755 cli/gt "$(BINDIR)/gt"

# benchmark on real traces -> bench/reports/<UTCts>-<gitsha>/
report: cli
	cd bench && python3 run.py run

clean:
	$(MAKE) -C cli clean
	rm -rf bench/build

distclean: clean

.PHONY: all cli test install report clean distclean
