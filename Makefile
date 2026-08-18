# traceq — two independent subprojects.
#
#   cli/    the product: libtraceq + the `gt` CLI.
#           Knows nothing about benchmarks.
#   bench/  product-self benchmarks: a python driver that measures the
#           shipping `gt` binary from the outside, on real trace files only
#           (bench/traces/). Nothing to compile here.

all: cli

cli:
	$(MAKE) -C cli

# correctness: the cli test suite (real-log fixtures + ExecEvent literals)
test:
	$(MAKE) -C cli test

# benchmark on real traces -> bench/reports/<UTCts>-<gitsha>/
report: cli
	cd bench && python3 run.py run

clean:
	$(MAKE) -C cli clean
	rm -rf bench/build

distclean: clean

.PHONY: all cli test report clean distclean
