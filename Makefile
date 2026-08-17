# GumTrace-ng — two independent subprojects.
#
#   cli/    the target project: libgumtrace + the `gt` CLI.
#           Knows nothing about benchmarks or synthetic corpora.
#   bench/  the evaluation harness: a python driver that measures cli/ from the
#           outside, plus a small C++ binary supplying the event source and the
#           in-process per-event timing that a black-box CLI run cannot provide.

all: cli bench

cli:
	$(MAKE) -C cli

bench:
	$(MAKE) -C bench

# correctness: 24 checks against libgumtrace, driven through the corpus
test:
	$(MAKE) -C bench test

# full A/B suite -> bench/build/report.md
report:
	$(MAKE) -C bench run

clean:
	$(MAKE) -C cli clean
	$(MAKE) -C bench clean

distclean: clean
	rm -rf bench/build

.PHONY: all cli bench test report clean distclean
