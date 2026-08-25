# traceq — libtraceq and the `gt` CLI.

all: cli

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

cli:
	$(MAKE) -C cli

# Install the agent-facing CLI on the current user's PATH without sudo.
install: cli
	mkdir -p "$(BINDIR)"
	install -m 755 cli/gt "$(BINDIR)/gt"

clean:
	$(MAKE) -C cli clean

distclean: clean

.PHONY: all cli install clean distclean
