CXX      := clang++
CLI      := ../cli
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wno-unused-parameter -I$(CLI)/include -Iharness

CAPSTONE_PREFIX := $(shell brew --prefix capstone 2>/dev/null)
ifneq ($(CAPSTONE_PREFIX),)
  CXXFLAGS += -DGUMTRACE_HAVE_CAPSTONE -I$(CAPSTONE_PREFIX)/include
  CAP_LDFLAGS := -L$(CAPSTONE_PREFIX)/lib -lcapstone
endif

ifndef GT_NO_SQLITE
  SQL_LDFLAGS := -lsqlite3
else
  CXXFLAGS += -DGT_NO_SQLITE
endif

LDFLAGS := $(SQL_LDFLAGS) $(CAP_LDFLAGS)

SRC := harness/corpus.cpp harness/legacy.cpp harness/selftest.cpp harness/main.cpp
OBJ := $(SRC:.cpp=.o)

all: gt-harness

# links libgumtrace: the hot-path measurement needs in-process timing, which a
# black-box CLI invocation cannot provide
gt-harness: $(OBJ) $(CLI)/libgumtrace.a
	$(CXX) $(CXXFLAGS) $(OBJ) $(CLI)/libgumtrace.a -o $@ $(LDFLAGS)

$(CLI)/libgumtrace.a:
	$(MAKE) -C $(CLI) libgumtrace.a

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: gt-harness
	./gt-harness selftest

# full A/B suite: python drives the CLI, the harness supplies the corpus
run: gt-harness
	$(MAKE) -C $(CLI) gt
	python3 run.py

clean:
	rm -f gt-harness harness/*.o

.PHONY: all test run clean
