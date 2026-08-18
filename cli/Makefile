CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wno-unused-parameter -Iinclude
AR       := ar

CAPSTONE_PREFIX := $(shell brew --prefix capstone 2>/dev/null)
ifneq ($(CAPSTONE_PREFIX),)
  CXXFLAGS += -DGUMTRACE_HAVE_CAPSTONE -I$(CAPSTONE_PREFIX)/include
  CAP_LDFLAGS := -L$(CAPSTONE_PREFIX)/lib -lcapstone
endif

LDFLAGS := $(CAP_LDFLAGS)

LIB_SRC := src/site.cpp src/recorder.cpp src/ingest.cpp src/queries.cpp src/import.cpp
LIB_OBJ := $(LIB_SRC:.cpp=.o)
HEADERS := $(wildcard include/traceq/*.h)

all: gt

# libtraceq: the reusable core (site compiler, recorder, expander, queries).
# Deliberately free of any event source — see include/traceq/event.h.
libtraceq.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

gt: src/main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $< libtraceq.a -o $@ $(LDFLAGS)

# correctness suite: upstream-log fixtures + ExecEvent literals, no simulator
gt-test: tests/test_main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $< libtraceq.a -o $@ $(LDFLAGS)

test: gt-test
	./gt-test

clean:
	rm -f gt gt-test libtraceq.a src/*.o tests/*.o

.PHONY: all test clean
