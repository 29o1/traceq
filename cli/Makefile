CXX      ?= c++
CPPFLAGS ?=
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wno-unused-parameter
LDFLAGS  ?=
LDLIBS   ?=
AR       ?= ar
INCLUDES := -Iinclude

LIB_SRC := src/site.cpp src/recorder.cpp src/event_decoder.cpp src/ingest.cpp \
	src/export.cpp src/queries.cpp src/import.cpp
LIB_OBJ := $(LIB_SRC:.cpp=.o)
HEADERS := $(wildcard include/traceq/*.h) $(wildcard src/*.h)

all: gt

# libtraceq: text import, .gtb parsing/expansion, and queries.
libtraceq.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

%.o: %.cpp $(HEADERS)
	$(CXX) $(CPPFLAGS) $(INCLUDES) $(CXXFLAGS) -c $< -o $@

gt: src/main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< libtraceq.a $(LDLIBS) -o $@

# correctness suite: upstream-log fixtures through the product path
gt-test: tests/test_main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< libtraceq.a $(LDLIBS) -o $@

test: gt-test
	./gt-test

clean:
	rm -f gt gt-test libtraceq.a src/*.o tests/*.o

.PHONY: all test clean
