CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wno-unused-parameter -Iinclude
AR       := ar

LIB_SRC := src/site.cpp src/recorder.cpp src/ingest.cpp src/queries.cpp src/import.cpp
LIB_OBJ := $(LIB_SRC:.cpp=.o)
HEADERS := $(wildcard include/traceq/*.h)

all: gt

# libtraceq: text import, .gtb parsing/expansion, and queries.
libtraceq.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

gt: src/main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $< libtraceq.a -o $@

# correctness suite: upstream-log fixtures through the product path
gt-test: tests/test_main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $< libtraceq.a -o $@

test: gt-test
	./gt-test

clean:
	rm -f gt gt-test libtraceq.a src/*.o tests/*.o

.PHONY: all test clean
