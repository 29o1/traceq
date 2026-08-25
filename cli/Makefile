CXX      ?= c++
CPPFLAGS ?=
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wno-unused-parameter
LDFLAGS  ?=
LDLIBS   ?=
AR       ?= ar
INCLUDES := -Iinclude

LIB_SRC := src/site.cpp src/recorder.cpp src/event_decoder.cpp src/ingest.cpp \
	src/export.cpp src/query_taint.cpp src/query_compare.cpp \
	src/query_lookup.cpp src/query_calls.cpp src/import.cpp
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

clean:
	rm -f gt libtraceq.a src/*.o

.PHONY: all clean
