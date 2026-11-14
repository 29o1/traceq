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
LIB_SRC += src/query_last_writers.cpp
LIB_SRC += src/state_stream.cpp src/query_state_stream.cpp
LIB_SRC += src/query_context.cpp
LIB_OBJ := $(LIB_SRC:.cpp=.o)
HEADERS := $(wildcard include/traceq/*.h) $(wildcard src/*.h)

all: traceq gt

# libtraceq: text import, .gtb parsing/expansion, and queries.
libtraceq.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

%.o: %.cpp $(HEADERS)
	$(CXX) $(CPPFLAGS) $(INCLUDES) $(CXXFLAGS) -c $< -o $@

traceq: src/main.o libtraceq.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< libtraceq.a $(LDLIBS) -o $@

# Compatibility for existing scripts; help and continuation commands use traceq.
gt: traceq
	ln -sfn traceq gt

clean:
	rm -f traceq gt libtraceq.a src/*.o

.PHONY: all clean gt
