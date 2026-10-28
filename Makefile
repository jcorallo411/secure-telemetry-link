#. Secure Telemetry Link build
#
# Warnings are errors. On a project whose whole point is parser safety, a
# warning you learned to scroll past is a bug you have agreed to ship.

CXX      ?= g++
CXXSTD   := -std=c++17
WARN     := -Wall -Wextra -Wpedantic -Werror \
            -Wconversion -Wsign-conversion -Wshadow \
            -Wcast-qual -Wformat=2 -Wundef -Wdouble-promotion
OPT      ?= -O2 -g
HARDEN   := -fstack-protector-strong -D_FORTIFY_SOURCE=2
INCLUDES := -Iflight/include

CXXFLAGS := $(CXXSTD) $(WARN) $(OPT) $(HARDEN) $(INCLUDES)

BUILD    := build
LIB_SRC  := flight/src/sha256.cpp \
            flight/src/hmac.cpp \
            flight/src/protocol.cpp \
            flight/src/replay.cpp \
            flight/src/secure_link.cpp \
            flight/src/sensors.cpp \
            flight/src/keys.cpp \
            flight/src/counter_store.cpp \
            flight/src/udp.cpp
LIB_OBJ  := $(patsubst flight/src/%.cpp,$(BUILD)/%.o,$(LIB_SRC))

TEST_SRC := flight/tests/test_main.cpp
VEC_SRC  := tools/vectors.cpp

.PHONY: all clean test asan fuzz fuzz-run vectors check

all: $(BUILD)/flight_computer $(BUILD)/vectors

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: flight/src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/flight_computer: $(LIB_OBJ) flight/src/main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(LIB_OBJ) flight/src/main.cpp -o $@

$(BUILD)/vectors: $(LIB_OBJ) $(VEC_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(LIB_OBJ) $(VEC_SRC) -o $@

$(BUILD)/tests: $(LIB_OBJ) $(TEST_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(LIB_OBJ) $(TEST_SRC) -o $@

test: $(BUILD)/tests
	@./$(BUILD)/tests

# Same tests under AddressSanitizer and UndefinedBehaviorSanitizer. A parser
# bug that does not crash a plain build will usually crash here.
asan: | $(BUILD)
	$(CXX) $(CXXSTD) $(WARN) -O1 -g -fsanitize=address,undefined \
	    -fno-omit-frame-pointer $(INCLUDES) \
	    $(LIB_SRC) $(TEST_SRC) -o $(BUILD)/tests_asan
	@./$(BUILD)/tests_asan

vectors: $(BUILD)/vectors
	@./$(BUILD)/vectors

# libFuzzer build. Needs a clang whose compiler-rt is installed; on Debian and
# Ubuntu that is the libclang-rt-<version>-dev package. Override with
# `make fuzz FUZZ_CXX=clang++-18` if a different version has the runtime.
FUZZ_CXX ?= $(shell for c in clang++ clang++-18 clang++-17 clang++-16 clang++-15; do \
	    command -v $$c >/dev/null 2>&1 || continue; \
	    d=$$($$c -print-runtime-dir 2>/dev/null); \
	    if [ -n "$$d" ] && [ -f "$$d/libclang_rt.fuzzer-x86_64.a" ]; then \
	        echo $$c; exit 0; fi; done; echo clang++)

fuzz: | $(BUILD)
	@echo "fuzzing compiler: $(FUZZ_CXX)"
	$(FUZZ_CXX) $(CXXSTD) -O1 -g $(INCLUDES) \
	    -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
	    $(LIB_SRC) fuzz/fuzz_parser.cpp -o $(BUILD)/fuzz_parser

FUZZ_SECONDS ?= 60
fuzz-run: fuzz
	@mkdir -p fuzz/corpus fuzz/findings
	./$(BUILD)/fuzz_parser fuzz/corpus -max_total_time=$(FUZZ_SECONDS) \
	    -artifact_prefix=fuzz/findings/ -print_final_stats=1

# Everything that should pass before a commit.
check: test asan vectors
	@python3 -m pytest ground/tests -q
	@echo "all checks passed"

clean:
	rm -rf $(BUILD) fuzz/findings
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
