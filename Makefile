.PHONY: build test vectors vectors-check interop check \
	build-rust build-python build-cpp \
	test-rust test-python test-cpp test-cpp-asan

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
export CARGO_TARGET_DIR := $(ROOT)/rust/target
PYTHON_VENV := $(ROOT)/python/.venv
CPP_BUILD := $(ROOT)/cpp/build
CPP_ASAN_BUILD := $(ROOT)/cpp/build-asan

build: build-rust build-python build-cpp

build-rust:
	cd $(ROOT)/rust && cargo build --release

build-python:
	test -d $(PYTHON_VENV) || python3 -m venv $(PYTHON_VENV)
	$(PYTHON_VENV)/bin/python -c "import secreto, cryptography" 2>/dev/null || \
		$(PYTHON_VENV)/bin/pip install -q -e '$(ROOT)/python[dev]'

build-cpp:
	cmake -S $(ROOT)/cpp -B $(CPP_BUILD) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(CPP_BUILD) -j

test: test-rust test-python test-cpp

test-rust:
	cd $(ROOT)/rust && cargo test
	cd $(ROOT)/rust && cargo clippy --workspace --all-targets -- -D warnings

test-python:
	@$(MAKE) build-python
	cd $(ROOT)/python && $(PYTHON_VENV)/bin/pytest -q

test-cpp: build-cpp
	cd $(CPP_BUILD) && ctest --output-on-failure

test-cpp-asan:
	cmake -S $(ROOT)/cpp -B $(CPP_ASAN_BUILD) \
		-DCMAKE_BUILD_TYPE=Debug -DSECRETO_SANITIZE=ON
	cmake --build $(CPP_ASAN_BUILD) -j
	cd $(CPP_ASAN_BUILD) && ASAN_OPTIONS=detect_leaks=0 ctest --output-on-failure

vectors:
	cd $(ROOT)/rust && cargo run -p secreto-vectors --release -- generate $(ROOT)/vectors/testkit

vectors-check:
	cd $(ROOT)/rust && cargo run -p secreto-vectors --release -- check $(ROOT)/vectors/testkit

interop: build
	python3 $(ROOT)/interop/run.py

check: test vectors-check interop test-cpp-asan
	@echo "all checks passed"
