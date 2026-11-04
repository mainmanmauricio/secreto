# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

.PHONY: build test vectors vectors-check interop check \
	build-rust build-python build-cpp \
	test-rust test-python test-cpp test-cpp-asan \
	package package-deb package-rpm \
	install install-deb install-rpm \
	uninstall uninstall-deb uninstall-rpm \
	reinstall reinstall-deb reinstall-rpm

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
export CARGO_TARGET_DIR := $(ROOT)/rust/target
PYTHON_VENV := $(ROOT)/python/.venv
CPP_BUILD := $(ROOT)/cpp/build
CPP_ASAN_BUILD := $(ROOT)/cpp/build-asan

PKG_NAME := secreto
DEB_DIR := $(CARGO_TARGET_DIR)/debian
RPM_DIR := $(CARGO_TARGET_DIR)/generate-rpm

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

# ---- Linux packages (Rust CLI via cargo-deb / cargo-generate-rpm) -----------

package: package-deb package-rpm

package-deb: build-rust
	@command -v cargo-deb >/dev/null || { echo "cargo-deb not found; install with: cargo install cargo-deb"; exit 1; }
	mkdir -p $(DEB_DIR)
	cd $(ROOT)/rust && cargo deb -p secreto-cli --no-dbgsym -o $(DEB_DIR)
	@echo "built: $$(ls -1t $(DEB_DIR)/$(PKG_NAME)*.deb | head -1)"

package-rpm: build-rust
	@command -v cargo-generate-rpm >/dev/null || { echo "cargo-generate-rpm not found; install with: cargo install cargo-generate-rpm"; exit 1; }
	mkdir -p $(RPM_DIR)
	cd $(ROOT)/rust/crates/secreto-cli && cargo generate-rpm -o $(RPM_DIR)
	@echo "built: $$(ls -1t $(RPM_DIR)/$(PKG_NAME)*.rpm | head -1)"

install-deb: package-deb
	@deb=$$(ls -1t $(DEB_DIR)/$(PKG_NAME)*.deb 2>/dev/null | head -1); \
	test -n "$$deb" || { echo "no .deb found under $(DEB_DIR)"; exit 1; }; \
	sudo dpkg -i "$$deb"

install-rpm: package-rpm
	@rpm=$$(ls -1t $(RPM_DIR)/$(PKG_NAME)*.rpm 2>/dev/null | head -1); \
	test -n "$$rpm" || { echo "no .rpm found under $(RPM_DIR)"; exit 1; }; \
	if command -v dnf >/dev/null; then sudo dnf -y install "$$rpm"; \
	elif command -v zypper >/dev/null; then sudo zypper --non-interactive install "$$rpm"; \
	elif command -v yum >/dev/null; then sudo yum -y localinstall "$$rpm"; \
	elif command -v rpm >/dev/null; then sudo rpm -Uvh "$$rpm"; \
	else echo "no rpm/dnf/yum/zypper found"; exit 1; fi

uninstall-deb:
	@if dpkg -s $(PKG_NAME) >/dev/null 2>&1; then sudo dpkg -r $(PKG_NAME); \
	else echo "$(PKG_NAME) is not installed"; fi

uninstall-rpm:
	@if ! { command -v rpm >/dev/null && rpm -q $(PKG_NAME) >/dev/null 2>&1; }; then \
		echo "$(PKG_NAME) is not installed"; \
	elif command -v dnf >/dev/null; then sudo dnf -y remove $(PKG_NAME); \
	elif command -v zypper >/dev/null; then sudo zypper --non-interactive remove $(PKG_NAME); \
	elif command -v yum >/dev/null; then sudo yum -y remove $(PKG_NAME); \
	elif command -v rpm >/dev/null; then sudo rpm -e $(PKG_NAME); \
	else echo "no rpm/dnf/yum/zypper found"; exit 1; fi

reinstall-deb: uninstall-deb
	@$(MAKE) install-deb

reinstall-rpm: uninstall-rpm
	@$(MAKE) install-rpm

# Auto-pick package format from the host packaging tools.
install:
	@if command -v dpkg >/dev/null && { [ -f /etc/debian_version ] || command -v apt-get >/dev/null; }; then \
		$(MAKE) install-deb; \
	elif command -v rpm >/dev/null || command -v dnf >/dev/null || command -v yum >/dev/null || command -v zypper >/dev/null; then \
		$(MAKE) install-rpm; \
	else echo "unsupported host: need dpkg (deb) or rpm/dnf/yum/zypper"; exit 1; fi

uninstall:
	@if command -v dpkg >/dev/null && { [ -f /etc/debian_version ] || command -v apt-get >/dev/null; }; then \
		$(MAKE) uninstall-deb; \
	elif command -v rpm >/dev/null || command -v dnf >/dev/null || command -v yum >/dev/null || command -v zypper >/dev/null; then \
		$(MAKE) uninstall-rpm; \
	else echo "unsupported host: need dpkg (deb) or rpm/dnf/yum/zypper"; exit 1; fi

reinstall:
	@if command -v dpkg >/dev/null && { [ -f /etc/debian_version ] || command -v apt-get >/dev/null; }; then \
		$(MAKE) reinstall-deb; \
	elif command -v rpm >/dev/null || command -v dnf >/dev/null || command -v yum >/dev/null || command -v zypper >/dev/null; then \
		$(MAKE) reinstall-rpm; \
	else echo "unsupported host: need dpkg (deb) or rpm/dnf/yum/zypper"; exit 1; fi
