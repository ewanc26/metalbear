SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the project (Debug)
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
	cmake --build build -j"$$(nproc 2>/dev/null || echo 4)"

.PHONY: build-release
build-release: ## Build the project (Release)
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build -j"$$(nproc 2>/dev/null || echo 4)"

.PHONY: test
test: build ## Build and run tests
	ctest --test-dir build --output-on-failure -j"$$(nproc 2>/dev/null || echo 4)"

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf build

.PHONY: run
run: build ## Build and run the metalbear binary
	./build/metalbear

.PHONY: fmt
fmt: ## Reformat C sources (clang-format if available)
	if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i src/*.c include/**/*.h; \
	else \
		echo "clang-format not found; skipping"; \
	fi

.PHONY: check
check: ## Compile without building tests
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMETALBEAR_BUILD_TESTS=OFF
	cmake --build build -j"$$(nproc 2>/dev/null || echo 4)"
