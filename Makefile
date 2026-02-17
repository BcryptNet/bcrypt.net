#!/usr/bin/make -f
#SHELL:=/bin/bash

default: help
help: # Show help for each of the Makefile recipes.
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m:$$(echo $$l | cut -f 2- -d'#')\n"; done

.PHONY: all
all:
	@echo "Usage: make [target]"
	@exit 0

.PHONY: ci-test
ci-test: ## Run tests in CI with code coverage
	@dotnet run --configuration Release --coverage --coverage-output-format cobertura --report-github

.PHONY: build-alpha-package:
	@dotnet pack src/BCrypt.Net/BCrypt.Net.csproj --version-suffix 5.0.0-alpha -o artifacts

