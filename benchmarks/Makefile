#!/usr/bin/make -f
#SHELL:=/bin/bash

default: help
help: # Show help for each of the Makefile recipes.
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m:$$(echo $$l | cut -f 2- -d'#')\n"; done

.PHONY: all
all:
	@echo "Usage: make [target]"
	@exit 0

.PHONY: run-release-benchmark
run-release-benchmark: # compares nuget releases of this package
	@dotnet run --configuration Benchmarks --project benchmarks/Release-Benchmarks/Release-Benchmarks.csproj

.PHONY: run-method-benchmarks
run-method-benchmarks: # compares methods against older versions of this package
	@dotnet run --configuration Benchmarks --project benchmarks/Method-Benchmarks/Method-Benchmarks.csproj

.PHONY: run-diagnostic-benchmarks
run-diagnostic-benchmarks: # benchmarks the main entry point with vs diagnostics enabled
	@dotnet run --configuration Benchmarks --project benchmarks/Diagnostic-Benchmarks/Diagnostic-Benchmarks.csproj
