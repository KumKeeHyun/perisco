CLANG ?= clang-14
STRIP ?= llvm-strip-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# path where go.mod is located
REPODIR := $(realpath ../..)

# podman if installed, otherwise docker
CONTAINER_ENGINE ?= $(if $(shell command -v podman), podman, docker)

# ebpf-builder image
BUILDER_IMAGE := $(shell cat EBPF_BUILDER_IMAGE)

.PHONY: container-build container-shell clean generate

.DEFAULT_TARGET = container-build

# Build ELF binaries using a containerized LLVM toolchain.
container-build:
	sudo ${CONTAINER_ENGINE} run --rm \
		-v "${REPODIR}":/perisco -w /perisco/perisco/bpf --env MAKEFLAGS \
		--env HOME="/tmp" \
		"${BUILDER_IMAGE}" \
		$(MAKE) generate

# (debug) 
container-shell:
	sudo ${CONTAINER_ENGINE} run --rm -ti \
		-v "${REPODIR}":/perisco -w /perisco \
		"${BUILDER_IMAGE}"

clean:
	rm *.o

# BPF_CLANG, BPF_CFLAGS is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate .
