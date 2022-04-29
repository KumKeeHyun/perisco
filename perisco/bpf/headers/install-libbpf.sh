rm ./*.c ./*.h

LIBBPF_VERSION=0.6.1
prefix=libbpf-"$LIBBPF_VERSION"

headers=(
    "$prefix"/LICENSE.BSD-2-Clause
    "$prefix"/src/*.c
    "$prefix"/src/*.h
)

# Fetch libbpf release and extract the desired headers
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz --xform='s#.*/##' "${headers[@]}"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# wget "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz"
# tar -C . -xzf v${LIBBPF_VERSION}.tar.gz $prefix/src $prefix/include

# mv $prefix/src/*.c .
# mv $prefix/src/*.h .

# rm -r $prefix
# rm v${LIBBPF_VERSION}.tar.gz