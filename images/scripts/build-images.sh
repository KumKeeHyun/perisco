#!/bin/bash

root_dir="$(git rev-parse --show-toplevel)"
perisco_dir="${root_dir}/perisco"
perisco_dockerfile="${root_dir}/images/perisco/Dockerfile"

cd "${perisco_dir}"
make bpf

cd "${root_dir}"
docker build -f "${perisco_dockerfile}" -t kbzjung359/perisco:0.0.1 .