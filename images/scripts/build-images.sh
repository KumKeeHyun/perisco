#!/bin/bash

root_dir="$(git rev-parse --show-toplevel)"
perisco_dockerfile="${root_dir}/images/perisco/Dockerfile"

cd "${root_dir}"
docker build -f "${perisco_dockerfile}" -t kbzjung359/perisco:0.0.2 .