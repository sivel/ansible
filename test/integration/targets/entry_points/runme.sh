#!/usr/bin/env bash

set -eu
source virtualenv.sh
set +x
unset PYTHONPATH

base_dir="$(dirname "$(dirname "$(dirname "$(dirname "${OUTPUT_DIR}")")")")"
bin_dir="$(dirname "$(command -v pip)")"

# --version doesn't require deps
pip install "${base_dir}" --disable-pip-version-check --no-deps
# --use-feature=in-tree-build not available on all platforms

for bin in "${bin_dir}/ansible"*; do
    name="$(basename "${bin}")"

    echo "=== ${name}=${bin} ==="

    if [ "${name}" == "ansible-test" ]; then
        "${bin}" --help | tee /dev/stderr | grep -Eo "^usage:\ ansible-test\ .*"
    else
        "${bin}" --version | tee /dev/stderr | grep -Eo "(^${name}\ \[core\ .*|executable location = ${bin}$)"
    fi
done
