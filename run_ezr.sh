#!/bin/bash
TARGET=${1:-libpng}
DURATION=${2:-3600}
RESULTS_DIR="$(pwd)/ezr_results"
mkdir -p "$RESULTS_DIR"

docker run -it --rm \
    --user root \
    --privileged \
    -v "$RESULTS_DIR":/ezr/work \
    ezr_fuzzer \
    --target "$TARGET" \
    --duration "$DURATION"
