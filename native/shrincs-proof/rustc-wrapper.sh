#!/bin/sh
# Keep checkout and Cargo-cache paths out of the guest's committed image.
set -eu
compiler=$1
shift
task_cargo_root=${CARGO_HOME:-"$HOME/.cargo"}
exec "$compiler" "--remap-path-prefix=$BTC_PQ_REMAP_ROOT=/btc-pq" \
    "--remap-path-prefix=$task_cargo_root=/cargo" "$@"
