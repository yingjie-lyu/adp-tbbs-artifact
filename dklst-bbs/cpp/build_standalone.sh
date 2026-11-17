#!/usr/bin/env bash
# Standalone build of the libOTe shim with its self-check `main()`.
#
#   ./cpp/build_standalone.sh [output-dir]
#
# Not needed for the Rust build (build.rs does that); this exists so the shim can be compiled,
# run and debugged without going through cargo.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LIBOTE="${LIBOTE_DIR:-$HERE/../../libOTe}"
BUILD="$LIBOTE/out/build/linux"
OUT="${1:-/tmp}"

INCLUDES=(
  "-I$BUILD"
  "-I$LIBOTE"
  "-I$BUILD/cryptoTools"
  "-I$LIBOTE/cryptoTools"
  "-I$BUILD/coproto"
  "-I$LIBOTE/out/coproto"
  "-I$BUILD/macoro"
  "-I$LIBOTE/out/macoro"
  "-I$LIBOTE/out/function2/include"
  "-I$LIBOTE/out/libdivide"
)

LIBS=(
  "-L$BUILD/libOTe"
  "-L$BUILD/cryptoTools/cryptoTools"
  "-L$BUILD/coproto/coproto"
  "-L$BUILD/macoro/macoro"
  -llibOTe -lcryptoTools -lcoproto -lmacoro -lcoproto -lmacoro -lpthread
)

set -x
g++ -O3 -std=c++20 -DNDEBUG -DLIBOTE_SHIM_MAIN \
  -maes -msse2 -msse3 -mssse3 -msse4.1 -mpclmul -mavx -mavx2 \
  -mavx512f -mavx512vl -mavx512bw -mavx512dq -mbmi2 \
  "${INCLUDES[@]}" -no-pie \
  "$HERE/libote_shim.cc" "${LIBS[@]}" -o "$OUT/ot_bench"
