#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/build}"
CC="${CC:-cc}"

UNAME=$(uname | tr '[:upper:]' '[:lower:]')
if [[ "$UNAME" == *mingw* || "$UNAME" == *msys* || "$UNAME" == *cygwin* ]]; then
  EXE_SUFFIX=".exe"
else
  EXE_SUFFIX=""
fi

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "error: compiler '$CC' not found" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

COMMON_FLAGS=(
  -std=c99 -O2
  -I"$ROOT_DIR/third_party/mifare/include"
  -I"$ROOT_DIR/third_party/mifare/common"
  -I"$ROOT_DIR/third_party/mifare/common/crapto1"
  -I"$ROOT_DIR/third_party/mifare/tools/mfc"
)

COMMON_SRCS=(
  "$ROOT_DIR/third_party/mifare/tools/mfc/util_posix.c"
  "$ROOT_DIR/third_party/mifare/tools/mfc/sleep.c"
  "$ROOT_DIR/third_party/mifare/common/bucketsort.c"
  "$ROOT_DIR/third_party/mifare/common/crapto1/crapto1.c"
  "$ROOT_DIR/third_party/mifare/common/crapto1/crypto1.c"
)

LIBS=( -lpthread )

build_tool() {
  local target="$1"
  local src="$ROOT_DIR/third_party/mifare/tools/mfc/${target}.c"
  local output="$OUT_DIR/${target}${EXE_SUFFIX}"
  echo "Building $target -> $output"
  "$CC" "${COMMON_FLAGS[@]}" "$src" "${COMMON_SRCS[@]}" "${LIBS[@]}" -o "$output"
}

build_tool mfkey32v2
build_tool mfkey64

STATIC_FLAGS=(
  -std=c99 -O2
  -I"$ROOT_DIR/third_party/mifare/include"
  -I"$ROOT_DIR/third_party/mifare/common"
  -I"$ROOT_DIR/third_party/mifare/common/crapto1"
  -I"$ROOT_DIR/third_party/mifare/tools/mfc"
)

STATIC_SRCS=(
  "$ROOT_DIR/third_party/mifare/tools/mfc/staticnested.c"
  "$ROOT_DIR/third_party/mifare/tools/mfc/nested_util.c"
  "$ROOT_DIR/third_party/mifare/common/bucketsort.c"
  "$ROOT_DIR/third_party/mifare/common/crapto1/crapto1.c"
  "$ROOT_DIR/third_party/mifare/common/crapto1/crypto1.c"
)

STATIC_OUTPUT="$OUT_DIR/staticnested${EXE_SUFFIX}"
echo "Building staticnested -> $STATIC_OUTPUT"
"$CC" "${STATIC_FLAGS[@]}" "${STATIC_SRCS[@]}" -lpthread -o "$STATIC_OUTPUT"

echo "Build artifacts are in $OUT_DIR"
