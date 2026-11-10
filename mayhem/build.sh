#!/usr/bin/env bash
#
# mayhem/build.sh — build the slurm fuzz harnesses (sanitized, libslurm.o linked in) plus the
# unit-test suite (normal flags) that mayhem/test.sh runs.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
FUZZ="$SRC/mayhem/build-fuzz"
TEST="$SRC/mayhem/build-test"
PLUGINDIR="$FUZZ/plugins"
HARNESSES="fuzz_hostlist fuzz_bitstring fuzz_unpack_msg fuzz_unpack_dbd fuzz_serializer fuzz_url"

# 1) Sanitized build. --without-shared-libslurm makes src/api/libslurm.o (one relocatable object with
#    libcommon + interfaces + conmgr + the API) that each harness links directly. SanCov goes on the
#    library compile: without fuzzer-no-link the fuzzed code reports zero edges.
mkdir -p "$FUZZ"
cd "$FUZZ"
if [ ! -f config.status ]; then
  "$SRC/configure" CC="$CC" --without-shared-libslurm --enable-debug --disable-dependency-tracking \
    CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
fi
# bitstring.c keeps its words in a signed int64 and builds masks as `((bitstr_t)1 << n) - 1` with n up to
# 63, so any bitstring of 64+ bits trips shift-base and signed-integer-overflow on two's-complement
# wraparound that the file relies on. Those two checks are relaxed for that one file; the rest of UBSan
# and ASan stay on and halting there.
BASE_CFLAGS="$(make -s -C src/common --eval='print-cflags: ; @echo $(CFLAGS)' print-cflags)"
make -C src/common bitstring.lo CFLAGS="$BASE_CFLAGS -fno-sanitize=shift-base,signed-integer-overflow"
make -j"$MAYHEM_JOBS" -C src/api libslurm.o
make -j"$MAYHEM_JOBS" -C src/plugins/serializer
make -j"$MAYHEM_JOBS" -C src/plugins/url_parser
# fuzz_unpack_msg runs the interfaces a daemon initialises before unpack_msg(): cred, hash, topology.
make -j"$MAYHEM_JOBS" -C src/plugins/cred/common
make -j"$MAYHEM_JOBS" -C src/plugins/cred/none
make -j"$MAYHEM_JOBS" -C src/plugins/hash/common_xkcp
make -j"$MAYHEM_JOBS" -C src/plugins/hash/k12
make -j"$MAYHEM_JOBS" -C src/plugins/topology/flat

# Plugins are dlopen'ed by name from slurm_conf.plugindir; stage them in one directory.
mkdir -p "$PLUGINDIR"
for p in src/plugins/serializer/json/.libs/serializer_json.so \
         src/plugins/serializer/yaml/.libs/serializer_yaml.so \
         src/plugins/serializer/url-encoded/.libs/serializer_url_encoded.so \
         src/plugins/url_parser/internal/.libs/url_parser_internal.so \
         src/plugins/cred/none/.libs/cred_none.so \
         src/plugins/hash/k12/.libs/hash_k12.so \
         src/plugins/topology/flat/.libs/topology_flat.so; do
  cp -f "$p" "$PLUGINDIR/"
done

# 2) Harnesses: fuzzer + standalone reproducer, each with the LSan-off hook.
$CXX $SANITIZER_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/keep_plugins.c" -o "$FUZZ/keep_plugins.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/alloc_cap.c" -o "$FUZZ/alloc_cap.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ/standalone_main.o"
LIBS="$FUZZ/src/api/libslurm.o $FUZZ/alloc_cap.o -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc -Wl,--export-dynamic -ldl -lpthread -lm -lresolv"
for h in $HARNESSES; do
  src="$SRC/mayhem/$h/$h.c"
  $CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -DMAYHEM_PLUGINDIR="\"$PLUGINDIR\"" \
      -I"$SRC" -I"$FUZZ" -c "$src" -o "$FUZZ/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FUZZ/$h.o" "$FUZZ/lsan_off.o" "$FUZZ/keep_plugins.o" $LIBS \
      -o "/mayhem/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$FUZZ/$h.o" "$FUZZ/standalone_main.o" "$FUZZ/lsan_off.o" "$FUZZ/keep_plugins.o" $LIBS \
      -o "/mayhem/$h-standalone"
done

# 3) Unit-test suite with the project's normal flags, built out of tree in its own dir.
mkdir -p "$TEST"
cd "$TEST"
if [ ! -f config.status ]; then
  (env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" --without-shared-libslurm --enable-debug \
     --disable-dependency-tracking CFLAGS="-O1 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
fi
make -j"$MAYHEM_JOBS" -C src/api libslurm.o
UT=testsuite/slurm_unit/common
make -j"$MAYHEM_JOBS" -C $UT/hostlist hostlist_create-test hostlist_nth-test hostlist_iterator-test
make -j"$MAYHEM_JOBS" -C $UT/bitstring bitstring-test bit_unfmt_hexmask-test
make -j"$MAYHEM_JOBS" -C $UT xstring-test parse_time-test data-test pack-test buf-test xbase64-test \
     xhash-test reverse_tree-test
