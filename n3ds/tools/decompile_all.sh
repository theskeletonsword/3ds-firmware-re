#!/usr/bin/env bash
# Resumable bulk decompilation of every binary (headless Ghidra). Usage: tools/decompile_all.sh [parallel_jobs] [--fresh]
# Progress: n3ds/docs/HANDOFF.md ("Decompilation status"), per-binary index: <bin_dir>/decompiled/index.tsv, logs: <bin_dir>/decompiled/ghidra.log
cd "$(dirname "$0")/.."
P=5; FRESH=""
for arg in "$@"; do
  if [ "$arg" = "--fresh" ]; then FRESH="--fresh"; else P="$arg"; fi
done
python3 tools/decompile_jobs.py $FRESH > /tmp/decomp_jobs.txt
# smallest first so that most binaries finish early
xargs -P "$P" -I{} bash -c '{}' < /tmp/decomp_jobs.txt 2>&1 | tee -a /tmp/decompile_all.log
