#!/usr/bin/env bash
# Extract/decrypt the N3DS CIAs (SysModules 00040130*, FIRM 00040138*) with ctrtool.
# Output: decrypted_binaries/<TID>/{code.bin,exheader.bin,exefs.bin,exefs_dir/}; FIRM titles also get firm_sections/
set -u
cd "$(dirname "$0")"
OUT=decrypted_binaries; mkdir -p "$OUT"
for cia in updates/00040130*.cia updates/00040138*.cia; do
  tid=$(basename "$cia" .cia); d="$OUT/$tid"; mkdir -p "$d/raw"
  ( cd "$d" && ctrtool -q --contents=raw --exefs=exefs.bin --exheader=exheader.bin \
      --exefsdir=exefs_dir --decompresscode "../../$cia" >ctrtool.log 2>&1 )
  if [[ $tid == 00040138* ]]; then
    ctrtool -q -t firm --firmdir="$d/firm_sections" "$d/exefs_dir/firm.bin" >>"$d/ctrtool.log" 2>&1 || true
  fi
  [[ -f $d/exefs_dir/code.bin ]] && cp "$d/exefs_dir/code.bin" "$d/code.bin"
  echo "$tid $(ls $d | tr '\n' ' ')"
done

# English directory names (module name taken from each ExHeader)
python3 -I tools/rename_to_english.py "$OUT" --apply >/dev/null
