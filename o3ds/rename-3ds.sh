#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${1:-.}"
SRC_DIR="$BASE_DIR/updates"
OUT_DIR="$BASE_DIR/extracted"

mkdir -p "$OUT_DIR"

sanitize_name() {
  local s="$1"
  s="$(printf '%s' "$s" | tr '/\\:*?"<>|' '_' | tr -s ' ' | sed 's/^ //; s/ $//')"
  printf '%s' "${s:0:140}"
}

category_from_tid() {
  local prefix8
  prefix8="$(printf '%s' "$1" | cut -c1-8 | tr '[:lower:]' '[:upper:]')"
  case "$prefix8" in
    00040010) echo "SysApp" ;;
    0004001B) echo "SysData_001B" ;;
    00040030) echo "Applet" ;;
    0004009B) echo "SharedData_009B" ;;
    000400DB) echo "SysData_00DB" ;;
    00040130) echo "SysModule" ;;
    00040138) echo "FIRM" ;;
    00048005) echo "TWL_App" ;;
    0004800F) echo "TWL_Data" ;;
    *)        echo "Title" ;;
  esac
}

verified_title_name() {
  local tid
  tid="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"

  case "$tid" in
    # 00040010 - System Applications (USA TIDLow verificados en 3dbrew)
    0004001000021000) echo "System Settings" ;;
    0004001000021100) echo "Download Play" ;;
    0004001000021200) echo "Activity Log" ;;
    0004001000021300) echo "Health and Safety Information" ;;
    0004001000021400) echo "Nintendo 3DS Camera" ;;
    0004001000021500) echo "Nintendo 3DS Sound" ;;
    0004001000021700) echo "Mii Maker" ;;
    0004001000021800) echo "StreetPass Mii Plaza" ;;
    0004001000021900) echo "eShop" ;;

    # 0004001B - System Data Archives (verificados en 3dbrew / GBATEK)
    0004001B00010002) echo "ClCertA" ;;
    0004001B00010702) echo "NS CFA" ;;
    0004001B00018102) echo "Miiverse Offline Browser Data" ;;
    0004001B00018202) echo "Miiverse and ACT WebKit CROs" ;;
    0004001B00019002) echo "Fangate_updater" ;;

    *) echo "" ;;
  esac
}

for cia in "$SRC_DIR"/*.cia; do
  [ -e "$cia" ] || continue
  base_noext="$(basename "$cia" .cia)"
  tid="$(printf '%s' "$base_noext" | grep -oE '[0-9a-fA-F]{16}' | head -n 1 | tr '[:lower:]' '[:upper:]' || true)"

  if [ -n "$tid" ]; then
    vname="$(verified_title_name "$tid")"
    cat_label="$(category_from_tid "$tid")"
    if [ -n "$vname" ]; then
      final_stem="$(sanitize_name "$vname") [${tid}]"
    else
      final_stem="${cat_label}_${tid}"
    fi
  else
    final_stem="$(sanitize_name "$base_noext")"
  fi

  new_cia="$SRC_DIR/${final_stem}.cia"
  if [ "$cia" != "$new_cia" ] && [ ! -e "$new_cia" ]; then
    mv "$cia" "$new_cia"
  fi

  existing_dir=""
  if [ -d "$OUT_DIR/$base_noext" ]; then
    existing_dir="$OUT_DIR/$base_noext"
  elif [ -n "$tid" ]; then
    existing_dir="$(find "$OUT_DIR" -maxdepth 1 -mindepth 1 -type d -iname "*${tid}*" | head -n 1 || true)"
  fi

  if [ -n "$existing_dir" ]; then
    final_dir="$OUT_DIR/${final_stem}"
    if [ "$existing_dir" != "$final_dir" ]; then
      if [ -e "$final_dir" ]; then
        final_dir="${final_dir}_$$"
      fi
      mv "$existing_dir" "$final_dir"
    fi
  fi

  echo "[+] ${base_noext} -> ${final_stem}"
done
