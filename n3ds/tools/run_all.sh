#!/usr/bin/env bash
# Re-generate every N3DS symbol file from the O3DS reference. Run from n3ds/.
set -euo pipefail
cd "$(dirname "$0")/.."
D=decrypted_binaries; O=../o3ds/decrypted_binaries
mkdir -p symbols; find symbols -maxdepth 1 -type f -delete; rm -rf symbols/derived
tr_() { # tag old old_base new new_base sym [extra args]
  tag=$1; old=$2; ob=$3; new=$4; nb=$5; sym=$6; shift 6
  python3 -I tools/transfer_syms.py --old "$old" --old-base $ob --new "$new" --new-base $nb --sym "$sym" --out symbols/$tag --tag $tag "$@"
  python3 tools/refine_matches.py --old "$old" --old-base $ob --new "$new" --new-base $nb --sym "$sym" --csv symbols/$tag.csv --tag $tag "$@"
}
tr_ kernel9_process9 $O/Firm-NATIVE_FIRM-0004013800000002/arm9.bin 0x08006800 $D/kernel_native/arm9.bin 0x08006800 $O/Firm-NATIVE_FIRM-0004013800000002/arm9_friendly.sym
tr_ kernel11 $O/Firm-NATIVE_FIRM-0004013800000002/arm11_section1.bin 0x1FF80000 $D/kernel_native/arm11_section1.bin 0x1FF80000 $O/Firm-NATIVE_FIRM-0004013800000002/arm11_kernel11_friendly.sym --alias 0xFFF00000
tr_ kernel9_safe $O/Firm-NATIVE_FIRM-0004013800000002/arm9.bin 0x08006800 $D/kernel_safe/arm9.bin 0x08006800 $O/Firm-NATIVE_FIRM-0004013800000002/arm9_friendly.sym
tr_ kernel11_safe $O/Firm-NATIVE_FIRM-0004013800000002/arm11_section1.bin 0x1FF80000 $D/kernel_safe/arm11_section1.bin 0x1FF80000 $O/Firm-NATIVE_FIRM-0004013800000002/arm11_kernel11_friendly.sym --alias 0xFFF00000
for m in fs loader pm pxi sm; do
  tr_ firm_$m $O/firm_modules/$m/code.bin 0 $D/firm_modules/$m/code.bin 0 $O/firm_modules/$m/${m}_friendly.sym
done
mod(){ # name O3DS_TID N3DS_TID
  od=$(ls -d $O/Module-*$2 | head -1); nd=$(ls -d $D/Module-*$3 | head -1)
  tr_ ${1}_$3 $od/code.bin 0 $nd/code.bin 0 $od/${1}_friendly.sym
}
mod cecd 0004013000002602 0004013000002602
mod hid  0004013000001D02 0004013000001D02
mod nwm  0004013000002D02 0004013000002D02
mod gsp  0004013000001C02 0004013020001C02
mod i2c  0004013000001E02 0004013020001E02
mod mcu  0004013000001F02 0004013020001F02
mod ptm  0004013000002202 0004013020002202
python3 tools/r2_functions.py >/dev/null
python3 tools/derive_ipc.py >/dev/null
python3 tools/name_from_decomp.py >/dev/null 2>&1 || true
python3 tools/extract_ipc_from_decomp.py >/dev/null 2>&1 || true
python3 -I tools/build_master_table.py
python3 -I tools/module_inventory.py
python3 -I tools/make_stats.py >/dev/null
# --- titles: applications / applets / data (everything that is not a sysmodule), both models
python3 tools/extract_titles.py ../o3ds/updates ../o3ds/decrypted_titles --name-map ../o3ds/title_names.tsv >/dev/null
python3 tools/extract_titles.py updates decrypted_titles --name-map ../o3ds/title_names.tsv >/dev/null
for r in decrypted_titles ../o3ds/decrypted_titles decrypted_binaries ../o3ds/decrypted_binaries decrypted_binaries/firm_modules ../o3ds/decrypted_binaries/firm_modules; do python3 tools/title_analysis.py "$r" --jobs 8 >/dev/null; done
python3 tools/library_propagation.py >/dev/null
python3 tools/titles_inventory.py n3ds symbols/titles; python3 tools/titles_inventory.py o3ds ../o3ds/symbols_titles
python3 tools/make_titles_doc.py
