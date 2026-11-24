# Pending / not confirmed (updated after the second resolution round)

## Resolved since the first round
| Item | Resolution |
|---|---|
| SAFE_MODE_FIRM ARM9 encrypted | decrypted: older arm9loader scheme (KeyX = `slot0x15KeyX`, KeyY and CTR from the header as stored). TWL_FIRM and AGB_FIRM ARM9 use the same scheme and are decrypted too (`kernel_safe/`, `kernel_twl/`, `kernel_agb/`). Symbols were transferred for the SAFE_MODE kernels; TWL/AGB are different programs and have no O3DS reference. |
| 640 `unresolved` rows | reduced to **66** for the NATIVE_FIRM components (ARM9 40, Kernel11 16, `gsp` 9, `mcu` 1) by call-graph voting, link-order layout, pointer tables, constants, similarity and radare2 gap functions (see METHODOLOGY §2.6). |
| `probable_by_transfer` rows not verified one by one | every placed row now has a `verification` column (call sites / strings / callers must agree). 11 `exact` rows whose call sites contradict the mapping were downgraded to `probable_by_transfer`, and contradicted probable rows were demoted to `unresolved`. |
| Modules without semantic names (IPC / vtables / jump tables) | structural names were derived for all 61 modules (2 079 `derived_structural` rows): 865 SVC wrappers, IPC handler / client-call / dispatcher candidates (`N3DS_IPC_COMMANDS.csv`), service-name strings, function-pointer tables. |
| `qtm`, `mvd` without functions | services, ports (`qtm:c/sp/s/u`), SVC wrappers and IPC reply writers named (`symbols/derived/…4202.csv`, `…4102.csv`). |
| Spanish notes in the O3DS `.sym` files | all Notes translated: regular templates by regex + 885 hand-translated message skeletons (`o3ds/translate_sym_notes.py`, `o3ds/sym_notes_translation.tsv`); Spanish originals kept in `o3ds/docs_es_backup/sym_notes_es/`. No accented character is left in any `.sym`. |
| `o3ds/extracted/` and `o3ds/updates/` Spanish names | renamed to English (`o3ds/extracted/RENAME_MAP.tsv`); module titles use the real module names. |

## Added in the third round (titles)
All non-sysmodule titles of both models are now decrypted/unpacked and analysed (see README and `TITLES.md`).

## Still open (titles)
| Item | State | Why |
|---|---|---|
| Titles without RTTI (HOME Menu, System Settings, Mii Maker, Plaza, Activity Log, eShop, Download Play, keyboard/pickers, ...) | only library/string/SVC/IPC names | their C++ type information is stripped; function naming comes from strings, source-path references and masked-byte identity with named code elsewhere. Full naming needs decompilation + manual work. |
| RomFS contents | extracted, not parsed | layouts (BCLYT/BCLIM/BCFNT/BCSTM/BCWAV, message tables, `*_LZ.bin`) are listed in the inventory but their formats were not decoded. |
| TWL titles (`00048005…`, `0004800F…`) | kept as decrypted `raw.bin` | the NDS/SRL images were not split into ARM9/ARM7 binaries or analysed. |
| Names of N3DS-only apps `mcopy`, `menu`, `friend`, `newslist`, `cherry` | by ExHeader name only | no reference exists (4 of them are 8 KiB launchers). |
| Library matches | only functions >= 32 bytes with a unique name in the source set | domain-bucket names inherited from the O3DS sysmodule tables were excluded; some `lib_*` names are still descriptive buckets, not individual function names. |

## Still open
| Item | State | Why |
|---|---|---|
| 66 NATIVE_FIRM `unresolved` + 378 SAFE_MODE `unresolved` | open | no unique, mutually consistent placement. The real functions among them (e.g. `gsp_gx_command_queue_proc`, `gsp_irq_handler_0_to_F`, `arm11_core_bringup_init`, `arm9_mpu_and_aes_cfg_init`) look rewritten for N3DS; the tiny stubs are byte-identical to many others. Need manual reversing in Ghidra/IDA. |
| 188 `partial`, 11 `conflict` verification rows | review | the mapping is placed but some call sites disagree (function changed in N3DS or a callee mapped differently). Listed with `verification=` in the master table. |
| 714 matched non-exact rows with `no_evidence` verification | not independently checked | leaf functions without calls or strings; placed by byte/structure similarity only. |
| Derived IPC detection coverage | partial | only handlers/headers built from literal-pool constants are seen; `switch`-based dispatch without header literals, headers built with `mov/orr`, and Thumb-only handlers are not. Full command tables for the modules without O3DS names would need decompilation (Ghidra/IDA) of each dispatcher. |
| N3DS-only functions beyond SVC wrappers / IPC writers (`qtm`, `mvd`, `nfc` N3DS build, …) | not named | no reference exists; only structural facts were derived. |
| TWL_FIRM / AGB_FIRM ARM11 sections | split only | not analysed. |
| Process9 Thumb code in REA/Ghidra | limited | raw-binary language `ARM:LE:32:v7` has no Thumb entry hints; REA was used for byte/string checks, procedure inventories and `procedure_info` cross-checks, not for decompilation of Thumb-only functions. Hopper is installed (`/opt/hopper`) but was not used (no scriptable headless workflow set up here); IDA is not installed. |
| `extracted/` contents | not re-translated | only directory/file names were renamed; the data inside (extracted NCCH trees) is unchanged. |
