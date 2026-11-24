# New Nintendo 3DS (N3DS / CTR "Snake") – Recreated Symbol Table

Symbols for the decrypted **New 3DS** firmware binaries, recreated by transferring the already-recreated
**Old 3DS (O3DS)** symbols in `../o3ds/decrypted_binaries/` and verifying every transfer against the N3DS bytes.

> Rule followed throughout: **no address, offset or name is stated without byte-level evidence** from the N3DS
> binary and the O3DS reference table. Anything that could not be matched is kept as `unresolved`.

## Layout

```
n3ds/
├── updates/                      # source CIAs (encrypted, untouched)
├── decrypted_binaries/           # everything below was produced by tools/ (ctrtool + K9L2 decryption)
│   ├── Module-<NAME>-<Role>[-SafeMode][-N3DS]-<TitleID>/   # one sysmodule: code.bin, exheader.bin, exefs.bin, exefs_dir/
│   ├── Firm-<NAME>-<TitleID>/    # FIRM titles: exefs_dir/firm.bin + firm_sections/ (raw sections)
│   ├── kernel_native/            # NATIVE_FIRM (N3DS) split: arm9.bin, arm9_header_0x800.bin, arm9loader_tail.bin, arm11.bin, arm11_section1.bin
│   ├── kernel_safe/, kernel_twl/, kernel_agb/   # SAFE_MODE / TWL / AGB FIRM split + ARM9 decrypted
│   ├── firm_modules/{fs,loader,pm,sm,pxi}/   # the 5 NCCH modules embedded in NATIVE_FIRM section 0
│   └── RENAME_MAP.tsv            # old name -> new English name
├── decrypted_titles/             # every non-sysmodule title (apps, applets, system/shared data, TWL): code.bin, exheader.bin, exefs_dir/, full romfs/ tree, analysis/
├── symbols/                      # RESULTS
│   ├── N3DS_SYMBOL_TABLE.csv     # merged table (21 755 rows)
│   ├── titles/                   # TITLES_SYMBOL_TABLE.csv, TITLES_INVENTORY.csv, LIBRARY_MATCHES.csv (apps/applets, both models)
│   ├── N3DS_IPC_COMMANDS.csv     # IPC header-shaped constants found per handler / client call
│   ├── derived/<TID>.csv         # structural symbols per module
│   ├── r2_functions/             # radare2 function lists (cache)
│   ├── N3DS_MODULE_INVENTORY.csv # per-module identity vs O3DS, exheader deltas, services, SVC numbers
│   └── <component>.{csv,sym,r2}  # per-component results (+ radare2 flag scripts)
├── tools/                        # reproducible pipeline (see below)
└── docs/                         # methodology, findings, corrections
```

## Headline results

* **Decryption:** all 56 SysModule CIAs and the 4 FIRM CIAs decrypt with `ctrtool` + the keys in `../aes_keys.txt`. The ARM9 of every N3DS FIRM
  additionally carries the **arm9loader layer**: NATIVE_FIRM uses `K9L2` (KeyX = slot 0x16), SAFE_MODE / TWL / AGB FIRM use the older scheme (KeyX = slot 0x15).
  Both are handled by `tools/dec_arm9_n3ds.py`, so the ARM9 of all four FIRMs is now decrypted (`kernel_native/`, `kernel_safe/`, `kernel_twl/`, `kernel_agb/`).
* **All 24 shared (`0004013000xxxxxx`) sysmodules are byte-identical to O3DS** (`code.bin` sha256 equal) -> every O3DS symbol transfers 1:1 (`exact`, same addresses).
  Of the 5 FIRM-embedded modules `fs`, `loader`, `pxi`, `sm` are identical; `pm` differs (all 142 symbols placed).
* **Native-FIRM kernels and N3DS-specific module builds** (the real work): of the 7 360 O3DS symbols of ARM9, Kernel11, `pm`, `gsp`, `i2c`, `mcu`, `ptm`,
  **7 294 (99.1 %) are placed in N3DS; 66 stay `unresolved`** (ARM9 40, Kernel11 16, `gsp` 9, `mcu` 1). Placement uses byte matching, call-graph voting,
  link-order layout, pointer tables, literal constants and radare2 function boundaries; see `docs/METHODOLOGY.md`.
  Every placed row carries a `verification` status (call sites / strings / callers must agree with the mapping); across all components 6 487 non-exact matches are `verified` that way, 714 are leaf functions with no call/string evidence, 188 `partial`, 11 `conflict` (see `docs/STATS.md`).
* **SAFE_MODE_FIRM** (older build, system 15.45.1): ARM9 and Kernel11 symbols transferred as well (`kernel9_safe`, `kernel11_safe`), with more `unresolved` rows because the code is older.
* **N3DS-only code:** arm9loader (FIRM ARM9 entry `0x0808AA3C`), module `qtm` (head tracking) and the N3DS build of `mvd`, plus a `qtm:sp`/`qtm:s` dependency in `gsp`/`ns`.
* **Derived structural symbols (2 079 rows)** for every module, including the ones that have no O3DS reference (`qtm`, `mvd`, ...): 865 SVC wrapper functions named after the SVC they wrap,
  IPC command handlers / client calls / dispatchers detected from header-shaped literals, service-name strings classified as *client of* / *registered name*, and function-pointer tables.
  These are `derived_structural` (names describe evidence; they are not Nintendo's names).

## Applications, applets and data titles (everything in `extracted` / `updates`)

`tools/extract_titles.py` decrypts and unpacks **all** non-sysmodule CIAs of both models: 52 N3DS titles (`n3ds/decrypted_titles/`, 36 with code) and 67 O3DS titles
(`o3ds/decrypted_titles/`, 38 with code) - System Settings, Camera, Sound, eShop, Download Play, HOME Menu, Mii Maker, StreetPass Mii Plaza, Activity Log, Face Raiders, AR Games,
Internet Browser, Miiverse applets, amiibo Settings, keyboard / pickers / error applets, N3DS-only apps, system and shared data archives, TWL titles. Every NCCH content gets
`exheader.bin`, `exefs_dir/` (decompressed `code.bin`, icon, banner) and the **complete RomFS tree** (CFA manuals included).

* **41 of 52 N3DS titles are byte-identical to their O3DS counterpart** (same TitleID, equal `code.bin` / content hash); the 6 that differ are Health and Safety, Face Raiders, Internet Browser and the three safe-mode
  Error Display / Error Dialog / Keyboard applets (system data archives are identical too); 5 titles are N3DS-only (`mcopy`, `menu`, `friend`, `newslist`, `cherry`).
* `tools/title_analysis.py` recovers, per binary: **C++ class names from the binary's own RTTI** (e.g. `notes::pnote::GameApp`, `nw::lyt::Pane`, `imgdb::JpegDecoder` in Camera; `www::util`, `browser::wkc`,
  `sequence::main` in the Miiverse applet / amiibo Settings; `nw::snd`, `mw::igr` in the Internet Browser) with their vtables, virtual slots and vptr-initialising functions (constructors/destructors);
  functions that reference **source-file paths** (`Q:/snake-skater/product/src/...` - 2 388 path strings in the Browser, `d:/home/jenkins/workspace/CTR_SDK-11_2/...`, `c:/MyProjects/CTR/CIA/...`);
  functions identified by the **strings they use**; SVC wrappers, IPC candidates, service strings, pointer tables.
* `tools/library_propagation.py` then carries those names (and the O3DS semantic sysmodule names) to every other binary containing the same statically linked code (libc / CTR-SDK / NintendoWare / `nn::fs`...),
  by position-masked byte identity: 2 878 matches (`symbols/titles/LIBRARY_MATCHES.csv`).
* Totals: N3DS 23 816 title symbol rows, O3DS 25 891 (`symbols/titles/TITLES_SYMBOL_TABLE.csv`, `o3ds/symbols_titles/`). Per-title numbers: [`docs/TITLES.md`](docs/TITLES.md).

Confidence levels used everywhere (full per-component numbers in [`docs/STATS.md`](docs/STATS.md)):

| Level | Meaning |
|---|---|
| `exact` | identical function bytes (or whole binary), unique in the N3DS binary |
| `probable_by_transfer` | identical after masking position-dependent operands and unique, or several candidates resolved by neighbouring anchors' address shift |
| `probable_by_callgraph` | not found by bytes, but matched callers vote for it through call sites aligned at the same offsets |
| `probable_by_layout` | placed between two matched neighbours with the same link-order distance (or one function that changed size), masked similarity >= 0.4 |
| `probable_by_table` | slot of a pointer table / vtable / string-pointer array whose neighbouring slots matched |
| `probable_by_similarity` | best masked-byte similarity (>= 0.5, clear margin; >= 0.75 if it moved far) in unclaimed N3DS space |
| `probable_by_constants` | placed by the rare 32-bit constants of its literal pool |
| `probable_by_gap_function` | the only unclaimed radare2 function between two matched neighbours |
| `adapted_n3ds` | matched as above, but the O3DS name embedded the old address and was re-addressed (underlying level kept in column `match_basis`) |
| `derived_structural` | no O3DS equivalent: named from direct evidence in the N3DS bytes |
| `unresolved` | no unique/consistent placement |

Title rows additionally use `derived_rtti`, `derived_source_ref`, `derived_string_ref`, `derived_structural` and `library_match` (see `docs/TITLES.md`).

## Reproduce

```bash
cd n3ds
./extract_n3ds.sh            # CIA -> NCCH -> ExeFS -> code.bin (+ FIRM)           (needs ctrtool)
python3 -I tools/dec_arm9_n3ds.py <firm_arm9_section.bin> <arm9.bin>               # arm9loader layer
tools/run_all.sh             # transfers, refinement, derived symbols, merged table, inventory, stats
```

See `docs/` for details: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md), [`docs/N3DS_VS_O3DS_FINDINGS.md`](docs/N3DS_VS_O3DS_FINDINGS.md),
[`docs/O3DS_LABEL_CORRECTIONS.md`](docs/O3DS_LABEL_CORRECTIONS.md), [`docs/PENDING.md`](docs/PENDING.md), [`docs/STATS.md`](docs/STATS.md).
