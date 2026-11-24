# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this workspace is

Reverse-engineering of Nintendo 3DS system firmware (ARM11 / ARM9) for **Old 3DS (`o3ds/`)** and **New 3DS (`n3ds/`)**. It is **not a git repository** and has no build/test suite: the "code" is a set of Python/bash tools in `n3ds/tools/` that decrypt, unpack, analyse and cross-reference binaries, and the "output" is symbol tables (CSV/`.sym`/`.r2`) plus Markdown docs. Chat with the user is in **Spanish**; **all files, docs, directory names and tool output are in English** (the user explicitly asked for this - keep it that way).

Evidence rule (user's standing instruction): never invent addresses, offsets or Nintendo-internal function names. Every symbol must carry a confidence level and the evidence for it (bytes, strings, call sites, headers). Structural names (`vslot`, `svc_wrapper`, `ipc_handler_cmd_*`) are *derived* names, not Nintendo's.

Read first: `n3ds/README.md` (results + confidence levels), `n3ds/docs/METHODOLOGY.md` (how every number was obtained), `n3ds/docs/PENDING.md` (what is open), `n3ds/docs/HANDOFF.md` (state of the "decompile everything" effort). `n3ds/docs/STATS.md` and `n3ds/docs/TITLES.md` are auto-generated - do not hand-edit.

## Layout (big picture)

```
aes_keys.txt, movable.sed      console key material used by ctrtool / tools (private)
o3ds/                          REFERENCE side (O3DS)
  updates/ extracted/          source CIAs (Spanish->English renamed) / old raw extraction (encrypted)
  decrypted_binaries/          sysmodules Module-<EXHEADER-NAME>-<Role>[-SafeMode]-<TID>/, firm_modules/{fs,loader,pm,pxi,sm}, Firm-NATIVE_FIRM-0004013800000002/ (kernel; symlink `kernel`)
                               + the hand-built semantic symbol tables *_friendly.sym/.r2/_ghidra.py and pseudocode_{arm9,k11}/ (the only semantic names we have)
  decrypted_titles/            apps, applets, data titles (code.bin, exheader.bin, exefs_dir/, romfs/, analysis/)
  symbols_titles/              TITLES_SYMBOL_TABLE.csv / TITLES_INVENTORY.csv
  *.md                         translated English docs (README, KERNEL_ANALYSIS, PXI_PROTOCOL, ...); Spanish originals in docs_es_backup/
  translate_sym_notes.py + sym_notes_translation.tsv   Spanish->English of the .sym Notes column (originals in docs_es_backup/sym_notes_es/)
n3ds/                          TARGET side (N3DS) + all tooling
  updates/                     source CIAs
  decrypted_binaries/          Module-*-N3DS-*, Firm-* (FIRM + firm_sections/), kernel_{native,safe,twl,agb}/ (arm9.bin decrypted, arm11*.bin), firm_modules/
  decrypted_titles/            same layout as o3ds/decrypted_titles
  symbols/                     RESULTS: N3DS_SYMBOL_TABLE.csv (master), per-component *.csv/.sym/.r2, derived/, r2_functions/ (cache), titles/
  tools/                       the pipeline (below)
  docs/                        METHODOLOGY, FINDINGS, PENDING, HANDOFF, STATS(auto), TITLES(auto), O3DS_LABEL_CORRECTIONS
```

Data flow: CIA -> `ctrtool` (title key from ticket) -> NCCH -> ExHeader/ExeFS(`code.bin`, LZSS-decompressed)/RomFS -> per-binary analysis -> O3DS-semantic-name transfer to N3DS -> master CSV. Same-TitleID binaries are mostly **byte-identical** between models (all 24 shared `0004013000xxxxxx` sysmodules, 41/52 titles), so symbols there transfer 1:1; N3DS-specific builds (`00040130 20xxxxxx` sysmodules, kernel, a few apps) need real matching.

## Commands

All from `n3ds/`. `tools/run_all.sh` regenerates **everything** (symbols, derived, master table, inventory, stats, titles; ~2-3 min). Pieces:

```bash
./extract_n3ds.sh                                   # sysmodule/FIRM CIAs -> decrypted_binaries (ctrtool), then rename_to_english.py
python3 tools/extract_titles.py <updates> <out> --name-map ../o3ds/title_names.tsv   # all non-sysmodule titles
python3 -I tools/dec_arm9_n3ds.py <firm arm9 section> <arm9.bin>   # arm9loader layer (K9L2 / old scheme), writes header + tail too
python3 -I tools/transfer_syms.py --old O.bin --old-base 0x.. --new N.bin --new-base 0x.. --sym O.sym --out symbols/X [--alias 0xFFF00000]
python3 tools/refine_matches.py  ...same args... --csv symbols/X.csv   # call-graph/layout/table/similarity passes + verification (needs numpy -> NOT `-I`)
python3 tools/r2_functions.py; python3 tools/derive_ipc.py          # r2 function cache + derived structural symbols for modules
python3 tools/title_analysis.py <root> --jobs 8                      # RTTI, source refs, string refs, structural, per-title analysis/
python3 tools/library_propagation.py                                 # cross-binary name propagation (masked-byte identity)
python3 -I tools/build_master_table.py; python3 -I tools/module_inventory.py; python3 -I tools/make_stats.py
python3 tools/titles_inventory.py {n3ds symbols/titles | o3ds ../o3ds/symbols_titles}; python3 tools/make_titles_doc.py
../o3ds/translate_sym_notes.py                                      # re-apply notes translation from the Spanish backups
```

Decompilation (headless Ghidra 12.2; hours for everything, resumable): `nohup tools/decompile_all.sh 5 &` (job list from `tools/decompile_jobs.py`, per-binary `tools/ghidra_decompile.py <dir> [--fresh] [--bin ... --lang ... --base ... --out ...]`, output `<binary>/decompiled/<addr>.c`), progress `python3 tools/decompile_status.py` -> `docs/DECOMPILATION_STATUS.md`, IPC tables from the C `python3 tools/extract_ipc_from_decomp.py`, names proven by the C `python3 tools/name_from_decomp.py`, proposals for unresolved symbols by decompiled-C similarity `python3 tools/match_by_decompilation.py <stem> <o3ds decompiled dir> <n3ds decompiled dir> [--alias ...]` (output `symbols/proposals/`; always read both C files before accepting). Hand-verified names go to `symbols/manual/<binary>.csv` (merged by `build_master_table.py`), prose to `docs/decompiled_notes/`.

Inspect results: `r2 -q -a arm -b 32 -m <base> -i symbols/<x>.r2 <bin> -c 'pd 20 @ sym.name'`; `ctrtool -t exheader <exheader.bin>`; `ctrtool -t firm --firmdir=<dir> firm.bin`. There are no tests: validate by re-running a stage and checking row counts / the `verification` column.

## Facts and pitfalls that are not obvious from the files

* **Directory labels lie, ExHeader names are truth.** The original Spanish labels mismatched most modules (`FS 1502` is really `am`, `PM 1602` is `camera`, ...). Directories were renamed from the ExHeader `Name`; mapping in each `decrypted_binaries/RENAME_MAP.tsv`; explanation in `n3ds/docs/O3DS_LABEL_CORRECTIONS.md`. TitleID tail `...02` = normal build, `...03` = safe-mode build; `00040130 20xxxxxx` = N3DS-specific build, matched to O3DS `00040130 00xxxxxx`.
* **Load addresses.** Sysmodule/app `code.bin`: `0x00100000` (text, then ro, data contiguous). FIRM module `loader`: `0x14000000`. ARM9 (`arm9.bin`, both models): `0x08006800`. Kernel11 `arm11_section1.bin`: file offset 0 = `0xFFF00000` for the kernel body but the boot code at file offsets >= 0x2D000 lives at `0x1FF80000 + offset` (tools use `--alias 0xFFF00000`; N3DS boot code is shifted +0x1030).
* **N3DS ARM9 is wrapped by arm9loader.** FIRM section 2 = `[0x800 header][AES-CTR ARM9 binary][plain arm9loader tail]`, entry `0x0808AA3C`. NATIVE_FIRM header magic `K9L2`: normal key = scramble(`slot0x16KeyX`, header KeyY), CTR = header@0x20 as stored. SAFE_MODE/TWL/AGB: KeyX = `slot0x15KeyX`. Scrambler: `rol((rol(X,2) ^ Y) + C, 87)`, C = `generatorConstant`.
* **ctrtool 1.3 quirks:** use `--intype=ncch` (not `-t ncch`) with options *before* the input file; `-t exheader|firm` works as `ctrtool -t exheader file`. `--decompresscode` is required for usable `code.bin`. System `objdump` has **no ARM backend** - use radare2.
* **Tool conventions:** `python3 -I` ignores user site-packages, so anything importing numpy (`refine_matches.py`, `title_analysis.py`, `library_propagation.py`) must run without `-I`. Matching engine = position-masked bytes (bl/b, pc-relative loads, address-like literal words) in ARM and Thumb; confidence levels are listed in `n3ds/README.md` and implemented in `refine_matches.py` / `build_master_table.py` (outlier rejection and `adapted_n3ds` re-addressing happen in the master builder, not in the per-component CSVs). `run_all.sh` deletes and rebuilds `symbols/*` files (not subdirs `titles/`, `r2_functions/` caches).
* **REA** (MCP `mcp__rea__*`, Ghidra 12.2 provider): open raw binaries with `format: raw-binary, architecture: arm, entry_point: <load address>`; it maps file offset 0 at that address; language is `ARM:LE:32:v7` with no Thumb entry hints, so Thumb-only functions do not decompile via `procedure_pseudo_code` (use it for `procedure_info`, strings, `search_bytes`, inventories). Close with `close_binary` before moving files. Outputs are very verbose; prefer headless Ghidra / radare2 for bulk work.
* **Environment limits seen:** Claude Code blocks `rm -rf`-style commands whose target contains an unquoted shell variable; use `"${var:?}"` or avoid removals (scripts overwrite outputs anyway). Hopper is in `/opt/hopper` (unused), IDA is not installed, Ghidra headless is `/opt/ghidra_12.2_PUBLIC/support/analyzeHeadless`.
* **Another process/the user edits this tree concurrently** (renamed `kernel` dirs, moved key files to the root, changed script names). Re-`ls` before relying on a path; the O3DS kernel dir is `Firm-NATIVE_FIRM-0004013800000002` with compatibility symlink `kernel`.
* O3DS semantic names exist only for: Kernel9/Process9, Kernel11, FIRM modules `fs loader pm pxi sm`, sysmodules `cecd hid nwm gsp i2c mcu ptm`. Everything else is `derived_structural` / `derived_rtti` / `library_match`. 640 -> 66 N3DS symbols are still `unresolved` (list in `docs/PENDING.md`).

## Current objective

The user asked to **decompile everything manually** (not just name things) and to document so work can resume if the weekly quota runs out. State, work queue, and the resumable bulk-decompile tooling are in `n3ds/docs/HANDOFF.md` - continue from there, and keep that file updated after each batch (what was done, what is next).
