# Handoff: state of the work and how to continue (written so a fresh session can resume if the quota runs out)

Last updated at the end of the session in which the bulk decompilation was started. Always re-check `docs/DECOMPILATION_STATUS.md` (run `python3 tools/decompile_status.py`).

## 1. What exists (all verified, reproducible with `tools/run_all.sh`)

| Area | Where | State |
|---|---|---|
| Decryption of every CIA (sysmodules, FIRM, apps, applets, data, TWL raw) both models | `*/decrypted_binaries`, `*/decrypted_titles` | done; N3DS ARM9 arm9loader layer solved for NATIVE/SAFE/TWL/AGB FIRM |
| O3DS -> N3DS symbol transfer for kernel + FIRM modules + 7 sysmodules | `n3ds/symbols/*.csv`, master `N3DS_SYMBOL_TABLE.csv` | 99.1 % of the 7 360 O3DS symbols of native kernel/pm/gsp/i2c/mcu/ptm placed; 66 `unresolved` (list in PENDING.md) |
| Derived structural symbols (SVC wrappers, IPC handler/client/dispatcher candidates, service strings, pointer tables) all modules | `symbols/derived/`, `N3DS_IPC_COMMANDS.csv` | done (partial IPC coverage: literal-pool headers only) |
| Titles: RTTI class names, source-path refs, string refs, library matches | `*/decrypted_titles/*/analysis/`, `symbols/titles/` | done; RTTI only exists in Camera, Sound, Photo Picker, Miiverse applet, amiibo Settings, Browser |
| Docs (English) | `o3ds/*.md`, `n3ds/README.md`, `n3ds/docs/*` | done; `STATS.md`, `TITLES.md`, `DECOMPILATION_STATUS.md` auto-generated |

## 2. Decompile-everything effort (current objective)

The user asked to **decompile everything** and to continue manually. Two layers:

### 2.1 Bulk layer (automatic, resumable) - tooling in place
* `n3ds/tools/decompile_jobs.py` builds the job list (154 jobs at creation): all N3DS modules/FIRM modules/titles/kernel images + every O3DS binary that is not byte-identical to an N3DS one (O3DS-only titles, safe-mode builds, O3DS kernel).
* `n3ds/tools/decompile_all.sh [parallel]` runs them with `tools/ghidra_decompile.py` (headless Ghidra 12.2, `analyzeHeadless`, script `tools/ghidra/DecompileAll.java`).
  Output per binary: `<dir>/decompiled/<addr>.c` (+ `index.tsv`, `names.tsv`, `ghidra.log`); kernels: `<kernel dir>/decompiled_<image>/`. **Re-running skips functions already written**; use `--fresh` on one binary to redo it (needed after adding names).
  Our symbol names are applied before decompiling (names.tsv from the master tables), so C output already shows e.g. `spi_ipc_handler_cmd_0001_...`.
* Languages: ARM11/modules/titles `ARM:LE:32:v6`, ARM9 `ARM:LE:32:v5t`; base = ExHeader text address (`0x100000`; `loader` `0x14000000`; ARM9 `0x08006800`; Kernel11 image loaded at `0xFFF00000` - its boot code at file offsets >= 0x2D000 therefore shows up at `0xFFF2D000+`, not at `0x1FFAxxxx`; names.tsv already uses the shifted addresses).
* Started in the background with `nohup tools/decompile_all.sh 5` (5 parallel JVMs, 3 GB each). If the machine rebooted or the run was interrupted, simply start it again; finished binaries have `index.tsv` and are re-checked quickly (all functions "existing").
* Known limits of the bulk pass: Ghidra decides ARM vs Thumb per function heuristically (some Thumb functions fail or look odd); a few functions time out (40 s each, listed as `fail` in `index.tsv`); data tables are not typed; `coproc_movefrom_User_R_Thread_and_Process_ID()` = read of the TLS pointer (IPC command buffer is TLS+0x80).

### 2.2 Manual layer (what "manual" means here) - procedure
1. Pick a binary from the queue below; open `decompiled/<addr>.c` of its dispatcher / entry / unresolved functions (find names in `symbols/N3DS_SYMBOL_TABLE.csv`; unresolved ones are in the `unresolved` rows).
2. Read the C together with the surrounding evidence (strings via `analysis/strings_interesting.txt`, SVC wrappers, service names, callers). Decide a name **only from evidence**; otherwise leave `FUN_` and write a note.
3. Record names in `symbols/manual/<binary dir>.csv` (format in `symbols/manual/README.md`) and prose findings in `docs/decompiled_notes/<binary>.md` (create the folder; one short file per binary: purpose, services provided/used, IPC command table, data structures, open questions).
4. Re-run `python3 tools/build_master_table.py` (merges manual rows as `manual_decompiled`), optionally `tools/ghidra_decompile.py <dir> --fresh` to regenerate C with the new names, and `python3 tools/decompile_status.py`.
5. Update the "Work log" below (one line per finished binary/batch).

Helper already written: `tools/extract_ipc_from_decomp.py` -> `symbols/ipc/IPC_COMMANDS_FROM_DECOMPILATION.csv` (every `switch(cmdbuf[0] >> 16)` dispatcher found in the decompiled C with the function called per case). Run it after the bulk pass finishes and improve it (reply header, argument counts, which service each dispatcher serves) - this gives complete IPC command tables for all modules without O3DS names.

### 2.3 Priority queue for manual work (highest value first)
1. **The 66 NATIVE_FIRM `unresolved` symbols** (ARM9 40, Kernel11 16, `gsp` 9, `mcu` 1) - the genuinely N3DS-changed code: `arm11_core_bringup_init`, `arm11_mmu_and_scu_enable`, `k11_kernel_sync_barrier_on_boot`, `k11_boot_enable_cpacr_vfp`, `arm9_mpu_and_aes_cfg_init`, `gsp_gx_command_queue_proc`, `gsp_irq_handler_0_to_F`, `gsp_gpu_cache_inv_and_ctrl`, ... (compare against the O3DS C in `o3ds/decrypted_binaries/Firm-NATIVE_FIRM-0004013800000002/pseudocode_{arm9,k11}/` and the N3DS C in `decrypted_binaries/kernel_native/decompiled_*/`).
2. **N3DS-only code:** `qtm` (`Module-QTM-...-0004013020004202`: ports `qtm:c/sp/s/u`, face tracking; model data string `face_SIRL_SVD.lbp`), `mvd`, titles `mcopy` (`0004001020024100`, large), `menu/friend/newslist/cherry` (8 KiB launchers), N3DS `camera` build, N3DS `nfc` build.
3. **IPC tables of every module** via `extract_ipc_from_decomp.py`, cross-checked against the service names in `analysis/derived.csv` and the ExHeader; document per module in `docs/decompiled_notes/`.
4. **Kernel diffs:** N3DS vs O3DS Kernel11 SVC table and new SVCs (compare `kernel_native/decompiled_arm11_section1` with the O3DS `pseudocode_k11`), N3DS Process9 changes (`p9_*` with `probable_by_*` levels and `partial` verification), SAFE_MODE kernels.
5. **Apps without RTTI** (HOME Menu, Settings, Mii Maker, Plaza, Activity Log, eShop, Download Play): identify subsystems from `strings_interesting.txt`, `string_refs.csv`, and `romfs/` file names, then name entry points, layout/message loaders, SD/NAND file accessors.
6. **Apps with RTTI** (Camera, Sound, Photo Picker, Miiverse, amiibo Settings, Browser): class hierarchy documents from `analysis/rtti.csv` (base classes are in the evidence column), then name methods through vtable slot usage.
7. TWL titles (`raw.bin` NDS images: split ARM9/ARM7 from the NDS header, analyse in `ARM:LE:32:v5t`/`v4t`), RomFS formats (BCLYT/BCSTM/BCFNT/BCWAV/message tables).

### 2.4 Progress of the manual layer (keep this table current)
| Item | State |
|---|---|
| Bulk decompilation (`--fresh` pass, 154 jobs / 157 entries in status, 317 628 discovered, 316 625 decompiled) | **finished** (re-run `tools/decompile_status.py` for numbers; includes `manual_decompiled`, `derived_decompiled`, `firm_modules`, `library_matches`, O3DS `.sym`, and 8 KiB launchers `App-cherry`/`friend`/`menu`/`newslist` at `7/7` each) |
| IPC tables from decompiled C | `tools/extract_ipc_from_decomp.py` -> 2 065 case rows, 94 dispatchers in 48 binaries (`docs/decompiled_notes/IPC_TABLES.md`); validated against the older hand analysis (gsp::Gpu 31, hid 24, mcu::RTC 92 commands). Thumb / non-`switch` dispatchers not covered. |
| Names proven by decompiled C | `tools/name_from_decomp.py` -> `symbols/derived_decomp/` (3 765 non-overlapping rows across both models: SVC wrappers, TLS accessors, IPC server loops), merged as `derived_decompiled` (`2 654` N3DS rows; master table `24 437` rows) |
| Kernel11 unresolved (16) | 5 resolved/identified by reading C (see `decompiled_notes/kernel11_native_vs_o3ds.md`), 11 open |
| `gsp` unresolved (9) | 3 resolved (`gsp_gx_command_queue_proc`, `gsp_gpu_cache_inv_and_ctrl`, maybe irq handler), 6 open |
| `mcu` unresolved (1) | resolved (`mcu_svc_0x3C_Break_103acc`) |
| ARM9 unresolved (40) | 2 resolved (interwork stubs); 38 open (mostly <= 4-byte vobj stubs; `arm9_mpu_and_aes_cfg_init`, `k9_cfg9_drv_02`, `k9_aes_drv_01` need a read of the N3DS entry code `0x0808AA3C` / `decompiled_arm9loader_tail`) |
| `spi` module | dispatcher + cmd table documented (`decompiled_notes/Module-SPI-...md`); command semantics open |
| qtm / mvd / mcopy / other N3DS-only | not started beyond the server-loop/port facts below |

Facts already established for **qtm** (`0004013020004202`): `FUN_00100214` is the module main (registers 4 ports in a loop - names `qtm:c`, `qtm:sp`, `qtm:s`, `qtm:u` sit together in `.data` at `0x1AA8A4` - then a ReplyAndReceive loop through the svc 0x4F wrapper `FUN_00115928`); command handlers `0x103464`/`0x1035C4`/`0x1039F8` (cases 1-6, reply headers `0x00010340 0x00030040 0x00040040 0x00050040 0x00060080`) and a second dispatcher `0x103918` (cases 1-5+). Next step: read the handlers behind each case (`FUN_00113a38`, `FUN_001137e0`, ...) and the face-tracking worker (largest functions `0x11c098` 6 KB, `0x109d18` 5 KB).

## 3. Operating notes for a new session
* Read `/home/skels/3ds-reversing/CLAUDE.md` first (layout, pitfalls: ExHeader names are truth, load addresses, `python3 -I` vs numpy, ctrtool quirks, no-`rm` rule with shell variables).
* The chat language is Spanish; every file is English. Never invent names or addresses; keep confidence levels.
* `tools/run_all.sh` rebuilds the symbol side (2-3 min); it does **not** run the bulk decompiler (hours). Do not delete `symbols/manual/`, `*/decompiled*/` or `*/analysis/` by hand.
* Other processes may rename directories while you work; re-list before using paths.

## 4. Work log
| Date | What |
|---|---|
| 2026-11-24 | Re-ran full bulk decompilation with `--fresh` (`tools/decompile_all.sh 5 --fresh`), baking all manual/derived/library/firm_module/O3DS names into the `.c` files and fixing `ghidra_decompile.py` / `decompile_jobs.py` / `DecompileAll.java` / `name_from_decomp.py` (`316 625` of `317 628` functions decompiled; `2 065` IPC cases across `94` dispatchers in `48` binaries). |
| 2026-11-24 | Bulk decompilation finished (154 binaries). IPC tables, decompiled-C naming and manual Kernel11/gsp/mcu/ARM9 findings added (see 2.4). |
| 2026-11-24 | Third round: titles extracted/analysed (RTTI, library propagation); headless Ghidra bulk decompiler + job generator + status/IPC tools written; bulk run started (5 parallel). Manual layer procedure and queue defined (this file). |
