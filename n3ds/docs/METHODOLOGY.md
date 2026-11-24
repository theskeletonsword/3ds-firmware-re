# Methodology (N3DS symbol recreation)

All steps are reproducible from `n3ds/tools/` and `n3ds/extract_n3ds.sh`.

## 1. Decrypting the N3DS titles

| Step | Tool | Result |
|---|---|---|
| CIA → NCCH | `ctrtool --contents` (ticket title key is decrypted with the common key built into ctrtool) | `raw.0000.*` = NCCH |
| NCCH → ExHeader / ExeFS | `ctrtool --exheader --exefs --exefsdir --decompresscode` | `exheader.bin`, `exefs_dir/code.bin` (LZSS-decompressed, valid ARM: `blx`/`bl` at reset vector, readable service strings) |
| FIRM titles | same, then `ctrtool -t firm --firmdir` | `firm_sections/firm_<n>_<addr>.bin` |
| 5 modules embedded in NATIVE_FIRM section 0 | split on `NCCH` magic at 0x100 inside each 0x200-aligned module | `firm_modules/{fs,loader,pm,sm,pxi}` |

Evidence the output is real code and not garbage: 83 % of the 32-bit words of the decrypted ARM9 carry the ARM "always" condition (`0xE`), `arm9.bin` starts with the same Thumb interworking stub as O3DS (`70 47 70 47 01 c0 8f e2 1c ff 2f e1`), readable ExHeader `Name` and service strings in every module, and 148 of the 149 printable strings (≥ 8 chars) of the O3DS `arm9.bin` are also present in the N3DS `arm9.bin`.

### 1.1 The extra N3DS ARM9 layer (arm9loader / K9L2)

NATIVE_FIRM section 2 (`0x08006000`, size `0x8A400`) is **not** a plain ARM9 image on N3DS:

```
0x000  header: [0x00] KeyX-blob  [0x10] KeyY  [0x20] CTR  [0x30] ASCII size "540928"  [0x50] magic "K9L2"  [0x60] 2nd key blob
0x800  AES-CTR encrypted ARM9 binary (540 928 bytes)  -> loaded at 0x08006800 (same as O3DS)
0x84900 plain tail (23 296 bytes) = arm9loader code, FIRM ARM9 entrypoint 0x0808AA3C
```

Working recipe (found by testing key combinations and scoring the result by ARM opcode statistics; `tools/dec_arm9_n3ds.py`):

* normal key = `scramble(KeyX = slot0x16KeyX, KeyY = header[0x10:0x20])` with the 3DS key scrambler and the generator constant from `aes_keys.txt`;
* IV/CTR = `header[0x20:0x30]` **as stored**;
* the 2nd blob at `0x60`, decrypted with the slot-0x11 normal key, equals `slot0x16KeyX` – an independent confirmation that the key schedule is right.

SAFE_MODE_FIRM (`0004013820000003`), TWL_FIRM (`…0102`) and AGB_FIRM (`…0202`) do **not** carry `K9L2` (magic bytes are `FF FF FF FF`). A brute-force over every KeyX/KeyY/KeyN/CTR candidate of `aes_keys.txt` (45 144 combinations, scored by ARM-opcode statistics and entropy) found the older scheme: normal key = `scramble(slot0x15KeyX, header KeyY)`, CTR = header@0x20 as stored. `tools/dec_arm9_n3ds.py` tries both schemes and keeps the one whose output has the lowest entropy; TWL/AGB are Thumb-heavy (entropy 6.3 instead of 5.8), so ARM-condition statistics alone are not a reliable test there.

## 2. Transfer of O3DS symbols

`tools/transfer_syms.py` – for each O3DS symbol (address, size) in `../o3ds/decrypted_binaries/**/*_friendly.sym`:

1. **Whole binary identical** (same `code.bin` bytes and base) → `exact`, same address.
2. **Raw function bytes found exactly once** in the N3DS binary → `exact`.
3. **Masked match** – ARM words (`B/BL/BLX imm`, `LDR/ADD/SUB rX,pc,#imm`) and Thumb halfwords (`BL/BLX` pairs, `LDR/ADR pc-rel`, `B`, `Bcond`) are masked, and 32-bit words that look like addresses (literal pool entries) are zeroed, in both binaries; a unique hit → `probable_by_transfer`.
4. **Ambiguous / short functions** are resolved only if a candidate lies within 0x40 bytes of the address predicted by the shift of the nearest uniquely matched neighbour (anchor); otherwise `unresolved`.
5. Names that embed the O3DS address (e.g. `k9_boot_helper_0x08006C24`) are re-addressed to the N3DS address → `adapted_n3ds`.
6. **Refinement (`tools/refine_matches.py`)** for everything that step 1-4 left unresolved or only ambiguous; each pass is evidence-based and later passes only use what earlier ones established:
   * *call-graph voting* - for each matched pair the ARM `BL/BLX` and Thumb `BL/BLX` pairs found at the **same offsets** in both bodies give target pairs; an unresolved callee receives the N3DS address its matched callers vote for (unanimous or >= 2x runner-up);
   * *layout* - between two matched neighbours the link order is kept: same distance (rule A) or one function that changed size (rule B), accepted only if position-masked similarity >= 0.4;
   * *pointer tables* - vtables / dispatch / worker arrays: the N3DS table is located from >= 2 matched slots (or, for tables without matched slots, from the pointer-spacing pattern or from the strings they point to); unmatched slots and the table symbol itself are then read off it;
   * *similarity* - best masked similarity inside the unclaimed space between neighbours (>= 0.5, margin >= 0.15), or anywhere in the image for moved functions (>= 0.75, margin >= 0.25);
   * *literal constants* - rare pool constants (MMIO bases, sizes, magic numbers) loaded at the same offsets imply the function start;
   * *radare2 function boundaries* - the only unclaimed `aflj` function between two matched neighbours.
7. **Verification of every placed row**: aligned call sites must land on the mapped N3DS callee (`calls_agree`), literal-pool strings at the same offsets must be equal (`strings_agree`), and incoming call sites from matched callers must hit the row's address (`callers_agree`). Rows are `verified` (agreement, no disagreement), `partial`, `no_evidence` (leaf without calls/strings), or `conflict`; a contradicted `exact` row is downgraded to `probable_by_transfer`, a contradicted probable row is demoted to `unresolved`. Several O3DS symbols mapping to one N3DS address (identical copies) are all set to `unresolved`.
8. **Outlier rejection (during master build):** a `probable` match whose shift differs by more than 0x4000 from the median of its 12 nearest neighbours is demoted to `unresolved`.

Symbols with size 0 in the O3DS table are probed with at most 64 bytes of the following code (marked `estimated_size(<=64)` in the evidence column).

Limits worth knowing: the matcher proves *byte equivalence of code*, not semantic identity of surrounding data structures. Exact matches of very small functions (< 8 bytes) are never accepted without an anchor.

## 3. Use of REA (Ghidra 12.2 provider) as independent check

* `open_binary` (raw-binary, `arm`, entry `0x08006800`) of the N3DS `arm9.bin`: 2 770 procedures / 75 strings found by auto-analysis.
* **Cross-check of a transferred symbol** – `p9_movable_sed_path_handler`: transferred to `0x08025CA4` (exact). REA `search_bytes` for the UTF-16LE string `movable` found it at `0x08025D06` (= handler + 0x62). In O3DS the handler is `0x08025EA4` and the string `0x08025F06` (= handler + 0x62). Same relative layout, shifted by −0x200 in both.
* `open_binary` of `0004013020004202/code.bin` (qtm): 574 procedures, 52 strings; used with `strings`/SVC scan to document the N3DS-only module.
* **Cross-check of refined placements (N3DS `gsp`)**: REA `procedure_info` on addresses placed by the refinement passes - `0x00101568` (`gsp_lcd_ipc_dispatcher`, `probable_by_callgraph`, O3DS size 0x448) and `0x00109ED4` (`probable_by_similarity`, O3DS size 0x1F8) - shows that Ghidra's own auto-analysis independently created functions with those exact entry points; the second has the identical length (504 B = 0x1F8), the first 1 136 B in two ranges (34 basic blocks) because Ghidra also folds the tail block.
* Limitation: the REA/Ghidra raw-binary language is `ARM:LE:32:v7` without Thumb entry-mode hints, so `procedure_pseudo_code` on Thumb-only Process9 functions fails (`no loaded source mapping`), and Ghidra left the Thumb literal-pool string without xrefs. REA was therefore used for byte/string verification and inventories, not for decompilation of Process9.

## 4. Derived structural symbols (`tools/derive_ipc.py`)

For every N3DS module, including those without an O3DS reference (`qtm`, `mvd`, N3DS builds of `camera`, `nfc`, ...):

* **SVC wrappers** - radare2 functions of <= 0x20 bytes with exactly one `svc #n` and a return are named `<mod>_svc_0xNN_<SvcName>_<addr>` (SVC names from the Kernel11 table in `o3ds/KERNEL_ANALYSIS.md`). 865 wrappers.
* **IPC command handlers / client calls** - a header-shaped literal (`cmd_id<<16 | normal<<6 | translate`, low 16 bits < 0x1000) loaded from the literal pool and stored soon after at `[reg+0]` (reply header, handler) or `[reg+0x80]` / next to `svc #0x32` (request, client call). Names `<mod>_ipc_handler_cmd_<id>_<addr>` / `<mod>_ipc_client_cmd_<id>_<addr>`; every observed header is listed in `symbols/N3DS_IPC_COMMANDS.csv`.
* **IPC dispatchers** - functions with >= 4 distinct header-shaped literals.
* **Service-name strings** - `xxx:yyy` / `xxx::YYY` strings; *client of* if the name is in the ExHeader service-access list, otherwise *name present in module data* (registered port or ACL-table entry).
* **Pointer tables** - runs of >= 3 words pointing at function starts.

Limits: handlers whose header is built with `mov/orr` instead of a literal, and `switch`-based dispatch without header literals, are not seen; the names are structural and carry the level `derived_structural`.

## 5. Module inventory (`tools/module_inventory.py`)

For each module: `code.bin` sha256 vs O3DS counterpart (N3DS-specific TitleID `00040130 20xxxxxx` ↔ O3DS `00040130 00xxxxxx`), ExHeader fields (`ctrtool -t exheader`), service access list, and the SVC numbers actually present as `svc #n` words (`0xEF0000nn`) in the code.
