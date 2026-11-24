# (b) Recreated Symbol Table and Scripts — Nintendo 3DS (ARM11/ARM9)

> **Evidence status:** `[VERIFIED IN THIS REPO]` — The FIRM kernels (`arm11_section1.bin`, `arm9.bin`, `arm11.bin` with 5 embedded FIRM modules) and **58 SysModules** (`decrypted_binaries/Module-*/`) were decrypted with `ctrtool` + `aes_keys.txt` + `movable.sed`. The tables in §6 document the detected functions (`decrypted_binaries/analysis/SysModule_*_funcs.txt`) and the real SVCs of the 58 SysModules and the 5 FIRM modules.
>
> This document delivers:
> 1. A **symbol-table format/template** ready to be filled in once decrypted `arm9.bin`, `arm11.bin`, `code.decompressed.bin` and `exheader.bin` are available.
> 2. **Concrete scripts** (objdump, radare2, Ghidra, REA) to locate, verify and export semantic symbols (function names, structs, enums, addresses/offsets).
> 3. A **golden rule**: a name/address is only recorded if confirmed by cross-references in the binary. Inventing unconfirmed names is expressly forbidden.
>
> **Module naming:** module directories were renamed to English names built from the real ExHeader name (`Module-<NAME>-<Role>-<TitleID>`); the old Spanish labels were often wrong (see `../n3ds/docs/O3DS_LABEL_CORRECTIONS.md`). Wherever this document says `am`, `camera`, … it means the **ExHeader name**, which is authoritative. The N3DS version of these tables is in `../n3ds/symbols/`.

---

## 1. Symbol table format (empty template)

| # | Core | Address (VA) | File offset | Semantic name | Type | Associated struct/enum | Verification signature | Source | State |
|---|------|--------------|-------------|---------------|------|------------------------|------------------------|--------|-------|
| 1 | ARM11 | `0x0800XXXX` | `0xXXXXXX` | `kernel_svc_handler` | Function | `svc_table_t` | Cross-references from the SVC dispatcher | Ghidra + r2 | PENDING (encrypted binary) |
| 2 | ARM9 | `0xFFFF0000` | `0xXXXXXX` | `firm9_reset_vector` | Function | — | Reset vector at 0xFFFF0000 | objdump | PENDING |
| 3 | ARM11 | `0x08YYYYYY` | `0xYYYYYY` | `pxi_send_command` | Function | `pxi_msg_t` | Called from the PXI syscall | r2 + objdump | PENDING |
| … | … | … | … | … | … | … | … | … | … |

**Filling rules (mandatory):**
- `Address (VA)`: virtual load address (e.g. `0x08000000` + section offset). Must match in objdump, r2 and Ghidra.
- `File offset`: real offset inside the `.bin` binary (so it can be re-inspected with `xxd` / `objdump -s`).
- `Semantic name`: only if confirmed by context (reference strings, calls, adjacent structs). If there is no confirmation, use `sub_0xXXXXXX` (synthetic Ghidra/r2 name) and mark State = `NOT CONFIRMED`.
- `Type`: `Function`, `Global variable`, `Struct`, `Enum`, `Constant`, `Exception vector`, `SVC table`.
- `Associated struct/enum`: name of the struct/enum it belongs to or uses.
- `Verification signature`: instructions or data that demonstrate the identification (e.g. `stmfd sp!, {r4-lr, pc}`, `svc #0xXX`, nearby string `"PXI:"`).
- `State`: `CONFIRMED` / `PENDING` / `NOT CONFIRMED` / `HYPOTHESIS`.

> No row of this table may be filled in with invented data. While no decrypted binaries were available, the table stayed empty with state `PENDING`.

---

## 2. Scripts to reproduce symbol discovery and verification

### 2.1 objdump — disassembly and function/SVC search

> Note: the system `objdump` on the analysis machine has no ARM backend; use radare2/REA instead there. The commands are kept for machines with `binutils-multiarch` / `arm-none-eabi-objdump`.

```bash
# ARM11 (ARMv6K, little-endian)
objdump -D -m arm -M force-thumb --no-show-raw-insn \
  --adjust-vma=0x08000000 \
  arm11.bin > arm11.disasm.txt

# ARM9 (ARMv5TE)
objdump -D -m armv5te --no-show-raw-insn \
  arm9.bin > arm9.disasm.txt

# List all SVC instructions (syscall-table candidates)
grep -nE "\svc\b|\svcpl\b|\svcmi\b|\svcne\b" arm11.disasm.txt > arm11_svc.txt

# Raw data dump at an address (useful for exheader/structs)
objdump -s --start-address=0x08001000 --stop-address=0x08001080 arm11.bin

# Look for references to a known address/label
grep -n "0x08001234" arm11.disasm.txt
```

### 2.2 radare2 (r2) — analysis, functions and CSV export

Open and analyse:
```bash
r2 -a arm -b 32 -A arm11.bin
```

Inside r2:
```
aaa              # full analysis
afl              # list detected functions (with addresses)
afli @ fcn.08001000   # info about a function
pd 200 @ entry0  # disassemble 200 instructions at the entry point
px 256 @ 0x08001000  # hexdump of 256 bytes at an address
/ce svc          # search SVC instructions in the analysis
/ce 0xe12fff1e   # search bx lr (typical epilogue)
s 0x08000000     # move the cursor to the load base
```

Export detected functions to CSV (only names that r2 assigned automatically; review by hand before treating them as semantic):
```r2
#!/usr/bin/env r2 -i
aagf
# functions JSON -> convert to CSV externally
aflj
```

Script to write comments only at verified addresses:
```r2
# Example: only if 0x08001000 was verified to be the SVC handler
CC kernel_svc_handler @ 0x08001000
```

### 2.3 Ghidra — import, analysis and symbol export

**Import (GUI):**
- File → New project → Import file → `arm11.bin` / `arm9.bin`.
- **Language:** `ARM:LE:32:v6k` (ARM11 MPCore) / `ARM:LE:32:v5te` (ARM946E-S).
- **Compiler:** `gcc` (or `default`).
- **Image base:** `0x08000000` (adjust according to the header of the decrypted FIRM/CXI).
- Run "Analyze" → "Analyze All".

**Headless (export symbols to CSV):**
```bash
/opt/ghidra_12.1.4_PUBLIC/ghidraRun \
  -import arm11.bin \
  -postscript ExportSymbols.java arm11_symbols.csv
```

`ExportSymbols.java` skeleton (exports only function + address; complete with confirmed names):
```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportSymbols extends GhidraScript {
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        println("VA\tOffset\tName\tType\tState");
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            // Long offset: converting VA to file offset requires the memory map
            println(entry + "\t<file-offset>\t" + f.getName() + "\tFunction\tPENDING");
        }
    }
}
```

> **Naming rule:** in Ghidra, unnamed functions appear as `FUN_0800XXXX`. Those names are synthetic and must NOT be copied into the symbol table as if they were semantic. A semantic name is only recorded if there is evidence (strings, cross-references, use of known structs).

### 2.4 REA — capabilities and address↔offset mapping

```bash
# List provider capabilities (useful to decide what REA can automate)
rea capabilities

# General analysis of a decrypted artifact
rea analyze --path arm11.bin

# Map an analysis address to a file offset (cross r2 ↔ Ghidra ↔ objdump)
rea address-to-file-offset --path arm11.bin --address 0x08001234
```

> REA is not an embedded-firmware disassembler by default; use it for exposure auditing and reconstruction evidence obligations. (In practice REA's Ghidra provider opens raw ARM binaries with `format: raw-binary`, `architecture: arm`, `entry_point: <load address>`, and supports `list_procedures`, `search_bytes`, `xrefs`, `compare` and `match_native_functions`; see `../n3ds/docs/METHODOLOGY.md`.)

---

## 3. ctrtool / makerom — decrypting CXI/CFA (when keys are available)

> **Note:** ctrtool and makerom are installed in `/usr/local/bin/`. They require the console keys (`movable.sed` + `otp.bin` or `keyX/keyY`) to decrypt the SysModule and FIRM CXI/CFA files.

```bash
# Extract exefs/code.bin from a decrypted CXI (example; adjust flags to your version)
ctrtool --exefsdir=exefs/ title.cxi

# ExHeader (access-control metadata and process capabilities)
ctrtool --exheader=exheader.bin title.cxi

# code.bin from the exefs (ARM code of the title/sysmodule)
ctrtool --exefsdir=exefs/ --cd=code.decompressed.bin title.cxi
```

> Only after decryption can the scripts in §2 be applied to recover real symbols.

---

## 4. Naming rules (evidence)

| Situation | What to put in the table |
|-----------|--------------------------|
| Function confirmed by string/cross-reference | Real semantic name, State `CONFIRMED` |
| Function detected by r2/Ghidra without semantic evidence | `FUN_0800XXXX` / `sub_0800XXXX`, State `NOT CONFIRMED` |
| Address with no certainty about what it does | `0x0800XXXX`, empty name, State `PENDING` |
| Hypothesis not verified in the binary | Prefix the comment with `[HYPOTHESIS]`, State `HYPOTHESIS`, do not include in the final table |

---

## 5. REAL symbols found in a decrypted SysModule (VERIFIED)

> Source: `extracted/SysModule_0004013000002102/raw/content.0000.00000005` decrypted with `ctrtool` + `aes_keys.txt`.
> Title: `0004013000002102` ("0430builder", ExHeader name `pdn`), NCCH/CXI format. ARM32/Thumb code (interworking).
> This is a **user-level/application-kernel ARM11 sysmodule**, NOT the FIRM `arm11.bin`/`arm9.bin` kernel (those were decrypted afterwards, see `KERNEL_ANALYSIS.md`).

### 5.1 Functions detected by radare2 (addresses relative to the start of .code)

| Address (relative VA) | Blocks | Size (bytes) | r2 name (synthetic) | State | Note |
|-----------------------|--------|--------------|---------------------|-------|------|
| `0x00000000` | 2 | 44 | `fcn.00000000` | CONFIRMED | Entry point / init (calls fcn.00000024, 0000055c, 0000120c, 00000110, 00000528, 00000164) |
| `0x00000024` | 3 | 28 | `fcn.00000024` | CONFIRMED | `ldr r0,[0x40]`; `ldr r1,[0x44]`; `mov r2,#0`; `bx lr` |
| `0x00000070` | 1 | 8 | `fcn.00000070` | CONFIRMED | `add ip,pc,#1`; `bx ip` (Thumb interworking stub) |
| `0x00000110` | 4 | 26 | `fcn.00000110` | CONFIRMED | `push {r4,r5,r6,lr}`; Thumb jump table |
| `0x00000164` | 37 | 912 | `fcn.00000164` | CONFIRMED | Large function (912 B), main-service candidate |
| `0x00000ec0` | 24 | 504 | `fcn.00000ec0` | CONFIRMED | Medium function (504 B) |
| `0x00001e68` | 35 | 756 | `fcn.00001e68` | CONFIRMED | Largest function (756 B), xref from fcn.00000110 |
| `0x0000160c` | 17 | 328 | `fcn.0000160c` | CONFIRMED | (328 B) |
| `0x0000120c` | 10 | 280 | `fcn.0000120c` | CONFIRMED | (280 B) |
| `0x000009a8` | 11 | 184 | `fcn.000009a8` | CONFIRMED | (184 B) |
| `0x000014b8` | 18 | 224 | `fcn.000014b8` | CONFIRMED | (224 B) |
| … | … | … | … | … | (see `decrypted_binaries/Module-PDN-Power-and-Clock-Domains-0004013000002102/r2_functions_clean.txt` for all 60 functions) |

> The `fcn.XXXXXX` names are synthetic (assigned by radare2). **They are not confirmed semantic names.** To turn them into semantic names, additional evidence is required (reference strings, use of known structs, cross-references). Until then they stay `NOT CONFIRMED` in the semantic sense, although the **address and the code are verified**.

### 5.2 Verified SVC instructions (ARM11 syscalls)

| Address | Instruction | SVC number (immediate) | Containing function | State |
|---------|-------------|------------------------|---------------------|-------|
| `0x0000006c` | `svc 0x9ef000` | `0x9e` | (inside the init flow) | CONFIRMED |
| `0x000000bc` | `svc 0x76f000` | `0x76` | (service flow) | CONFIRMED |

> **Correction after ARM/Thumb analysis:** The opcodes `00f09eef` (`0x6c`) and `00f076ef` (`0xbc`) are actually **Thumb-2 `blx`** instructions (`0xF000 0xEF9E` / `0xF000 0xEF76`) wrongly decoded as ARM32. The **14 real ARM SVCs** (`0xEF0000XX`, verified against their ExHeader bitmap) in `pdn` (`0004013000002102`) are: `0x03, 0x0A, 0x21, 0x22, 0x23, 0x24, 0x27, 0x2B, 0x2D, 0x32, 0x35, 0x3C, 0x4A, 0x4F` (see §6 and `KERNEL_ANALYSIS.md`).

### 5.3 ExHeader (`exheader.bin`) — verified fields

| Offset | Field | Value | State |
|--------|-------|-------|-------|
| `0x00` | Magic | `pdn\0` (`70646e00`) | CONFIRMED |
| `0x0C` | Version/flags | `0x00010200` | CONFIRMED |
| `0x14` | Counter | `0x00000003` | CONFIRMED |
| `0x38` | Field | `0x00000090` (144) | CONFIRMED |
| `0x3C` | Field | `0x0000067c` (1660) | CONFIRMED |
| `0x1C0` | NCCH flags | `0x30010400` | CONFIRMED |
| `0x20C` | Field | `0x00000914` (2324) | CONFIRMED |
| `0x360` | Field | `0x00000003` | CONFIRMED |
| `0x364`+ | Allowed-syscall bitmap | `4e9ffaf0…` (bits = allowed syscalls) | CONFIRMED |

> ctrtool reported the allowed syscalls: `01,02,03,06,08,09,0A,0B,0C,0F,11,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,20,21,22,23,24,25,27,28,29,2A,2B,2C,2D,2E,2F,30,31,32,35,36,37,38,39,3A,3B,3C,3D,47,48,4A,4B,4C,4D,4E,4F,50,51,52,53,54,55,56,57`; `Arm9Capability: none`.

### 5.4 Verified execution mode

- The code mixes **ARM (32-bit)** and **Thumb (16-bit)** instructions (typical GCC interworking for 3DS). Example: `fcn.00000110` uses `push {r4,r5,r6,lr}` / `ldr r4,[pc]` (Thumb), while the entry `0x0` uses `bl` (ARM).
- Endianness: little-endian.
- Entry point: `0x00000000` (relative to the .code load base).

---

## 5b. Generated symbol files (separate from the raw binary)

All files in this section live in:
`decrypted_binaries/Module-PDN-Power-and-Clock-Domains-0004013000002102/` and are **separate from the raw binary** `code.bin`. They were generated from the verified radare2 analysis of the decrypted `.code`.

### 5b.1 `code.sym` — simple symbol table

Format: `Address Size Type Name Verified Notes`

```
0x00000000  0x002C  FUNC    fcn.00000000                    YES         entry_point
0x00000024  0x001C  FUNC    fcn.00000024                    NO          
0x00000070  0x0008  FUNC    fcn.00000070                    NO          stub/thunk
...
0x0000006c  0x0004  INSN    svc_0x9e                        YES         svc_instruction
0x000000bc  0x0004  INSN    svc_0x76                        YES         svc_instruction
```

- **Verified=YES**: confirmed entry/exit (entry point or SVC instruction).
- **Verified=NO**: address and size verified, but the `fcn.*` name is synthetic (radare2), not semantically confirmed.
- 91 function entries + 2 SVC instructions.

### 5b.2 `code.map` — linker-style map

Traditional `.map` file format (section + symbols with addresses/sizes). Useful to import into tools that expect this format.

### 5b.3 `symbols.r2` — radare2 script

Creates flags (`f name @ address`) and comments (`CC`) for the 91 functions and 2 verified SVCs.

```bash
# Load symbols in radare2 over the raw binary:
r2 -i symbols.r2 code.bin
# Or inside r2:
#   . symbols.r2
#   afl               ; list functions with flags
#   pd @ fcn_00000164 ; disassemble the verified large function
```

### 5b.4 `symbols_ghidra.py` — Ghidra script

Creates functions and symbols in the program open in Ghidra. Adjust the image base when loading `code.bin`.

```bash
/opt/ghidra_12.1.4_PUBLIC/ghidraRun \
  -import code.bin \
  -postscript symbols_ghidra.py
```

### 5b.5 `symbols_gdb.txt` — GDB commands

Symbol definitions to load manually in GDB (requires an ELF or add-symbol-file over the raw binary).

```bash
gdb -x symbols_gdb.txt
# then: add-symbol-file code.bin 0x0
```

### 5b.6 Note on `.dwo` / `.dwp` (split DWARF)

No `.dwo`/`.dwp` files were generated because they require an ELF container with real DWARF debug information (`.debug_info`, `.debug_abbrev`, … sections), which raw 3DS binaries do not have. The `.sym`, `.map` files and the radare2/Ghidra/GDB scripts are the practical equivalent for this environment without debug info.

---

## 6. Complete Analysis of the 58 Decrypted SysModules + 5 FIRM Modules `[VERIFIED]`

### 6.1 Identification of the filesystem loader and base modules in FIRM (`arm11.bin`)

Inspecting `decrypted_binaries/kernel/arm11.bin` (FIRM Section 0, load `0x1FF00000`, `218,624 B`), it was verified that it contains **5 decrypted NCCH containers** (`flags[7]=0x07`):

| FIRM module | TitleID | Offset in `arm11.bin` | NCCH size | `.code` size | Services in ExHeader / Strings | Real ARM SVCs used |
|-------------|---------|-----------------------|-----------|--------------|--------------------------------|--------------------|
| **`fs`** | `0004013000001102` | `0x00000` (`0x1FF00000`) | 157,184 B | 220,384 B | Registers `fs:LDR`, `fs:REG`, `fs:USER`; maps `0xFFE1EC01`, `0xFFE1EE01`; strings `/Quota.dat`, `/SEEDDB`, `/TITLETAG` | `0x01..0x03, 0x08..0x0C, 0x17, 0x18, 0x21..0x25, 0x27, 0x28, 0x2B, 0x2D, 0x32, 0x37, 0x3C, 0x49, 0x4A, 0x4F, 0x53..0x57` |
| **`loader`** | `0004013000001302` | `0x26600` (`0x1FF26600`) | 13,312 B | 16,188 B | Consumes **`fs:LDR`** (filesystem/program loader), strings `fs:REG`, `fs:USER`, `srv:`, `srv:pm` | `0x01..0x03, 0x0A, 0x21..0x24, 0x27, 0x28, 0x2B, 0x2D, 0x32, 0x3C, 0x4A, 0x4F, 0x73, 0x75` |
| **`pm`** | `0004013000001202` | `0x29A00` (`0x1FF29A00`) | 19,968 B | 25,764 B | Consumes `fs:REG`; strings `pm:app`, `pm:dbg`, `http:C`, `soc:U` | `0x02, 0x03, 0x05, 0x07..0x0A, 0x12, 0x17..0x19, 0x21..0x25, 0x27, 0x28, 0x2A, 0x2B, 0x2D, 0x32, 0x33, 0x35, 0x39, 0x3C, 0x4A, 0x4F, 0x60, 0x76..0x79, 0x7C` |
| **`sm`** | `0004013000001002` | `0x2E800` (`0x1FF2E800`) | 14,848 B | 17,448 B | Service Manager (`srv:`, `srv:pm`) | `0x01..0x03, 0x15, 0x16, 0x21..0x24, 0x27, 0x2A, 0x2B, 0x35, 0x3C, 0x47, 0x48, 0x4A, 0x4F` |
| **`pxi`** | `0004013000001402` | `0x32200` (`0x1FF32200`) | 13,312 B | 15,180 B | Maps MMIO `0x10163000` (`0xFFE1EC63` → `0x1EC63000`); IRQs `80, 81, 82, 83`; strings `pxi:am9`, `pxi:dev`, `pxi:mc`, `pxi:ps9` | `0x02, 0x03, 0x08..0x0A, 0x13..0x18, 0x21..0x25, 0x27, 0x2B, 0x2D, 0x32, 0x3C, 0x4A, 0x4F, 0x50, 0x51` |

- **Filesystem loader identified:** **`fs` (`0004013000001102`)** implements the file server (`fs:LDR`, `fs:REG`, `fs:USER`) in the first NCCH partition of `arm11.bin`, while **`loader` (`0004013000001302`, at `0x1FF26600`, the area where the string `"fs:LDR"` @ `0x1FF26A50` was observed)** consumes `fs:LDR` and creates processes via `SVC 0x73` (`CreateCodeSet`) and `SVC 0x75` (`CreateProcess`).
- **SysModules with `fs:USER` in the ExHeader (25 modules):** `am` (`0004013000001502`), `cfg` (`0004013000001702`), `cfg` (`0004013000001703`), `ptm` (`0004013000002202`), `ptm` (`0004013000002203`), `ac` (`0004013000002402`), `ac` (`0004013000002403`), `cecd` (`0004013000002602`), `dlp` (`0004013000002802`), `nim` (`0004013000002C02`), `nim` (`0004013000002C03`), `nwm` (`0004013000002D03`), `ssl` (`0004013000002F02`), `ssl` (`0004013000002F03`), `ps` (`0004013000003102`), `ps` (`0004013000003103`), `friends` (`0004013000003202`), `friends` (`0004013000003203`), `boss` (`0004013000003402`), `news` (`0004013000003502`), `ro` (`0004013000003702`), `act` (`0004013000003802`), `nfc` (`0004013000004002`), `ns` (`0004013000008002`), `ns` (`0004013000008003`).

### 6.2 Complete table of the 58 decrypted SysModules

> The complete per-module function lists live in `decrypted_binaries/analysis/SysModule_<TitleID>_funcs.txt` (58 files). The listed SVCs are exclusively ARM `0xEF0000XX` instructions verified against the allowed-syscall bitmap in `exheader.bin`. Module names are the real ExHeader names. For the New 3DS counterparts (same TitleID for 24 modules, `0004013020xxxxxx` for the N3DS-specific builds) see `../n3ds/symbols/N3DS_MODULE_INVENTORY.csv`.

| TitleID | Name (ExHeader) | `text_addr` | `.code` size | Functions (r2) | SVCs used (verified) | Allowed services (ExHeader) | Top 3 functions by size |
|---------|-------------------|---------------|------------------|----------------|---------------------------|---------------------------------|----------------------------|
| `0004013000001502` | `am` | `0x00100000` | 81,920 B | 830 | 24 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x47`, `0x48`, `0x4A`, `0x4F`) | `pxi:am9`, `fs:USER` | `fcn.00005540` (1794B), `fcn.0000a078` (1286B), `fcn.0000aa54` (1032B) |
| `0004013000001503` | `am` | `0x00100000` | 45,056 B | 489 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x47`, `0x48`, `0x4A`, `0x4F`) | `pxi:am9` | `fcn.00001d8c` (2816B), `fcn.00006de0` (800B), `fcn.00008528` (688B) |
| `0004013000001602` | `camera` | `0x00100000` | 98,304 B | 805 | 33 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x55`, `0x56`, `0x57`) | `i2c::CAM`, `pdn:c`, `cfg:s`, `mcu::CAM`, `csnd:SND`, `ptm:s` | `fcn.00002b3c` (890B), `fcn.0000bedc` (694B), `fcn.00000dc8` (688B) |
| `0004013000001702` | `cfg` | `0x00100000` | 57,344 B | 632 | 16 (`0x02`, `0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `SPI::NOR`, `ps:ps`, `i2c::EEP` | `fcn.000008c4` (1442B), `fcn.00001b0c` (978B), `fcn.0000a024` (904B) |
| `0004013000001703` | `cfg` | `0x00100000` | 45,056 B | 353 | 13 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `SPI::NOR`, `ps:ps`, `i2c::EEP` | `fcn.000060c0` (846B), `fcn.0000643c` (582B), `fcn.0000388c` (478B) |
| `0004013000001802` | `codec` | `0x00100000` | 40,960 B | 190 | 23 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pdn:i`, `SPI::CD2`, `gpio:CDC`, `mcu::CDC`, `cfg:s`, `ptm:s` | `fcn.0000146c` (2612B), `fcn.00000194` (1332B), `fcn.00005bf0` (1328B) |
| `0004013000001803` | `codec` | `0x00100000` | 40,960 B | 182 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pdn:i`, `SPI::CD1`, `SPI::CD2`, `SPI::PMC`, `gpio:CDC`, `mcu::CDC`, `cfg:s`, `ptm:s` | `fcn.00005ec4` (2488B), `fcn.00001c88` (1284B), `fcn.000032dc` (1260B) |
| `0004013000001A02` | `dsp` | `0x00100000` | 40,960 B | 124 | 26 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x54`) | `pdn:d`, `cdc:DSP`, `ptm:s`, `cfg:s`, `ps:ps` | `fcn.0000735c` (1384B), `fcn.000001a8` (1140B), `fcn.0000321c` (524B) |
| `0004013000001A03` | `dsp` | `0x00100000` | 40,960 B | 221 | 22 (`0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x54`) | `pdn:d`, `cdc:DSP`, `ptm:s`, `cfg:s`, `ps:ps` | `fcn.000012fc` (1500B), `fcn.000054f4` (1468B), `fcn.00006b48` (664B) |
| `0004013000001B02` | `gpio` | `0x00100000` | 20,480 B | 88 | 16 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | *(none)* | `fcn.0000016c` (936B), `fcn.000028d8` (840B), `fcn.000014f8` (504B) |
| `0004013000001B03` | `gpio` | `0x00100000` | 20,480 B | 83 | 14 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | *(none)* | `fcn.00001b34` (916B), `fcn.00000da4` (812B), `fcn.000019c0` (436B) |
| `0004013000001C02` | `gsp` | `0x00100000` | 61,440 B | 373 | 36 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x54`, `0x55`, `0x56`, `0x59`) | `pdn:g`, `i2c::LCD`, `mcu::GPU`, `cfg:s`, `ptm:s` | `fcn.00000550` (1228B), `fcn.00006f7c` (988B), `fcn.000024a0` (852B) |
| `0004013000001C03` | `gsp` | `0x00100000` | 61,440 B | 337 | 30 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x54`, `0x55`, `0x56`) | `pdn:g`, `gpio:GXS`, `i2c::LCD`, `mcu::GPU`, `cfg:s`, `ptm:s` | `fcn.00000e68` (1428B), `fcn.000075ac` (1096B), `fcn.000033a4` (872B) |
| `0004013000001D02` | `hid` | `0x00100000` | 53,248 B | 256 | 29 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:HID`, `cdc:HID`, `mcu::HID`, `i2c::HID`, `cfg:s`, `ptm:s` | `fcn.00002834` (1152B), `fcn.00000180` (1100B), `fcn.000037d0` (872B) |
| `0004013000001D03` | `hid` | `0x00100000` | 45,056 B | 245 | 27 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:HID`, `cdc:HID`, `mcu::HID`, `i2c::HID`, `cfg:s`, `ptm:s` | `fcn.000062d0` (1132B), `fcn.00002168` (776B), `fcn.00003308` (696B) |
| `0004013000001E02` | `i2c` | `0x00100000` | 28,672 B | 103 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x19`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`) | *(none)* | `fcn.000037f4` (1644B), `fcn.0000013c` (900B), `fcn.00003034` (588B) |
| `0004013000001E03` | `i2c` | `0x00100000` | 28,672 B | 125 | 20 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x19`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`) | *(none)* | `fcn.00001868` (1084B), `fcn.00003894` (1024B), `fcn.00002db0` (792B) |
| `0004013000001F02` | `mcu` | `0x00100000` | 61,440 B | 191 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:MCU`, `i2c::MCU`, `ptm:s` | `fcn.000000e8` (1464B), `fcn.0000086c` (852B), `fcn.00003eb0` (708B) |
| `0004013000001F03` | `mcu` | `0x00100000` | 61,440 B | 241 | 19 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:MCU`, `i2c::MCU`, `ptm:s` | `fcn.00006908` (1592B), `fcn.00007108` (948B), `fcn.0000493c` (940B) |
| `0004013000002002` | `mic` | `0x00100000` | 28,672 B | 153 | 27 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | `cdc:MIC`, `ptm:s` | `fcn.0000034c` (1428B), `fcn.00004240` (892B), `fcn.0000267c` (508B) |
| `0004013000002102` | `pdn` | `0x00100000` | 20,480 B | 91 | 14 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(none)* | `fcn.00000164` (912B), `fcn.00001e68` (756B), `fcn.00000ec0` (504B) |
| `0004013000002103` | `pdn` | `0x00100000` | 16,384 B | 77 | 12 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(none)* | `fcn.00000b14` (904B), `fcn.00000660` (752B), `fcn.00001250` (436B) |
| `0004013000002202` | `ptm` | `0x00100000` | 61,440 B | 705 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x7C`) | `mcu::RTC`, `fs:USER`, `cfg:s`, `pxi:mc`, `pm:app`, `pdn:s` | `fcn.00003f6c` (1016B), `fcn.00005af0` (926B), `fcn.0000b0fc` (880B) |
| `0004013000002203` | `ptm` | `0x00100000` | 53,248 B | 591 | 24 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x7C`) | `mcu::RTC`, `fs:USER`, `cfg:s`, `pxi:mc`, `pm:app`, `pdn:s` | `fcn.00008610` (942B), `fcn.00003100` (904B), `fcn.00006c4c` (848B) |
| `0004013000002302` | `spi` | `0x00100000` | 24,576 B | 120 | 19 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(none)* | `fcn.00000160` (832B), `fcn.00003384` (456B), `fcn.000028a8` (356B) |
| `0004013000002303` | `spi` | `0x00100000` | 24,576 B | 106 | 17 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(none)* | `fcn.00000c8c` (832B), `fcn.00000830` (704B), `fcn.00000654` (452B) |
| `0004013000002402` | `ac` | `0x00100000` | 155,648 B | 1249 | 24 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `ptm:s`, `ps:ps`, `nwm::INF`, `soc:P`, `soc:U`, `cfg:s`, `cfg:nor`, `http:C`, `fs:USER` | `fcn.00003330` (2478B), `fcn.00001878` (1776B), `fcn.00007190` (1456B) |
| `0004013000002403` | `ac` | `0x00100000` | 139,264 B | 1208 | 27 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `ptm:s`, `ps:ps`, `nwm::INF`, `soc:P`, `soc:U`, `cfg:s`, `cfg:nor`, `http:C`, `fs:USER` | `fcn.000089c8` (1744B), `fcn.0000df68` (1354B), `fcn.00017856` (1244B) |
| `0004013000002602` | `cecd` | `0x00100000` | 155,648 B | 1507 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `nwm::CEC`, `fs:USER`, `ptm:s`, `ps:ps`, `cfg:s`, `frd:u` | `fcn.0000aed0` (1280B), `fcn.0000bf94` (1248B), `fcn.00009c3c` (956B) |
| `0004013000002702` | `csnd` | `0x00100000` | 36,864 B | 407 | 31 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x52`, `0x53`, `0x54`) | `cdc:CSN`, `ptm:s` | `fcn.000052fc` (2236B), `fcn.0000105c` (842B), `fcn.000026f4` (556B) |
| `0004013000002703` | `csnd` | `0x00100000` | 32,768 B | 324 | 29 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x52`, `0x53`, `0x54`) | `cdc:CSN`, `ptm:s` | `fcn.00005098` (2124B), `fcn.000023f4` (862B), `fcn.000012e8` (646B) |
| `0004013000002802` | `dlp` | `0x00100000` | 86,016 B | 951 | 30 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x14`, `0x17`, `0x18`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x29`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `am:u`, `cfg:u`, `nwm::UDS`, `ptm:s`, `ps:ps` | `fcn.00010494` (1280B), `fcn.00004f5c` (754B), `fcn.000114b8` (688B) |
| `0004013000002902` | `http` | `0x00100000` | 118,784 B | 658 | 29 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x15`, `0x16`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ptm:s`, `soc:U`, `ssl:C` | `fcn.00009484` (1176B), `fcn.00010eec` (1176B), `fcn.00011544` (1176B) |
| `0004013000002903` | `http` | `0x00100000` | 110,592 B | 597 | 23 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `soc:U`, `ssl:C` | `fcn.0000f29c` (1680B), `fcn.00014e14` (1652B), `fcn.00013360` (1244B) |
| `0004013000002A02` | `mp` | `0x00100000` | 139,264 B | 680 | 34 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | `nwm::EXT`, `cfg:nor`, `ptm:s` | `fcn.000103ac` (4916B), `fcn.00017488` (3708B), `fcn.000149fc` (1540B) |
| `0004013000002A03` | `mp` | `0x00100000` | 139,264 B | 676 | 32 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | `nwm::EXT`, `cfg:nor`, `ptm:s` | `fcn.0000bd5c` (4604B), `fcn.00014550` (3724B), `fcn.00009d14` (1528B) |
| `0004013000002B02` | `ndm` | `0x00100000` | 49,152 B | 703 | 26 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x15`, `0x16`, `0x17`, `0x18`, `0x19`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `ptm:s`, `nwm::EXT`, `nim:ndm`, `ndm:u`, `cecd:ndm`, `frd:n`, `boss:M` | `fcn.000097cc` (688B), `fcn.00001598` (514B), `fcn.00000ca8` (364B) |
| `0004013000002C02` | `nim` | `0x00100000` | 356,352 B | 3143 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `am:net`, `ac:u`, `http:C`, `cfg:s`, `ptm:s`, `ptm:gets` | `fcn.000374dc` (1694B), `fcn.00007038` (1372B), `fcn.0002a5e4` (1356B) |
| `0004013000002C03` | `nim` | `0x00100000` | 225,280 B | 833 | 22 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `am:net`, `ac:u`, `http:C`, `ssl:C`, `cfg:s`, `ptm:s` | `fcn.0002d5bc` (3780B), `fcn.00029984` (3544B), `fcn.0002050c` (3224B) |
| `0004013000002D02` | `nwm` | `0x00100000` | 348,160 B | 2421 | 39 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x55`, `0x56`, `0x57`, `0x58`, `0x5A`) | `cfg:u`, `mcu::NWM`, `ps:ps`, `ptm:s` | `fcn.000024a0` (5830B), `fcn.000539f4` (2196B), `fcn.0001aefc` (1556B) |
| `0004013000002D03` | `nwm` | `0x00100000` | 327,680 B | 1875 | 34 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x55`, `0x56`, `0x57`) | `mcu::NWM`, `ptm:s`, `ps:ps`, `fs:USER` | `fcn.00026950` (4112B), `fcn.00034c3c` (1244B), `fcn.00015c8c` (956B) |
| `0004013000002E02` | `socket` | `0x00100000` | 212,992 B | 644 | 29 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0B`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `nwm::SOC`, `ptm:s` | `fcn.00030518` (2924B), `fcn.0002a800` (2484B), `fcn.0002a050` (2200B) |
| `0004013000002E03` | `socket` | `0x00100000` | 217,088 B | 782 | 25 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0B`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `nwm::SOC`, `ptm:s` | `fcn.0002aa58` (3200B), `fcn.0000eb50` (3108B), `fcn.0002e3e0` (2784B) |
| `0004013000002F02` | `ssl` | `0x00100000` | 356,352 B | 1911 | 25 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x15`, `0x16`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `soc:U`, `ps:ps`, `fs:USER` | `fcn.00022ad4` (6412B), `fcn.0004ce50` (5952B), `fcn.000243e0` (4908B) |
| `0004013000002F03` | `ssl` | `0x00100000` | 356,352 B | 1121 | 22 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `soc:U`, `soc:P`, `ps:ps`, `fs:USER` | `fcn.000255e4` (2396B), `fcn.0005176c` (2064B), `fcn.00053eac` (1848B) |
| `0004013000003102` | `ps` | `0x00100000` | 28,672 B | 159 | 15 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pxi:ps9`, `mcu::PLS`, `fs:USER` | `fcn.00000164` (920B), `fcn.00003bc0` (756B), `fcn.00001d84` (416B) |
| `0004013000003103` | `ps` | `0x00100000` | 24,576 B | 137 | 13 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pxi:ps9`, `mcu::PLS`, `fs:USER` | `fcn.00002aa4` (940B), `fcn.00001730` (752B), `fcn.00002444` (436B) |
| `0004013000003202` | `friends` | `0x00100000` | 413,696 B | 3690 | 27 (`0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `soc:U`, `http:C`, `fs:USER`, `cfg:s`, `ptm:s`, `ps:ps`, `ptm:sets`, `APT:U`, `nwm::EXT` | `fcn.00048a88` (1528B), `fcn.00029028` (1490B), `fcn.00007122` (1308B) |
| `0004013000003203` | `friends` | `0x00100000` | 376,832 B | 3718 | 26 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `soc:U`, `http:C`, `fs:USER`, `cfg:s`, `ptm:s`, `ps:ps`, `ptm:sets`, `APT:U`, `nwm::EXT` | `fcn.00050ef6` (1982B), `fcn.00051b5c` (1338B), `fcn.0004908a` (1268B) |
| `0004013000003302` | `ir` | `0x00100000` | 81,920 B | 388 | 27 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `cfg:s`, `gpio:IR`, `i2c::IR`, `ptm:s` | `fcn.000003ec` (1536B), `fcn.000029f0` (924B), `fcn.0000f7ec` (852B) |
| `0004013000003303` | `ir` | `0x00100000` | 32,768 B | 172 | 22 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:IR`, `i2c::IR`, `ptm:s` | `fcn.00000a7c` (1116B), `fcn.00004008` (1092B), `fcn.00003994` (752B) |
| `0004013000003402` | `boss` | `0x00100000` | 311,296 B | 2949 | 31 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1D`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `http:C`, `ac:u`, `ptm:s`, `ptm:play`, `cfg:s`, `fs:USER`, `ps:ps`, `frd:u`, `cecd:s` | `fcn.000330b2` (3080B), `fcn.00031c30` (1820B), `fcn.0003fb26` (1308B) |
| `0004013000003502` | `news` | `0x00100000` | 49,152 B | 603 | 19 (`0x01`, `0x02`, `0x03`, `0x0A`, `0x17`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `boss:P`, `cecd:s`, `frd:u`, `fs:USER`, `ndm:u`, `nim:u`, `ptm:sysm` | `fcn.0000909c` (688B), `fcn.00008384` (476B), `fcn.00005cd8` (388B) |
| `0004013000003702` | `ro` | `0x14000000` | 45,056 B | 143 | 19 (`0x02`, `0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x70`, `0x71`, `0x72`, `0x7D`) | `ps:ps`, `fs:USER` | `fcn.000041c0` (2088B), `fcn.00006e80` (1560B), `fcn.00000174` (1124B) |
| `0004013000003802` | `act` | `0x00100000` | 167,936 B | 1430 | 22 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x18`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `am:net`, `cfg:s`, `fs:USER`, `http:C`, `ptm:s`, `frd:u` | `fcn.00011874` (1940B), `fcn.0001c77c` (1346B), `fcn.00005e1e` (1308B) |
| `0004013000004002` | `nfc` | `0x00100000` | 110,592 B | 776 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `cfg:u`, `fs:USER`, `ir:USER`, `nwm::EXT`, `ps:ps`, `ptm:s` | `fcn.00015ab8` (904B), `fcn.00010fc0` (842B), `fcn.00000160` (688B) |
| `0004013000008002` | `ns` | `0x00100000` | 151,552 B | 854 | 35 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x54`, `0x55`, `0x56`, `0x7C`) | `APT:U`, `am:u`, `cam:s`, `cfg:s`, `fs:USER`, `nwm::EXT`, `pm:app`, `ps:ps`, `ptm:sysm`, `qtm:sp` | `fcn.0001e8d4` (2924B), `fcn.00000318` (1728B), `fcn.0000b730` (1356B) |
| `0004013000008003` | `ns` | `0x00100000` | 110,592 B | 579 | 31 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x54`, `0x55`, `0x56`, `0x7C`) | `pm:app`, `APT:U`, `cfg:s`, `ps:ps`, `fs:USER`, `nwm::EXT`, `am:u`, `ptm:sysm` | `fcn.000069c8` (3108B), `fcn.000076e8` (1608B), `fcn.00015d88` (1320B) |
