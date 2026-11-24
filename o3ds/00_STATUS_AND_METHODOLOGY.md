# 00. Repository Status and Analysis Methodology (3DS FIRM/ARM)

> **Translator's note:** this is the English translation of the original `00_ESTADO_Y_METODOLOGIA.md`. It records the *initial* state of the repository, when only encrypted containers were present. The binaries have since been decrypted (see `README.md`); sections 1–2 are kept as a historical record of how the encryption was verified.

> **Purpose:** record what was found, what could actually be verified in the binaries present, what is encrypted (and therefore cannot be analysed without console keys), and the concrete commands to reproduce the analysis once we have **decrypted** binaries (`arm9.bin`, `arm11.bin`, `code.decompressed.bin`, `exheader.bin`).

---

## 1. Inventory of what is present in the repository

| Path | Size | Detected type | State | Notes |
|------|------|---------------|-------|-------|
| `extracted/FIRM_0004013800000202/raw/content.0000.0000000b` | 891 904 B | high entropy (not ARM code) | **ENCRYPTED** | FIRM title (wrapped arm11/arm9). `file` wrongly labels it CXI; the header is not NCCH. |
| `extracted/FIRM_0004013800000102/raw/content.0000.00000018` | 1 711 104 B | high entropy | **ENCRYPTED** | FIRM title. |
| `extracted/FIRM_0004013800000002/raw/content.0000.0000006c` | 969 728 B | high entropy | **ENCRYPTED** | FIRM title. |
| `extracted/FIRM_0004013800000003/raw/content.0000.00000001` | 846 848 B | high entropy | **ENCRYPTED** | FIRM title. |
| `extracted/SysModule_000401300000XXXXXX/raw/content.0000.000000NN` | various | `NCCH` / CXI (container) | **CONTAINER READABLE; inner code ENCRYPTED** | `NCCH` header visible at offset `0x100`, but the sections (code.bin) show high entropy and **zero ARM opcodes** (see section 3). |

SysModule titles identified (examples): `0710pseg-ciuser`, `0812builder`, `0215builder`, `1105builder`, etc. These are ARM11-side system modules (services, filesystem, PM, etc.).

> **None** of the requested files exists as a loose file: **there is no `arm9.bin`, `arm11.bin`, `code.decompressed.bin` or `exheader.bin`** as independent files. They must be extracted/decrypted from the FIRM titles and from the ExeFS of the CXIs.

---

## 2. Verified finding: console encryption (VERIFIED IN THIS REPO)

The first bytes of each `content.*` were inspected and ARM instruction signatures were searched for (`e3a0` `mov`, `ea00` `b`, `e59f` `ldr literal`, `e28f` `add`, `e12f` `bx`).

**Result:** high entropy at every tested offset (`0x0`, `0x200`, `0x4000`, `0x8000`, `0x10000`) and **0 ARM opcode pattern matches** in any FIRM. In an 11 264 B SysModule the magic `NCCH` (`4e434348`) is read at `0x100`, confirming a CXI container, but its payload contains no decrypted ARM code.

**Conclusion:** the binaries are encrypted with keys derived from the console hardware (KeyX/KeyY derived from `movable.sed` + OTP / console-unique ID). **Without those keys it is not possible to disassemble, recover symbols or verify addresses in these specific files.**

### What is needed to continue
- `movable.sed` (and/or `otp.bin`) from the source console.
- 3DS decryption tools (for example `ctrtool`, `makerom`, `3dbrew`/`LibreTS` scripts).
- Once decrypted: `arm9.bin` (ARM9 kernel/firm9), `arm11.bin` (ARM11 kernel), `code.decompressed.bin` (decompressed ExeFS code) and `exheader.bin` (process access-control and capability metadata).

---

## 3. Reproduction commands (objdump / radare2 / Ghidra / REA)

> These commands are ready to run **against decrypted binaries**. Items marked `[PENDING: decrypted binary]` apply where relevant.

### 3.1 objdump (ARM disassembly)

```bash
# ARM11 (ARMv6K, little-endian, ARM mode)
objdump -D -m arm -M force-thumb --no-show-raw-insn \
  --adjust-vma=0x08000000 \
  arm11.bin > arm11.disasm.txt

# ARM9 (ARMv5TE)
objdump -D -m armv5te --no-show-raw-insn \
  arm9.bin > arm9.disasm.txt

# Find exception vectors and SVCs in the disassembly
grep -nE "\svc\b|\svcpl\b|\svcmi\b" arm11.disasm.txt | head -50
grep -nE "\bldr\b.*pc,|\bb\b.*#0x" arm9.disasm.txt | head -30

# Dump a data region (exheader / header)
objdump -s -j .rodata -j .data exheader.bin
```

> Note: on this machine the system `objdump` has no ARM backend (`objdump: cannot use the supplied machine`); radare2 and REA/Ghidra are used for disassembly instead.

### 3.2 radare2 (r2)

```bash
# Open in ARM mode, analyze everything
r2 -a arm -b 32 -A arm11.bin

# Inside r2:
aaa              # full analysis
afl              # list detected functions
pd 200 @ entry0  # disassemble 200 instructions at the entry point
px @ 0x08000000  # hexdump at the load address
/ce svc          # search for SVC instructions
/ce 0xe12fff1e   # search for bx lr (typical epilogue)
s 0x08000000     # seek to the load base
afr              # rename function (manual, verified names only)
```

radare2 script to export symbols to CSV (only names confirmed with cross-references):

```r2
#!/usr/bin/env r2 -i
aagf
aflj~{...}   # (see template in RECREATED_SYMBOLS.md)
```

### 3.3 Ghidra (GUI and headless)

New project → Import `arm11.bin` / `arm9.bin`:
- **Language:** `ARM:LE:32:v6k` (ARM11 MPCore) / `ARM:LE:32:v5te` (ARM946E-S)
- **Compiler:** `gcc`
- **Image base:** `0x08000000` (adjust according to the header/FIRM)

Headless (analyze + export symbols):

```bash
/opt/ghidra_12.1.4_PUBLIC/ghidraRun \
  -import arm11.bin \
  -postscript "ExportSymbols.java" arm11_symbols.csv
```

Minimal Ghidra (Java) script to export function + address only if a cross-reference is confirmed:

```java
// ExportSymbols.java - skeleton; fill in only with verified addresses
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportSymbols extends GhidraScript {
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            System.out.println(entry + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses());
        }
    }
}
```

### 3.4 REA (reverse engineering agent)

```bash
# Provider capabilities
rea capabilities

# General analysis of an artifact (on a decrypted binary)
rea analyze --path arm11.bin

# Map an analysis address to a file offset (useful to cross r2 ↔ Ghidra)
rea address-to-file-offset --path arm11.bin --address 0x08001234
```

> REA is not an embedded-firmware disassembler by default; use it for exposure auditing and reconstruction evidence obligations, not to replace objdump/r2/Ghidra for ARM instruction analysis. (In practice REA's Ghidra provider can open decrypted raw ARM binaries with `open_binary` `format: raw-binary`, `architecture: arm`, `entry_point: <load address>`; see `../n3ds/docs/METHODOLOGY.md`.)

---

## 4. Evidence rules adopted in this analysis

| Label | Meaning |
|-------|---------|
| `[VERIFIED IN THIS REPO]` | Checked directly on the files present (encryption, NCCH/CXI containers, sizes, TitleIDs). |
| `[PUBLIC 3DS KNOWLEDGE]` | Documented in 3dbrew / GBATEK / public 3DS reversing. **Not re-verified in these encrypted blobs.** Must be confirmed against decrypted `arm9.bin`/`arm11.bin`. |
| `[HYPOTHESIS / TO BE CHECKED]` | Inference that requires validation on real hardware or decrypted binaries. Do not assume it. |

**Everything that follows (ARM11 vs ARM9 architecture, symbol table, driver guide, README) explicitly separates these three categories.**
