# Symbol Table and Files — ARM11 and ARM9 Kernels (EL1)

> **Status:** `[VERIFIED IN THIS REPO]` — Symbols derived from `arm11_section1.bin` (real Kernel11, base `0x1FF80000` / runtime `0xFFF00000`), `arm9.bin` (Kernel9 `0x08006800` + Process9 `0x08028000`), and `arm11.bin` (5 NCCH modules embedded in FIRM).
>
> **Confidence rule (`CONFIRMED` vs `EVIDENCE_BASED`):**
> - **`CONFIRMED`:** Absolute certainty by direct anchoring in the binary/hardware (FIRM header, ARM vectors, the 109 SVCs at `0xFFF02328`, the 40 SWIs at `0x08007938`, C++ vtables + `destructor` + `GetTypeObj`, `CP15` opcodes / `ldrex`/`strex` atomics, literal MMIO accesses verified in C/ASM, direct XREFs to real strings and CRT/algorithmic routines audited 100 % in C).
> - **`EVIDENCE_BASED`:** Subsystem or role demonstrated by direct verified evidence (Ghidra C pseudocode, `Result` code, shared `.rodata` vtable slot or direct callgraph), without assuming the original source name beyond what was observed.
> - **`HYPOTHESIS`: 0** (all non-code false positives were purged).

---

## 1. Verified and Evidence-Based Symbols (Real Strings and XREFs)

### 1.1 ARM9 Kernel9 + Process9 (`arm9.bin` — **4,849** entries: **311 `CONFIRMED`**, **4,538 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`**)

> **Address note:** `Kernel9` runs at `0x08006800`. `Process9` (NCCH at file offset `0x15B00`, `.code` at `0x16700`) has `text_addr = 0x08028000` (`+0xB100` relative to `0x08006800 + file_offset`).

| VA in `arm9.bin` | Runtime VA | Confidence | Name | Verified evidence `[VERIFIED]` |
|------------------|------------|------------|------|--------------------------------|
| `0x0801B01C` | `0x0801B01C` | **CONFIRMED** | `arm9_firm_entry_point` | FIRM header entry point |
| `0x08006830` | `0x08006830` | **CONFIRMED** | `kernel9_main_init` | Final target of `arm9_firm_entry_point` (`0x0801B110`) |
| `0x0800E7E0` | `0x0800E7E0` | **CONFIRMED** | `kernel9_exception_vectors` | Vector table referenced at `0x0801B108` |
| `0x08007878` | `0x08007878` | **CONFIRMED** | `kernel9_swi_dispatcher` | SWI dispatcher with permission bitmap |
| `0x08007938` | `0x08007938` | **CONFIRMED** | `kernel9_swi_table` | Table of 40 SWI pointers (`0x08..0x7C`) |
| `0x08007B30` | `0x08007B30` | **EVIDENCE_BASED** | `k9_swi_0x7B_Backdoor` | Executes callback `blx r0` in Supervisor mode |
| `0x08018FA4..0x0801939C` | `0x08018FA4..0x0801939C` | **CONFIRMED** | `k9_vtbl_KDmaObject` .. `k9_vtbl_KProcess` | 11 Kernel9 C++ vtables + `GetTypeObj` + destructors |
| `0x0801E100` | `0x08029200` | **EVIDENCE_BASED** | `p9_nand_firm_twl_partitions` | UTF-16LE XREF to `"wnand"`, `"firm0"`, `"firm1"`, `"twls"` |
| `0x08025EA4` | `0x08030FA4` | **EVIDENCE_BASED** | `p9_movable_sed_path_handler` | UTF-16LE XREF to `"/private/movable.sed"` |
| `0x0802710C` | `0x0803220C` | **EVIDENCE_BASED** | `p9_sd_nintendo_3ds_dir_1` | UTF-16LE XREF to `"/Nintendo 3DS"` |
| `0x080276BC` | `0x080327BC` | **EVIDENCE_BASED** | `p9_fat_fs_type_detect` | Thumb XREF (`0x080327EA`) to `"FAT12"`, `"FAT16"`, `"FAT32"` |
| `0x080287F0` | `0x080338F0` | **EVIDENCE_BASED** | `p9_ertfs_init_error` | Thumb XREF (`0x08033942`) to `"pc_ertfs_init failed"` |
| `0x0802C0E4` | `0x080371E4` | **EVIDENCE_BASED** | `p9_ertfs_volume_clean_check` | Thumb XREF (`0x08037238`) to `"Volume is dirty"`, `"Volume is clean"` |
| `0x08038F0C` | `0x0804400C` | **EVIDENCE_BASED** | `p9_firm_exe_path_format` | Thumb XREF (`0x08044032`) to `"exe:/%016llx/.firm"` |
| `0x080424AC` | `0x0804D5AC` | **EVIDENCE_BASED** | `p9_aes_drv_01_0x080424AC` | Direct access to AES MMIO `0x10009000` |
| `0x0805F10C` | `0x0806A20C` | **EVIDENCE_BASED** | `p9_title_import_db_handler` | UTF-16LE XREF to `"/dbs/title.db"`, `"/dbs/import.db"` |
| `0x08062E40` | `0x0806DF40` | **EVIDENCE_BASED** | `p9_ticket_certs_db_handler` | UTF-16LE XREF to `"/dbs/ticket.db"`, `"/dbs/certs.db"` |
| `0x08064768` | `0x0806F868` | **EVIDENCE_BASED** | `p9_quota_dat_handler` | UTF-16LE XREF to `"/Quota.dat"` |
| `0x0806B080` | `0x08076180` | **EVIDENCE_BASED** | `p9_cardspi_archive_handler` | UTF-16LE XREF to `"cardspi"` |
| `0x08079B58` | `0x08084C58` | **EVIDENCE_BASED** | `p9_firm_exe_8x8x_format` | UTF-16LE XREF to `"exe:/%08x%08x/.firm"` |

Full list (**4,849 entries**: **311 `CONFIRMED`**, **4,538 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`** — including the 40 `CONFIRMED` SWI handlers, the 11 Kernel9 `K*` classes, C-audited primitives such as `p9_memcpy`, `p9_memset_byte`, `p9_memcmp`, `p9_utf16_strlen`, `k9_critical_section_enter`, `k9_slab_alloc`, 39+ Process9 functions found through ASCII/UTF-16LE strings, MMIO drivers `AES`/`SHA`/`RSA`/`SDMMC`/`NTRCARD`/`CTRCARD`/`PXI9`/`NDMA`/`XDMA`/`TIMER9`/`SPI9`/`CFG9`/`PRNG`, 55 `.rodata` vtable slots enriched per subsystem and clean propagation without CRT contamination): `decrypted_binaries/kernel/arm9_friendly.sym`.

### 1.2 ARM11 Kernel11 (`arm11_section1.bin` — **838** entries: **287 `CONFIRMED`**, **551 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`**)

| VA | Confidence | Name | Verified evidence `[VERIFIED]` |
|----|------------|------|--------------------------------|
| `0x1FFAE034` | **CONFIRMED** | `arm11_firm_entry_point` | Real entry point of the FIRM header (in Section 1) |
| `0x1FFAD000` | **CONFIRMED** | `kernel11_exception_vectors` | Vector page mapped at `0xFFFF0000` |
| `0xFFF00030` | **CONFIRMED** | `kernel11_main_init` | Target of the `bx r0` at the end of `arm11_firm_entry_point` |
| `0xFFF0220C` | **CONFIRMED** | `kernel11_svc_dispatcher` | SVC dispatcher (`0xFFFF0008` → `0xFFF00608` → `0xFFF0220C`) |
| `0xFFF02328` | **CONFIRMED** | `kernel11_svc_table` | Table of 109 active SVCs (`0x01..0x7D`) |
| `0xFFF02144` | **CONFIRMED** | `kernel11_irq_handler` | IRQ handler (calls `k11_gic_irq_dispatch` `0xFFF06450`) |
| `0xFFF020CC` | **CONFIRMED** | `kernel11_data_abort_handler` | Data Abort handler (with fixup range `[0xFFF15144, 0xFFF1532C)`) |
| `0xFFF02084` | **CONFIRMED** | `kernel11_prefetch_abort_handler` | Prefetch Abort handler |
| `0xFFF02520` | **CONFIRMED** | `kernel11_undef_handler` | Undef handler (lazy VFP context switch) |
| `0xFFF005D0` | **CONFIRMED** | `kernel11_fiq_handler` | FIQ handler |
| `0xFFF06058` | **EVIDENCE_BASED** | `svc_0x11_GetCurrentProcessorNumber` | `mrc p15, 0, r0, c0, c0, 5; and r0, r0, 3` |
| `0xFFF03664` | **EVIDENCE_BASED** | `svc_0x3E_ControlPerformanceCounter` | Calls `0xFFF0AC44` (`k11_pmu_control_dispatch`) |
| `0xFFF0AC44` | **EVIDENCE_BASED** | `k11_pmu_control_dispatch` | 9-case switch that invokes `0xFFF11070..0xFFF11668` |
| `0xFFF11070` | **CONFIRMED** | `k11_pmu_read_pmnc` | `mrc p15, 0, r1, c15, c12, 0` (PMNC) |
| `0xFFF1113C` | **CONFIRMED** | `k11_pmu_write_pmnc` | `mcr p15, 0, ..., c15, c12, 0` (PMNC) |
| `0xFFF11498` | **CONFIRMED** | `k11_pmu_read_counter` | Reads `c15, c12, 1` (`CCNT`), `c15, c12, 2` (`PMN0`), `c15, c12, 3` (`PMN1`) |
| `0xFFF06064` | **EVIDENCE_BASED** | `svc_0x52_InvalidateProcessDataCache` | Calls `0xFFF0AE48` with `0xFFF2D1F4` → `0xFFF2584C` |
| `0xFFF05E1C` | **EVIDENCE_BASED** | `svc_0x53_StoreProcessDataCache` | Calls `0xFFF0AE48` with `0xFFF2D1E0` → `0xFFF1DA3C` |
| `0xFFF05AE0` | **EVIDENCE_BASED** | `svc_0x54_FlushProcessDataCache` | Calls `0xFFF0AE48` with `0xFFF2D1CC` → `0xFFF1D7D4` |
| `0xFFF15980` | **EVIDENCE_BASED** | `svc_0x7C_KernelSetState` | 10-case switch (`0..9`), writes `0xFFFEFF00` |
| `0xFFF2D68C` / `0xFFF074D4` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KEvent` / `KEvent_create_or_init` | C++ vtable + `KEvent_GetTypeObj` (`0xFFF2C15C`) + `KEvent_destructor` (`0xFFF2C76C`) |
| `0xFFF2D6E4` / `0xFFF0764C` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KMutex` / `KMutex_create_or_init` | C++ vtable + `KMutex_GetTypeObj` (`0xFFF2C180`) + `KMutex_destructor` (`0xFFF2C7A8`) |
| `0xFFF2D7FC` / `0xFFF07BB8` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KThread` / `KThread_create_or_init` | C++ vtable + `KThread_GetTypeObj` (`0xFFF2C1E4`) + `KThread_destructor` (`0xFFF2C85C`) |
| `0xFFF2D8A0` / `0xFFF086CC` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KProcess` / `KProcess_create_or_init` | C++ vtable + `KProcess_GetTypeObj` (`0xFFF2C31C`) + `KProcess_destructor` (`0xFFF2C8D4`) |

Full list (**838 entries**: **287 `CONFIRMED`**, **551 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`** — including the 109 `CONFIRMED` SVC handlers, the 20 `K*` classes with `GetTypeObj`/`finalize`/`destructor` and `KMutex` priority inheritance, the `kernel11_launch_firm_sysmodules` launcher, GIC/SCU/CDMA PL330/MMU/Cache/PMU, critical sections/slabs/lists, `k11_memcpy`/`k11_memzero32_aligned` and 119 additional functions revealed by Ghidra 12.2): `decrypted_binaries/kernel/arm11_kernel11_friendly.sym`.

> **About `arm11.bin` (`0x1FF00000`):** Contains the 5 NCCH containers embedded in FIRM (`fs` @ `0x1FF00000`, `loader` @ `0x1FF26600`, `pm` @ `0x1FF29A00`, `sm` @ `0x1FF2E800`, `pxi` @ `0x1FF32200`). The string `"fs:LDR"` @ `0x1FF26A50` belongs to the `loader` module embedded in Section 0, not to the Section 1 Kernel11.

---

## 2. Generated Symbol Files

| File | Description | Target binary |
|------|-------------|---------------|
| `arm11_kernel11_friendly.sym` | Real Kernel11 table (**838** entries: **287** `CONFIRMED`, **551** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `arm11_section1.bin` (`-m 0xFFF00000`) |
| `symbols_arm11_kernel11_friendly.r2` | radare2 flags for Kernel11 | `arm11_section1.bin` |
| `symbols_arm11_kernel11_friendly_ghidra.py` | Ghidra script for Kernel11 | `arm11_section1.bin` |
| `pseudocode_k11/` | **654** C pseudocode files exported by REA + Ghidra 12.2 (`0` failures) | `arm11_section1.bin` (`-m 0xFFF00000`) |
| `arm9_friendly.sym` | Enriched ARM9 table (**4,849** entries: **311** `CONFIRMED`, **4,538** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `arm9.bin` (`-m 0x08006800`) |
| `symbols_arm9_friendly.r2` | radare2 flags for ARM9 | `arm9.bin` |
| `symbols_arm9_friendly_ghidra.py` | Ghidra script for ARM9 | `arm9.bin` |
| `pseudocode_arm9/` | **2,673** C pseudocode files exported by REA + Ghidra 12.2 (`14` overlapping ARM/Thumb failures) | `arm9.bin` (`-m 0x08006800`) |

---

## 3. Reproduction Commands

```bash
# Kernel11 (runtime base 0xFFF00000 over arm11_section1.bin)
r2 -a arm -b 32 -m 0xFFF00000 -i decrypted_binaries/kernel/symbols_arm11_kernel11_friendly.r2 decrypted_binaries/kernel/arm11_section1.bin

# ARM9 Kernel9 + Process9 (base 0x08006800 over arm9.bin)
r2 -a arm -b 32 -m 0x08006800 -i decrypted_binaries/kernel/symbols_arm9_friendly.r2 decrypted_binaries/kernel/arm9.bin
```

> **New 3DS:** the equivalent N3DS tables (transferred from these files with byte-level verification) are in `../n3ds/symbols/` (`kernel9_process9.*`, `kernel11.*`, merged `N3DS_SYMBOL_TABLE.csv`).
