# Tabla y Archivos de Símbolos — Kernels ARM11 y ARM9 (EL1)

> **Estado:** `[VERIFICADO EN ESTE REPO]` — Símbolos derivados de `arm11_section1.bin` (Kernel11 real, base `0x1FF80000` / runtime `0xFFF00000`), `arm9.bin` (Kernel9 `0x08006800` + Process9 `0x08028000`), y `arm11.bin` (5 módulos NCCH integrados en FIRM).
>
> **Regla de confianza (`CONFIRMED` vs `EVIDENCE_BASED`):**
> - **`CONFIRMED`:** Certeza absoluta por anclaje directo en el binario/hardware (header FIRM, vectores ARM, los 109 SVCs de `0xFFF02328`, los 40 SWIs de `0x08007938`, vtables C++ + `destructor` + `GetTypeObj`, opcodes `CP15`/atómicos `ldrex`/`strex`, accesos MMIO literales verificados en C/ASM, XREFs directos a strings reales y rutinas CRT/algorítmicas auditadas al 100% en C).
> - **`EVIDENCE_BASED`:** Subsistema o rol demostrado por evidencia directa verificada (pseudocódigo C de Ghidra, código `Result`, slot compartido de vtable `.rodata` o callgraph directo), sin asumir el nombre fuente original más allá de lo observado.
> - **`HYPOTHESIS`: 0** (todos los falsos positivos no-código fueron depurados).

---

## 1. Símbolos Verificados y Basados en Evidencia (Strings Reales y XREFs)

### 1.1 ARM9 Kernel9 + Process9 (`arm9.bin` — **4,849** entradas: **311 `CONFIRMED`**, **4,538 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`**)

> **Nota de direcciones:** `Kernel9` ejecuta en `0x08006800`. `Process9` (NCCH en offset de archivo `0x15B00`, `.code` en `0x16700`) tiene `text_addr = 0x08028000` (`+0xB100` respecto a `0x08006800 + file_offset`).

| VA en `arm9.bin` | VA Runtime | Confianza | Nombre | Evidencia Verificada `[VERIFICADO]` |
|------------------|------------|-----------|--------|-------------------------------------|
| `0x0801B01C` | `0x0801B01C` | **CONFIRMED** | `arm9_firm_entry_point` | Entry point del header FIRM |
| `0x08006830` | `0x08006830` | **CONFIRMED** | `kernel9_main_init` | Destino final de `arm9_firm_entry_point` (`0x0801B110`) |
| `0x0800E7E0` | `0x0800E7E0` | **CONFIRMED** | `kernel9_exception_vectors` | Tabla de vectores referenciada en `0x0801B108` |
| `0x08007878` | `0x08007878` | **CONFIRMED** | `kernel9_swi_dispatcher` | Dispatcher SWI con bitmap de permisos |
| `0x08007938` | `0x08007938` | **CONFIRMED** | `kernel9_swi_table` | Tabla de 40 punteros SWI (`0x08..0x7C`) |
| `0x08007B30` | `0x08007B30` | **EVIDENCE_BASED** | `k9_swi_0x7B_Backdoor` | Ejecuta callback `blx r0` en modo Supervisor |
| `0x08018FA4..0x0801939C` | `0x08018FA4..0x0801939C` | **CONFIRMED** | `k9_vtbl_KDmaObject` .. `k9_vtbl_KProcess` | 11 vtables C++ Kernel9 + `GetTypeObj` + destructores |
| `0x0801E100` | `0x08029200` | **EVIDENCE_BASED** | `p9_nand_firm_twl_partitions` | UTF-16LE XREF a `"wnand"`, `"firm0"`, `"firm1"`, `"twls"` |
| `0x08025EA4` | `0x08030FA4` | **EVIDENCE_BASED** | `p9_movable_sed_path_handler` | UTF-16LE XREF a `"/private/movable.sed"` |
| `0x0802710C` | `0x0803220C` | **EVIDENCE_BASED** | `p9_sd_nintendo_3ds_dir_1` | UTF-16LE XREF a `"/Nintendo 3DS"` |
| `0x080276BC` | `0x080327BC` | **EVIDENCE_BASED** | `p9_fat_fs_type_detect` | Thumb XREF (`0x080327EA`) a `"FAT12"`, `"FAT16"`, `"FAT32"` |
| `0x080287F0` | `0x080338F0` | **EVIDENCE_BASED** | `p9_ertfs_init_error` | Thumb XREF (`0x08033942`) a `"pc_ertfs_init failed"` |
| `0x0802C0E4` | `0x080371E4` | **EVIDENCE_BASED** | `p9_ertfs_volume_clean_check` | Thumb XREF (`0x08037238`) a `"Volume is dirty"`, `"Volume is clean"` |
| `0x08038F0C` | `0x0804400C` | **EVIDENCE_BASED** | `p9_firm_exe_path_format` | Thumb XREF (`0x08044032`) a `"exe:/%016llx/.firm"` |
| `0x080424AC` | `0x0804D5AC` | **EVIDENCE_BASED** | `p9_aes_drv_01_0x080424AC` | Acceso directo a MMIO AES `0x10009000` |
| `0x0805F10C` | `0x0806A20C` | **EVIDENCE_BASED** | `p9_title_import_db_handler` | UTF-16LE XREF a `"/dbs/title.db"`, `"/dbs/import.db"` |
| `0x08062E40` | `0x0806DF40` | **EVIDENCE_BASED** | `p9_ticket_certs_db_handler` | UTF-16LE XREF a `"/dbs/ticket.db"`, `"/dbs/certs.db"` |
| `0x08064768` | `0x0806F868` | **EVIDENCE_BASED** | `p9_quota_dat_handler` | UTF-16LE XREF a `"/Quota.dat"` |
| `0x0806B080` | `0x08076180` | **EVIDENCE_BASED** | `p9_cardspi_archive_handler` | UTF-16LE XREF a `"cardspi"` |
| `0x08079B58` | `0x08084C58` | **EVIDENCE_BASED** | `p9_firm_exe_8x8x_format` | UTF-16LE XREF a `"exe:/%08x%08x/.firm"` |

Lista completa (**4,849 entradas**: **311 `CONFIRMED`**, **4,538 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`** — incluyendo los 40 handlers SWI `CONFIRMED`, las 11 clases `K*` de Kernel9, primitivas auditadas en C como `p9_memcpy`, `p9_memset_byte`, `p9_memcmp`, `p9_utf16_strlen`, `k9_critical_section_enter`, `k9_slab_alloc`, 39+ funciones Process9 por strings ASCII/UTF-16LE, drivers MMIO `AES`/`SHA`/`RSA`/`SDMMC`/`NTRCARD`/`CTRCARD`/`PXI9`/`NDMA`/`XDMA`/`TIMER9`/`SPI9`/`CFG9`/`PRNG`, 55 slots de vtables `.rodata` enriquecidos por subsistema y propagación limpia sin contaminación CRT): `binarios_descifrados/FIRM_0002/arm9_friendly.sym`.

### 1.2 ARM11 Kernel11 (`arm11_section1.bin` — **838** entradas: **287 `CONFIRMED`**, **551 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`**)

| VA | Confianza | Nombre | Evidencia Verificada `[VERIFICADO]` |
|----|-----------|--------|-------------------------------------|
| `0x1FFAE034` | **CONFIRMED** | `arm11_firm_entry_point` | Entry point real del header FIRM (en Section 1) |
| `0x1FFAD000` | **CONFIRMED** | `kernel11_exception_vectors` | Página de vectores mapeada en `0xFFFF0000` |
| `0xFFF00030` | **CONFIRMED** | `kernel11_main_init` | Destino de `bx r0` al final de `arm11_firm_entry_point` |
| `0xFFF0220C` | **CONFIRMED** | `kernel11_svc_dispatcher` | Dispatcher SVC (`0xFFFF0008` → `0xFFF00608` → `0xFFF0220C`) |
| `0xFFF02328` | **CONFIRMED** | `kernel11_svc_table` | Tabla de 109 SVCs activos (`0x01..0x7D`) |
| `0xFFF02144` | **CONFIRMED** | `kernel11_irq_handler` | Handler IRQ (llama `k11_gic_irq_dispatch` `0xFFF06450`) |
| `0xFFF020CC` | **CONFIRMED** | `kernel11_data_abort_handler` | Handler Data Abort (con rango fixup `[0xFFF15144, 0xFFF1532C)`) |
| `0xFFF02084` | **CONFIRMED** | `kernel11_prefetch_abort_handler` | Handler Prefetch Abort |
| `0xFFF02520` | **CONFIRMED** | `kernel11_undef_handler` | Handler Undef (lazy VFP context switch) |
| `0xFFF005D0` | **CONFIRMED** | `kernel11_fiq_handler` | Handler FIQ |
| `0xFFF06058` | **EVIDENCE_BASED** | `svc_0x11_GetCurrentProcessorNumber` | `mrc p15, 0, r0, c0, c0, 5; and r0, r0, 3` |
| `0xFFF03664` | **EVIDENCE_BASED** | `svc_0x3E_ControlPerformanceCounter` | Llama a `0xFFF0AC44` (`k11_pmu_control_dispatch`) |
| `0xFFF0AC44` | **EVIDENCE_BASED** | `k11_pmu_control_dispatch` | Switch de 9 casos que invoca `0xFFF11070..0xFFF11668` |
| `0xFFF11070` | **CONFIRMED** | `k11_pmu_read_pmnc` | `mrc p15, 0, r1, c15, c12, 0` (PMNC) |
| `0xFFF1113C` | **CONFIRMED** | `k11_pmu_write_pmnc` | `mcr p15, 0, ..., c15, c12, 0` (PMNC) |
| `0xFFF11498` | **CONFIRMED** | `k11_pmu_read_counter` | Lee `c15, c12, 1` (`CCNT`), `c15, c12, 2` (`PMN0`), `c15, c12, 3` (`PMN1`) |
| `0xFFF06064` | **EVIDENCE_BASED** | `svc_0x52_InvalidateProcessDataCache` | Llama a `0xFFF0AE48` con `0xFFF2D1F4` → `0xFFF2584C` |
| `0xFFF05E1C` | **EVIDENCE_BASED** | `svc_0x53_StoreProcessDataCache` | Llama a `0xFFF0AE48` con `0xFFF2D1E0` → `0xFFF1DA3C` |
| `0xFFF05AE0` | **EVIDENCE_BASED** | `svc_0x54_FlushProcessDataCache` | Llama a `0xFFF0AE48` con `0xFFF2D1CC` → `0xFFF1D7D4` |
| `0xFFF15980` | **EVIDENCE_BASED** | `svc_0x7C_KernelSetState` | Switch 10 casos (`0..9`), escribe `0xFFFEFF00` |
| `0xFFF2D68C` / `0xFFF074D4` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KEvent` / `KEvent_create_or_init` | Vtable C++ + `KEvent_GetTypeObj` (`0xFFF2C15C`) + `KEvent_destructor` (`0xFFF2C76C`) |
| `0xFFF2D6E4` / `0xFFF0764C` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KMutex` / `KMutex_create_or_init` | Vtable C++ + `KMutex_GetTypeObj` (`0xFFF2C180`) + `KMutex_destructor` (`0xFFF2C7A8`) |
| `0xFFF2D7FC` / `0xFFF07BB8` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KThread` / `KThread_create_or_init` | Vtable C++ + `KThread_GetTypeObj` (`0xFFF2C1E4`) + `KThread_destructor` (`0xFFF2C85C`) |
| `0xFFF2D8A0` / `0xFFF086CC` | **CONFIRMED** / **EVIDENCE_BASED** | `vtbl_KProcess` / `KProcess_create_or_init` | Vtable C++ + `KProcess_GetTypeObj` (`0xFFF2C31C`) + `KProcess_destructor` (`0xFFF2C8D4`) |

Lista completa (**838 entradas**: **287 `CONFIRMED`**, **551 `EVIDENCE_BASED`**, **0 `HYPOTHESIS`** — incluyendo los 109 handlers SVC `CONFIRMED`, las 20 clases `K*` con `GetTypeObj`/`finalize`/`destructor` e inheritance de prioridad `KMutex`, lanzador `kernel11_launch_firm_sysmodules`, GIC/SCU/CDMA PL330/MMU/Cache/PMU, secciones críticas/slabs/listas, `k11_memcpy`/`k11_memzero32_aligned` y 119 funciones adicionales reveladas por Ghidra 12.2): `binarios_descifrados/FIRM_0002/arm11_kernel11_friendly.sym`.

> **Sobre `arm11.bin` (`0x1FF00000`):** Contiene los 5 contenedores NCCH integrados en FIRM (`fs` @ `0x1FF00000`, `loader` @ `0x1FF26600`, `pm` @ `0x1FF29A00`, `sm` @ `0x1FF2E800`, `pxi` @ `0x1FF32200`). La string `"fs:LDR"` @ `0x1FF26A50` pertenece al módulo `loader` embebido en Sección 0, no al Kernel11 de Sección 1.

---

## 2. Archivos de Símbolos Generados

| Archivo | Descripción | Binario Objetivo |
|---------|-------------|------------------|
| `arm11_kernel11_friendly.sym` | Tabla Kernel11 real (**838** entradas: **287** `CONFIRMED`, **551** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `arm11_section1.bin` (`-m 0xFFF00000`) |
| `symbols_arm11_kernel11_friendly.r2` | Flags radare2 para Kernel11 | `arm11_section1.bin` |
| `symbols_arm11_kernel11_friendly_ghidra.py` | Script Ghidra para Kernel11 | `arm11_section1.bin` |
| `pseudocodigo_k11/` | **654** pseudocódigos C exportados por REA + Ghidra 12.2 (`0` fallos) | `arm11_section1.bin` (`-m 0xFFF00000`) |
| `arm9_friendly.sym` | Tabla ARM9 enriquecida (**4,849** entradas: **311** `CONFIRMED`, **4,538** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `arm9.bin` (`-m 0x08006800`) |
| `symbols_arm9_friendly.r2` | Flags radare2 para ARM9 | `arm9.bin` |
| `symbols_arm9_friendly_ghidra.py` | Script Ghidra para ARM9 | `arm9.bin` |
| `pseudocodigo_arm9/` | **2,673** pseudocódigos C exportados por REA + Ghidra 12.2 (`14` fallos ARM/Thumb solapados) | `arm9.bin` (`-m 0x08006800`) |

---

## 3. Comandos de Reproducción

```bash
# Kernel11 (base runtime 0xFFF00000 sobre arm11_section1.bin)
r2 -a arm -b 32 -m 0xFFF00000 -i binarios_descifrados/FIRM_0002/symbols_arm11_kernel11_friendly.r2 binarios_descifrados/FIRM_0002/arm11_section1.bin

# ARM9 Kernel9 + Process9 (base 0x08006800 sobre arm9.bin)
r2 -a arm -b 32 -m 0x08006800 -i binarios_descifrados/FIRM_0002/symbols_arm9_friendly.r2 binarios_descifrados/FIRM_0002/arm9.bin
```
