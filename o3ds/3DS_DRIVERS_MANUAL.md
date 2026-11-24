# Critical Driver Programming Manual — Nintendo 3DS (ARM11/ARM9 EL1)

> **MANDATORY WARNING — READ BEFORE ANY TEST ON REAL HARDWARE**
>
> **ALWAYS make a full NAND backup (and of all critical recovery files: `movable.sed`, `otp.bin`, `seeds`, and copies of `FIRM`/`arm9.bin`/`arm11.bin`) BEFORE testing critical drivers, modifying `FIRM` or writing to the console's storage.**
>
> **What causes a hard brick or boot failure?**
> - Writing a corrupt, badly signed or wrongly keyed `FIRM` to the FIRM partition prevents the ARM9 bootROM from validating the firmware: the console does not even reach the menu (firmware-level hard brick).
> - Corrupting `arm9.bin` (firm9) breaks the security core: without it there is no title decryption, no access to console keys and the system cannot complete secure boot.
> - Corrupting `arm11.bin` prevents the application kernel from initialising: black screen after the logo or a reboot loop.
> - Writing to critical NAND blocks (FIRM, FIRM backup, SecureZone, boot SD/MMC FAT) without a backup makes software recovery impossible unless you have a hardmod / NAND programmer.
> - A faulty kernel driver (null pointer, invalid memory access, buffer overflow, page-table corruption) can cause an ARM11 *kernel panic* and, if it affects boot paths or PXI communication with the ARM9, leave the system unbootable.
>
> **How to mitigate the risk:**
> 1. **Full NAND backup** before touching anything (use a hardmod or Boot9strap/GodMode9 depending on the console state). Store the backup in a safe place, off the console.
> 2. **Back up `movable.sed`, `otp.bin`, `seeds` and copies of `FIRM`/`arm9.bin`/`arm11.bin`** — without them nothing specific to that console can be re-signed/decrypted.
> 3. **Test drivers first in an emulator (Citra) or on a NAND dump on a PC**, never directly on hardware if an alternative exists.
> 4. **Keep a recovery method** (hardmod, NAND programmer, or a spare console with an exploitable bootROM) before writing to FIRM.
> 5. **Never write unsigned kernel code** to a boot partition without being able to revert to a known-good FIRM.
> 6. **Validate checksums and signatures** of any binary before flashing.
>
> If you do not have a NAND backup and a recovery method, **DO NOT test critical drivers or modify FIRM/storage on real hardware**.

---

## 1. Introduction and Scope

This manual describes how to program **critical kernel drivers (EL1)** for the Nintendo 3DS, covering both processors:

- **ARM11 MPCore (ARMv6K):** Application kernel (`arm11.bin`), runs at EL1, manages processes, threads, virtual memory (FCRAM), SVC syscalls, sysmodules, and PXI communication with the ARM9.
- **ARM946E-S (ARMv5TE):** Security core (`arm9.bin`), runs at EL1/secure mode, manages console keys, cryptography, PMIC, secure SD/MMC and secure boot.

> **Verification status:** The kernels `arm11_section1.bin` (real Kernel11), `arm9.bin` (Kernel9 + Process9) and `arm11.bin` (5 NCCH FIRM modules) were decrypted and analysed in this repository (see `KERNEL_ANALYSIS.md`). The load addresses, entry points, exception vectors, the Kernel11 109-SVC table (`0xFFF02328`), the Kernel9 40-SWI table (`0x08007938`), the CP15 PMU (`c15, c12, 0..3`) + `SVC 0x3E`, and the PXI MMIO (`0x1EC63000` / `0x10163000` and `0x10008000`) are **`[VERIFIED]`** directly in the binaries.

---

## 2. System Architecture (Verified in Binary)

### 2.1 Decrypted and Analysed Kernels

| Item | ARM11 Kernel11 (`arm11_section1.bin`) | ARM9 Kernel9 + Process9 (`arm9.bin`) |
|------|---------------------------------------|--------------------------------------|
| File | `decrypted_binaries/kernel/arm11_section1.bin` | `decrypted_binaries/kernel/arm9.bin` |
| Architecture | ARMv6K MPCore | ARMv5TE ARM946E-S |
| Load address (FIRM) | `0x1FF80000` (MMU runtime `0xFFF00000`, vectors `0xFFFF0000`) | `0x08006800` (Process9 `.code` at `0x08028000`) |
| Entry point (FIRM header) | `0x1FFAE034` | `0x0801B01C` |
| Size | 204,800 bytes (`0x32000`) | 541,184 bytes (`0x84200`) |
| Functions | 415 `r2` / 654 Ghidra C (**838** symbols with SVC table, `K*` RTTI and C, **0 `HYPOTHESIS`**) | 4,455 `r2` / 2,673 Ghidra C (**4,849** symbols purged with Ghidra C, **0 `HYPOTHESIS`**) |
| Syscall table | 109 active SVCs at `0xFFF02328` (dispatcher `0xFFF0220C`) | 40 active SWIs at `0x08007938` (dispatcher `0x08007878`) |
| Mode | ARM + Thumb | ARM + Thumb |

> **Note on `arm11.bin` (`0x1FF00000`, 218,624 B):** It is FIRM Section 0 and contains 5 embedded NCCH modules (`fs`, `loader`, `pm`, `sm`, `pxi`).

### 2.2 Separate Symbol Files (they do not modify the raw binaries)

| File | Description |
|------|-------------|
| `arm11_kernel11_friendly.sym` / `arm9_friendly.sym` | Symbol tables (`0 HYPOTHESIS`) rebuilt with Ghidra C |
| `pseudocode_k11/` / `pseudocode_arm9/` | C pseudocode exported by REA + Ghidra 12.2 (`decompile-index.json`) |
| `symbols_arm11_kernel11_friendly.r2` / `symbols_arm9_friendly.r2` | Flag scripts for radare2 |
| `symbols_arm11_kernel11_friendly_ghidra.py` / `symbols_arm9_friendly_ghidra.py` | Import scripts for Ghidra |
| `symbols_arm9_gdb.txt` | GDB commands (ARM9) |

---

## 3. Driver Development for ARM11 (EL1 - Application Kernel)

### 3.1 Execution Environment

The ARM11 driver runs in **SVC (Supervisor) mode** of the ARM11 MPCore processor. It has full access to:
- Virtual memory (FCRAM) through the MMU
- CP15 registers (PMU, cache, MMU)
- Peripherals through MMIO (Memory Mapped I/O)
- Kernel11 SVC syscalls
- PXI communication with the ARM9

### 3.2 Registering a Driver as a Syscall

To expose functionality to userland, an ARM11 driver must register itself in the kernel11 SVC table:

```c
/* TYPICAL STRUCTURE OF AN ARM11 DRIVER (pseudocode, verify offsets) */

struct driver_entry {
    uint32_t svc_number;      /* SVC number assigned by the kernel */
    void* handler;            /* Pointer to the driver's handler function */
    uint32_t permissions;     /* Which processes may call it (capabilities) */
};

/* Conceptual registration - requires kernel11 access */
int register_driver(uint32_t svc_num, void* handler, uint32_t perms);
```

> `[TO BE VERIFIED]` The exact SVC registration mechanism in kernel11 requires analysis of the SVC handler in `arm11.bin`.

### 3.3 Access to CP15 Registers (PMU `c15,c12`, Cache, MMU) `[VERIFIED]`

The ARM11 MPCore exposes its PMU through **CP15 `c15, c12, 0..3`** (verified in `arm11_section1.bin` @ `0xFFF11074..0xFFF11768`, not the ARMv7 `c9, c12`) and also exposes it to authorised processes through **`SVC 0x3E`** (`0xFFF03664` → `0xFFF0AC44`, disabled in the retail SysModule ExHeaders):

```c
/* Real PMU registers on the ARM11 MPCore (CP15 c15, c12) - kernel mode only */
static inline uint32_t arm11_pmu_read_pmnc(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 0" : "=r" (val));
    return val;
}

static inline void arm11_pmu_write_pmnc(uint32_t val) {
    __asm__ volatile ("mcr p15, 0, %0, c15, c12, 0" :: "r" (val));
}

static inline uint32_t arm11_pmu_read_ccnt(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 1" : "=r" (val));
    return val;
}

static inline uint32_t arm11_pmu_read_pmn0(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 2" : "=r" (val));
    return val;
}

static inline uint32_t arm11_pmu_read_pmn1(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 3" : "=r" (val));
    return val;
}
```

> `[WARNING]` Accessing CP15 from user mode raises `Undefined Instruction`. Only kernel code (SVC mode) can execute `mrc`/`mcr` to CP15.

### 3.4 Memory and Cache Management

For drivers that share memory with the ARM9 (PXI buffers):

```c
/* Clean data cache for an address (dc clean) */
static inline void arm11_cache_clean(void* addr, size_t size) {
    /* Iterate over cache lines and do dc clean */
    __asm__ volatile ("dmb" ::: "memory");
    /* ... line-by-line specific implementation ... */
    __asm__ volatile ("dsb" ::: "memory");
}

/* Invalidate instruction cache (ic invalidate) */
static inline void arm11_cache_invalidate_ic(void) {
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r" (0));
    __asm__ volatile ("dsb" ::: "memory");
    __asm__ volatile ("isb");
}
```

### 3.5 Example: PMU Driver (Performance Counters)

A performance-governor driver can read CCNT to estimate CPU load:

```c
/* Pseudocode - simplified governor */
struct pmu_driver_state {
    uint32_t last_ccnt;
    uint32_t last_time;
    uint32_t cpu_usage_pct;
};

void pmu_driver_tick(struct pmu_driver_state* state) {
    uint32_t current_ccnt = arm11_pmu_read_ccnt();
    uint32_t delta_ccnt = current_ccnt - state->last_ccnt;
    /* Compute usage and decide DVFS */
    state->last_ccnt = current_ccnt;
}
```

---

## 4. Driver Development for ARM9 (EL1 - Security Core)

### 4.1 Execution Environment

The ARM9 driver runs in **Supervisor mode** of the ARM946E-S. It has access to:
- Console keys (keyX/keyY, derived movable.sed)
- Hardware cryptography (AES, RSA, SHA)
- PMIC (power management)
- SD/MMC in secure mode
- NAND SecureZone

### 4.2 Kernel9 SWI Dispatcher and Table `[VERIFIED]`

The ARM9 uses `SWI` (`SVC` on ARM11). In `arm9.bin`, the SWI dispatcher is at **`0x08007878`** and dispatches through the pointer table **`0x08007938`** (**40 active entries** in the range `0x08..0x7C`, checking the process permission bitmap just like Kernel11).

> **Note:** The earlier constants `0xFF8000`/`0xFF8001` at `0x08018F64` were data/constants next to the Kernel9 `K*` RTTI table, not SWI instructions. See `KERNEL_ANALYSIS.md` §4 for the full list of the 40 verified SWI addresses.

### 4.3 Access to Keys and Cryptography

An ARM9 driver that needs cryptography must use the ARM9 kernel services, not access the keys directly:

```c
/* Conceptual - access to ARM9 cryptographic services */
int arm9_crypto_aes_encrypt(const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, uint8_t* out, size_t len);

/* ARM11 drivers CANNOT call this directly - they must go through PXI */
```

> `[WARNING]` Console keys must never be exposed to the ARM11. All cryptographic access from ARM11 must go through PXI → ARM9.

---

## 5. PXI Communication (ARM11 ↔ ARM9)

PXI is the main inter-processor communication channel. An ARM11 driver that needs ARM9 services (cryptography, PMIC, secure SD) must use PXI. The complete verified protocol is documented in `PXI_PROTOCOL.md`.

### 5.1 Verified PXI MMIO Registers and IRQs `[VERIFIED]`

Extracted directly from `FIRM:pxi` (`0004013000001402`, embedded in `arm11.bin` @ `0x32200`) and `arm9.bin`:
- **ARM11 PXI MMIO:** physical `0x10163000`, mapped by the ExHeader (`0xFFE1EC63`) to **`0x1EC63000`**:
  - `+0x00`: `PXI_SYNC` (32-bit)
  - `+0x04`: `PXI_CNT` (16-bit — bit 1 `0x0002` SEND Full, bit 3 `0x0008` Flush, bit 8 `0x0100` RECV Empty, `0xC008` Enable)
  - `+0x08`: `PXI_SEND` (32-bit TX FIFO)
  - `+0x0C`: `PXI_RECV` (32-bit RX FIFO)
- **PXI IRQs (ARM11):** `80..83` (`0x50..0x53`), bound with `SVC 0x50` (`BindInterrupt` @ `0x00102BD4`): `0x52` (82) RECV and `0x53` (83) SEND. *(`PXI_PROTOCOL.md` §2.1 documents the per-IRQ roles verified in `0x001021A8`; that document takes precedence.)*
- **ARM9 PXI MMIO:** **`0x10008000`** (verified in Kernel9 @ `0x0800A148` and Process9 @ `0x0801D4F0..0x0804D28C`).

### 5.2 PXI Flow for Drivers

```
ARM11 driver                          PXI                              ARM9 kernel
--------                              ---                            -----------
1. Prepare payload in shared          ---------------->                4. Receive PXI IRQ
   buffer (clean cache)                                                    5. Read PXI RX command
2. Write command to PXI TX            <---------------                 6. Process request
   register + raise IRQ                                                 7. Write reply to PXI RX
3. Wait with timeout                  ---------------->                8. Raise PXI IRQ
                                                    <---------------   9. ARM11 driver reads reply
```

### 5.3 PXI Hardening Requirements

- **Mandatory timeout:** Every PXI operation must have a timeout to avoid infinite blocking if the ARM9 does not answer.
- **Cache maintenance:** Clean and invalidate the cache lines of the shared buffer before and after every PXI operation.
- **Input validation:** Validate every parameter received from the ARM9 before using it on the ARM11, and vice versa.
- **Do not share keys:** Never place console keys or cryptographic material in PXI buffers unencrypted.

---

## 6. Hardware and MMIO Access

### 6.1 Memory Maps (Reference)

| Region | Use | Access |
|--------|-----|--------|
| 0x1FF00000 | ARM11 kernel (arm11.bin) | ARM11 EL1 only |
| 0x08006800 | ARM9 kernel (arm9.bin) | ARM9 EL1 only |
| 0x1F000000-0x1F5FFFFF | StaticMapping (e.g. ns module) | ARM11 (see exheader) |
| FCRAM | Main application memory | ARM11 EL0/EL1 |
| AXI WRAM | ARM9 working memory | Mainly ARM9 |

> `[TO BE VERIFIED]` The exact MMIO addresses of peripherals (PMIC, PICA GPU, SD controller, etc.) require further analysis of `arm11.bin` and `arm9.bin`.

### 6.2 Reading/Writing MMIO Registers

```c
/* MMIO register read (volatile, no optimisation) */
static inline uint32_t mmio_read(uint32_t addr) {
    return *(volatile uint32_t*)addr;
}

/* MMIO register write */
static inline void mmio_write(uint32_t addr, uint32_t val) {
    *(volatile uint32_t*)addr = val;
    __asm__ volatile ("dsb" ::: "memory");  /* Memory barrier */
}

/* Example: write to a hypothetical register at 0x10140000 */
#define REG_PMU_CTRL 0x10140000  /* EXAMPLE - verify the real address */
mmio_write(REG_PMU_CTRL, 0x1);
```

> `[WARNING]` The MMIO addresses in this manual are EXAMPLES. Using incorrect addresses can cause memory corruption or a hard brick.

---

## 7. File Systems and Storage

### 7.1 NAND Partitions

| Partition | Use | Access |
|-----------|-----|--------|
| FIRM | ARM9 + ARM11 firmware | ARM9 only during boot |
| SecureZone | Keys, seeds, secure data | ARM9 only |
| SD/MMC | Titles, saves, content | ARM9 (secure mode) + ARM11 (through a sysmodule) |

### 7.2 Requirements for Storage Drivers

- **Validate signatures:** Every block written to NAND must have a valid checksum/signature.
- **Atomic writes:** Use double buffering or minimal journaling to avoid corruption on abrupt power-off.
- **Do not cache keys:** Never store console keys in a write cache unencrypted.
- **ARM9 for SecureZone:** ARM11 drivers cannot access SecureZone directly; they must go through PXI.

---

## 8. Optimisation and Governors (Extreme Performance)

### 8.1 PMU-based CPU Governor

A governor can read the PMU CCNT to decide frequency changes (DVFS):

```c
struct governor_config {
    uint32_t target_freq_khz;
    uint32_t min_freq_khz;
    uint32_t max_freq_khz;
    uint32_t up_threshold_pct;
    uint32_t down_threshold_pct;
    uint32_t sampling_interval_ms;
};

void governor_run(struct governor_config* cfg) {
    uint32_t ccnt_before = arm11_pmu_read_ccnt();
    /* ... wait sampling_interval ... */
    uint32_t ccnt_after = arm11_pmu_read_ccnt();
    uint32_t cycles = ccnt_after - ccnt_before;
    /* Compute usage and adjust frequency through the PMIC (PXI to ARM9) */
}
```

### 8.2 Enabling/Disabling MPCore Cores

The ARM11 MPCore has multiple cores (2 on old3DS, 4 on new3DS). A driver that manages cores must:

1. Synchronise with the kernel11 scheduler before powering down a core.
2. Verify the core is idle before clock gating.
3. Use cache/memory barriers (`dmb`, `dsb`) for inter-core coherence.
4. Never power down the core that is running the driver itself.

---

## 9. Hardening Checklist for Critical Drivers

Before deploying any driver on real hardware:

- [ ] Full NAND backup + `movable.sed` + `otp.bin` + `seeds`
- [ ] Driver tested in an emulator (Citra) or on a NAND dump on a PC
- [ ] All userland pointers validated before dereferencing in the kernel
- [ ] Size limits verified in all reads/writes
- [ ] CP15/PMU access restricted to kernel mode, mediated by SVC
- [ ] Memory barriers (`dmb`/`dsb`) on PXI shared buffers
- [ ] Cache clean/invalidate on buffers shared with the ARM9
- [ ] Spinlocks/semaphores protecting structures shared between MPCore cores
- [ ] Timeouts on all PXI communications with the ARM9
- [ ] Signature/checksum validation before writing to NAND/FIRM
- [ ] Recovery method available (hardmod / NAND programmer / spare console)
- [ ] MMIO addresses verified against the decrypted `arm11.bin`/`arm9.bin`
- [ ] SVC numbers verified against the kernel11 syscall table

---

## 10. Tool Commands for Analysis and Development

### 10.1 Decrypt FIRM and extract kernels

```bash
# Decrypt the FIRM title as NCCH
ctrtool -v --intype=ncch --exheader=exh.bin --exefs=exefs.bin title_firm.cxi

# Extract the .firm section from the ExeFS
ctrtool -v --exefsdir=exefs_dir title_firm.cxi

# Split FIRM into sections (arm9.bin, arm11.bin)
ctrtool -v --intype=firm --firmdir=firm_out --firmtype=nand exefs_dir/firm.bin
```

### 10.2 Analyze the kernel with radare2

```bash
# Real ARM11 Kernel11 (arm11_section1.bin, runtime base 0xFFF00000)
r2 -a arm -b 32 -m 0xFFF00000 -A decrypted_binaries/kernel/arm11_section1.bin
# Inside r2:
#   afl                        ; list 415 functions
#   pd 100 @ 0xFFF0220C        ; disassemble the SVC dispatcher
#   pd 100 @ 0x1FFAE034        ; entry point (with -m 0x1FF80000)

# ARM9 (base 0x08006800)
r2 -a arm -b 32 -B 0x08006800 -A decrypted_binaries/kernel/arm9.bin
# Inside r2:
#   afl                        ; list functions
#   pd 100 @ 0x0801B01C        ; disassemble the entry point
#   pd 100 @ 0x08007878        ; disassemble the SWI dispatcher
```

### 10.3 Load symbols in radare2

```bash
# ARM11 Kernel11 (verified names + SVC/PMU)
r2 -a arm -b 32 -m 0xFFF00000 -i decrypted_binaries/kernel/symbols_arm11_kernel11_friendly.r2 decrypted_binaries/kernel/arm11_section1.bin

# ARM9 (verified Kernel9 + Process9 names)
r2 -a arm -b 32 -B 0x08006800 -i decrypted_binaries/kernel/symbols_arm9_friendly.r2 decrypted_binaries/kernel/arm9.bin
```

### 10.4 Load symbols in Ghidra

1. New project → Import `arm11_section1.bin` (`0xFFF00000`) or `arm9.bin` (`0x08006800`)
2. **Language:** `ARM:LE:32:v6k` (ARM11) / `ARM:LE:32:v5te` (ARM9)
3. **Image base:** `0xFFF00000` (Kernel11 runtime) / `0x08006800` (ARM9)
4. Run script: `symbols_arm11_kernel11_friendly_ghidra.py` / `symbols_arm9_friendly_ghidra.py`

---

## 11. References and Repository Files

| File | Contents |
|------|----------|
| `KERNEL_ANALYSIS.md` | Full ARM11/ARM9 kernel analysis (SVCs, vectors, PMU, PXI) |
| `KERNEL_SYMBOLS.md` | Symbol table and separate symbol files for the raw binary |
| `RECREATED_SYMBOLS.md` | Complete table of the 58 SysModules + 5 FIRM modules |
| `ARCH_ARM11_vs_ARM9.md` | ARM11 vs ARM9 architecture and kernel flow |
| `CRITICAL_DRIVERS_GUIDE.md` | Design and hardening guide (earlier version) |
| `PXI_PROTOCOL.md` | Verified PXI protocol |
| `README.md` | Main repository README |
| `decrypted_binaries/kernel/arm11_section1.bin` | Real ARM11 kernel (204,800 B) |
| `decrypted_binaries/kernel/arm11.bin` | FIRM Section 0 with 5 NCCHs (`fs`, `loader`, `pm`, `sm`, `pxi`) |
| `decrypted_binaries/kernel/arm9.bin` | Decrypted ARM9 kernel + Process9 (541,184 B) |

---

## 12. Evidence Summary Table

| Item | State | Location |
|------|-------|----------|
| Kernels `arm11_section1.bin` / `arm9.bin` / `arm11.bin` decrypted | `[VERIFIED]` | `decrypted_binaries/kernel/` |
| 654 Kernel11 C functions (**838** total: **287** `CONFIRMED`, **551** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) / 2,673 ARM9 C functions (**4,849** total: **311** `CONFIRMED`, **4,538** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `[VERIFIED]` | `arm11_kernel11_friendly.sym`, `arm9_friendly.sym`, `pseudocode_k11/`, `pseudocode_arm9/` |
| Entry points `0x1FFAE034` (ARM11) and `0x0801B01C` (ARM9) | `[VERIFIED]` | `firm.bin` header |
| Kernel11 109-SVC table (`0xFFF02328`) and dispatcher (`0xFFF0220C`) | `[VERIFIED]` | `KERNEL_ANALYSIS.md` §3 |
| Kernel9 40-SWI table (`0x08007938`) and dispatcher (`0x08007878`) | `[VERIFIED]` | `KERNEL_ANALYSIS.md` §4 |
| ARM11 (`0x1FFAD000`/`0xFFFF0000`) and ARM9 (`0x0800E7E0`) exception vectors | `[VERIFIED]` | `KERNEL_ANALYSIS.md` §2 |
| PMU CP15 `c15, c12, 0..3` + `SVC 0x3E` (`0xFFF03664`) | `[VERIFIED]` | `KERNEL_ANALYSIS.md` §5 |
| PXI registers `0x1EC63000` (`0x10163000`), IRQs `80..83` and ARM9 `0x10008000` | `[VERIFIED]` | `KERNEL_ANALYSIS.md` §6 |
| 58 SysModules + 5 FIRM modules (functions and SVCs) | `[VERIFIED]` | `RECREATED_SYMBOLS.md` §6 |
| NAND backup warning | `[VERIFIED]` | Top of this manual |
