# (c) Design and Hardening Guide for Critical Drivers on Nintendo 3DS

> **MANDATORY WARNING — READ BEFORE ANY TEST**
>
> **ALWAYS make a full NAND backup (and of all critical recovery files: bootROM dumps, `movable.sed`, `otp.bin`, `seeds`, NAND bin, and any backup of `FIRM`/`arm9.bin`/`arm11.bin`) BEFORE testing critical drivers, modifying `FIRM` or writing to the console's storage.**
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
> 2. **Back up `movable.sed`, `otp.bin` and `seeds`** — without them nothing specific to that console can be re-signed/decrypted.
> 3. **Test drivers first in an emulator (Citra) or on a NAND dump on a PC**, never directly on hardware if an alternative exists.
> 4. **Keep a recovery method** (hardmod, NAND programmer, or a spare console with an exploitable bootROM) before writing to FIRM.
> 5. **Never write unsigned kernel code** to a boot partition without being able to revert to a known-good FIRM.
> 6. **Validate checksums and signatures** of any binary before flashing.
>
> If you do not have a NAND backup and a recovery method, **DO NOT test critical drivers or modify FIRM/storage on real hardware**.

---

## 1. Scope and threat model

This guide targets the development of **critical kernel drivers** for the Nintendo 3DS (ARM11 ARMv6K MPCore and ARM9 ARMv5TE ARM946E-S), specifically:

- PMU performance counters on ARM11 through CP15 registers.
- Access to exotic file systems (NAND partitions, SD/MMC in ARM9 secure mode, FIRM, SecureZone).
- Extreme performance optimisers / governors (DVFS, frequency scaling, enabling/disabling MPCore cores).
- Communication with the native app (userland ↔ kernel via SVC/PXI) and storage.

**Threat-model assumptions:**
- The attacker has user code (ARM11 userland) and may try to escalate privileges through SVC or PXI.
- The kernel driver runs in privileged mode (ARM11 SVC mode / ARM9 Supervisor).
- A bug in the driver can compromise the whole system (kernel panic, memory corruption, exposure of ARM9 keys).
- Storage (NAND/SD) may lose power abruptly; the driver must be robust against partial writes and corruption.

---

## 2. Architectural context (reference, to be verified against decrypted binaries)

> This section summarises the 3DS reference model. **It was not verified against the encrypted binaries of this repo** (see `00_STATUS_AND_METHODOLOGY.md`; the binaries are now decrypted and the verified values are in `ARCH_ARM11_vs_ARM9.md` and `KERNEL_ANALYSIS.md`). Validate addresses, SVC numbers and registers before writing code.

| Component | Core | Architecture | Role relevant to drivers |
|-----------|------|--------------|--------------------------|
| Application kernel | ARM11 | ARMv6K MPCore | SVC, virtual memory (FCRAM), PMU/CP15, sysmodules, PXI client |
| Security core | ARM9 | ARMv5TE ARM946E-S | Console keys, crypto, PMIC, secure SD, PXI server, secure boot |
| IPC communication | ARM11↔ARM9 | PXI | FIFO/mailbox, bidirectional IRQ, shared buffers |
| Performance counters | ARM11 | CP15 (PMU) | CCNT, PMNC, PMXEVTYPER, PMXEVCNTR, PMCEID |

---

## 3. Critical driver design — principles

### 3.1 Principle of least privilege
- A driver must run with the **minimum privilege level necessary**. If it only needs to read a PMU counter, it does not need direct access to PMIC registers or to ARM9 keys.
- Separate user logic (native app) from kernel logic: the app sends requests through SVC or PXI; the kernel validates them before acting.

### 3.2 Strict input validation (SVC / PXI)
- **Every parameter coming from userland** (pointers, sizes, handles, PXI command IDs) must be validated before use:
  - Check that pointers point to mapped user memory with the right permissions (read/write as appropriate).
  - Check sizes against maximum limits (avoid buffer overflows in the kernel).
  - Check that handles are valid and belong to the calling process.
- Use `copy_from_user` / `copy_to_user` equivalents with bounds checking; never dereference user pointers directly in kernel context without validation.

### 3.3 Safe memory management
- Page tables (ARM11 MMU) and memory attributes (AP bits, domain, XN) must be configured so the kernel does not execute data nor have writable-executable memory at the same time.
- When allocating memory for PXI shared buffers, use dedicated pages, clean/invalidate caches via CP15 (`dc clean`, `dc invalidate`, `ic invalidate`) and use memory barriers (`dmb`, `dsb`) for ARM11–ARM9 coherence.
- Never share pages containing keys, credentials or internal kernel structures with userland or with the ARM9 without encryption/bounding.

### 3.4 Concurrency and synchronisation
- The ARM11 MPCore has multiple cores. A critical driver must use kernel spinlocks or semaphores to protect shared structures.
- Disable interrupts only for the strictly necessary time; avoid long blocks with interrupts disabled.
- When accessing shared hardware registers (PMU, PMIC, PXI), use atomic access and memory barriers.

---

## 4. PMU counters on ARM11 (CP15) — specific guide

The ARM11 MPCore exposes a PMU through CP15 registers (p15). A governor or profiling driver can read them from kernel mode.

### 4.1 CP15 registers of interest (ARMv6K)

| Register | Purpose |
|----------|---------|
| `PMNC` | PMU control (enable, reset, count cycles) |
| `CCNT` | Cycle counter |
| `PMXEVTYPER` | Event type of the selected counter |
| `PMXEVCNTR` | Value of the selected event counter |
| `PMCEID0/1` | Implemented events (PMU capability) |

> **Warning:** accessing CP15 from user mode raises `Undefined Instruction`. Only kernel code (SVC mode) can read/write these registers.

### 4.2 Usage example (reference, pseudocode)

```c
/* ILLUSTRATIVE ONLY — verify exact registers in the ARM11 MPCore TRM and the decrypted binary */
static inline unsigned int pmccntr_read(void) {
    unsigned int val;
    asm volatile ("mrc p15, 0, %0, c9, c13, 0" : "=r" (val)); /* PMCCNTR */
    return val;
}

static inline void pmnc_enable(void) {
    asm volatile ("mcr p15, 0, %0, c9, c12, 0" :: "r" (1)); /* enable PMU */
}
```

### 4.3 PMU driver hardening
- The driver must **mediate access** to the PMU: userland does not read CP15 directly; it requests reads from the driver via SVC.
- Validate that the calling process is allowed to profile (capability in the ExHeader).
- Limit the read rate so as not to introduce measurable overhead or alter system behaviour (observer effect).
- Do not expose the raw cycle value as an entropy source or for key generation (it may be predictable).

---

## 5. Exotic file systems and storage

The 3DS uses NAND partitions (FIRM, SecureZone, SD/MMC) with specific formats. A critical storage driver must:

### 5.1 Principles for NAND / SecureZone / FIRM
- **Only the ARM9** should directly touch SecureZone keys and FIRM decryption. The ARM11 requests operations through PXI.
- Validate signatures and checksums of any block before writing to NAND.
- Implement atomic writes (double buffering or minimal journaling) to avoid corruption on abrupt power-off.
- Never cache keys or cryptographic material in unencrypted PXI shared memory.

### 5.2 SD/MMC in secure mode (ARM9)
- SD access for encrypted titles goes through the ARM9. An ARM11 driver that needs to read files must use the kernel11 filesystem syscalls or ask through PXI, not access the SD controller directly.
- Verify the integrity (hash) of files read before executing them or using them as configuration data.

---

## 6. Governors and extreme performance optimisers

A governor decides CPU frequencies and MPCore core states based on PMU readings (CCNT) and system load.

### 6.1 Safety requirements
- **Validate frequency and voltage limits** before programming the PMIC (through PXI to the ARM9). Out-of-range values can damage the hardware or cause instability.
- **Do not allow userland to write frequency/voltage registers directly.** Every DVFS request goes through the kernel governor, which validates it against a table of allowed frequencies.
- **Avoid changes that are too frequent** (governor throttling): set a minimum interval between readjustments so as not to saturate PXI or the PMIC.
- **Safe fallback:** on any governor error, return to safe default frequencies (no overheating, no overvoltage).

### 6.2 Enabling/disabling cores (MPCore)
- The ARM11 MPCore has secondary cores. A driver that turns them on/off must:
  - Synchronise with the kernel11 scheduler so as not to migrate threads to a core that is about to power down.
  - Verify the core is idle before clock gating.
  - Use cache and memory barriers for inter-core coherence.

---

## 7. Communication with the native app (userland) and storage

### 7.1 SVC and PXI
- Native apps invoke SVC to request services from kernel11. A critical driver exposes its functionality through a registered and validated SVC number.
- For operations that require the ARM9, the ARM11 driver sends a PXI message and waits for the reply with a timeout (avoid infinite blocking if the ARM9 does not answer).
- Implement timeouts and bounded retries in all PXI communication.

### 7.2 Storage from userland
- File access from userland uses the kernel11 filesystem syscalls (open, read, write, close). The storage driver must:
  - Validate the calling process's file permissions (read/write).
  - Sanitise paths (avoid `../` traversal outside the sandbox).
  - Limit read/write sizes so as not to exhaust kernel memory.

---

## 8. Hardening checklist before deploying on real hardware

- [ ] Full NAND backup + `movable.sed` + `otp.bin` + `seeds` + backups of `FIRM`/`arm9.bin`/`arm11.bin`.
- [ ] Driver tested in an emulator (Citra) or on a NAND dump on a PC before hardware.
- [ ] All userland pointers validated before dereferencing in the kernel.
- [ ] Size limits verified in all reads/writes.
- [ ] CP15/PMU access restricted to kernel mode, mediated by SVC.
- [ ] Memory barriers (`dmb`/`dsb`) and cache operations (clean/invalidate) on PXI shared buffers.
- [ ] Spinlocks/semaphores protecting structures shared between MPCore cores.
- [ ] Timeouts on all PXI communications with the ARM9.
- [ ] Signature/checksum validation before writing to NAND/FIRM.
- [ ] Recovery method available (hardmod / NAND programmer / spare console).
- [ ] Addresses, SVC numbers and registers verified against decrypted binaries (do not use invented values).

---

## 9. Evidence status table

| Item | State | Remark |
|------|-------|--------|
| NAND backup warning | `[VERIFIED IN THIS REPO]` | Requirement of the objective; included at the top of this guide |
| ARM11/ARM9 architecture | `[PUBLIC 3DS KNOWLEDGE]` | See `ARCH_ARM11_vs_ARM9.md`; pending verification in decrypted binaries |
| CP15/PMU registers | `[TO BE VERIFIED]` | According to the ARM11 MPCore TRM; not confirmed in this repo's `arm11.bin` (encrypted at the time of writing; later confirmed, see `KERNEL_ANALYSIS.md`) |
| SVC numbers and syscall table | `[TO BE VERIFIED]` | Pending decrypted `arm11.bin` (later obtained: see `KERNEL_ANALYSIS.md`) |
| PXI registers and MMIO addresses | `[TO BE VERIFIED]` | Pending decrypted binaries and SoC reference (later confirmed: see `ARCH_ARM11_vs_ARM9.md` §2) |
| NAND/SecureZone/FIRM formats | `[PUBLIC 3DS KNOWLEDGE]` | Pending verification in decrypted binaries |
