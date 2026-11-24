# (a) ARM11 vs ARM9 Architecture and Kernel Flow — Nintendo 3DS

> **Evidence status:** Updated with **`[VERIFIED IN THIS REPO]`** findings after decrypting `FIRM_0002` (`arm11_section1.bin`, `arm11.bin`, `arm9.bin`) and the 58 SysModules (see `KERNEL_ANALYSIS.md` and `RECREATED_SYMBOLS.md`). The general descriptive sections keep explicit `[PUBLIC 3DS KNOWLEDGE]` or `[VERIFIED]` labels.

---

## 1. Summary of the two processors

| Feature | ARM11 MPCore | ARM946E-S |
|---------|--------------|-----------|
| Architecture | ARMv6K | ARMv5TE |
| Core | MPCore (multi-core; 2 cores on old3DS, 4 on new3DS; one runs kernel/app) | Single core |
| Role in 3DS | Runs userland, application processes, sysmodules and the ARM11 kernel ("srv"/kernel11) | Security core ("firm9"/arm9.bin), secure boot, keys, cryptography, PMIC, SD/MMC |
| Typical clock | ~268 MHz (old3DS), ~804 MHz (new3DS) | ~134 MHz (old3DS) |
| Endianness | Little-endian | Little-endian |
| Execution modes | ARM + Thumb | ARM + Thumb |

### 1.1 Division of responsibilities (reference model)

- **ARM9 (firm9/arm9.bin):** boots first after the bootROM. It is the "secure core". It has direct access to the console keys (keyX/keyY), decrypts/validates the FIRM and titles, manages the PMIC, the SD card (in secure mode) and acts as the trust anchor. The ARM11 cannot read these keys directly.
- **ARM11 (arm11.bin):** application kernel. Manages processes, threads, virtual memory (FCRAM), syscalls (SVC), PXI services and the communication with the ARM9 through the PXI bus and shared memory.

> [TO BE VERIFIED] The exact split of which syscalls live in ARM9 vs ARM11 and the specific SVC numbers must be read from the decrypted `arm9.bin` and `arm11.bin`.

---

## 2. ARM11 ↔ ARM9 communication: PXI

**PXI (Processor eXchange Interface)** is the main ARM11↔ARM9 inter-processor channel.

| Item | Description |
|------|-------------|
| Nature | Register-based FIFO/mailbox, with an interrupt on each side |
| Typical use | ARM11 sends requests (cross syscalls) and the ARM9 answers; also event notifications |
| Synchronisation | Polling of status registers + IRQ; handshake to avoid overwriting pending messages |
| Shared memory | Regions agreed in the memory table (see §3) for large payloads that do not fit in the PXI registers |

### 2.1 Typical PXI flow (reference)

```
ARM11 (kernel)                    PXI bus                     ARM9 (firm9)
-------                           -------                     ---------
1. Writes command to PXI TX       ---------------->           4. Receives PXI interrupt
   register + parameters                                      5. Reads command, processes
2. Raises PXI IRQ towards ARM9    <---------------            6. Writes reply to PXI RX
3. Waits (block or callback)      ---------------->           7. Raises PXI IRQ towards ARM11
                                                <--------------- 8. ARM11 reads reply and wakes thread
```

> `[VERIFIED]` The exact PXI registers were confirmed in `FIRM:pxi` (`0004013000001402`, embedded in `arm11.bin` @ `0x32200`) and `arm9.bin`: ARM11 MMIO at `0x1EC63000` (physical `0x10163000`, offsets `+0x00` SYNC, `+0x04` CNT, `+0x08` SEND, `+0x0C` RECV), IRQs `80..83` (`0x50..0x53`), and ARM9 MMIO at `0x10008000`. See `KERNEL_ANALYSIS.md` §6.

### 2.2 Alternative: cross calls through SVC

Some ARM11→ARM9 operations are implemented as ARM11 SVCs that kernel11 translates into a PXI message to the ARM9, instead of the ARM11 calling the ARM9 directly.

> [TO BE VERIFIED] Which ARM11 SVCs are "PXI bridges" and which are resolved entirely inside kernel11.

---

## 3. Memory handling (reference map)

The 3DS has physically shared memory, but each core sees different regions with different attributes.

| Region (reference) | Typical use | Access |
|--------------------|-------------|--------|
| FCRAM | Main application memory (256 MB old3DS / 512 MB new3DS) | ARM11 (user+kernel) |
| AXI WRAM | Low-latency working memory | Mainly ARM9; shared with ARM11 in some areas |
| VRAM / PICA mem | Graphics (PICA GPU) | ARM11 (through GPU commands) |
| Secure region / keys | Console keys, seed | ARM9 only (hardware-enforced) |
| PXI shared buffers | Inter-processor payloads | ARM11 + ARM9 (manual cache-coherence agreement) |

### 3.1 Cache coherence notes

The ARM11 MPCore has per-core L1/L2 caches. When sharing memory with the ARM9 (PXI buffers), software must:
- Explicitly clean and invalidate cache lines with CP15 instructions before handing the buffer to the other core.
- Use memory barriers (`dmb`, `dsb`) to order writes.

> [TO BE VERIFIED] Exact address ranges, FCRAM size per model and kernel11 cache policy.

---

## 4. Exceptions and vectors

| Core | Vector table base (verified) | Exception mode |
|------|------------------------------|----------------|
| ARM9 | `0x0800E7E0` (copied to `0x08000000` / `0xFFFF0000`) | Reset, Undef (`0x08007B58`), SWI (`0x08007878`), Prefetch (`0x08007700`), Data (`0x080076FC`), IRQ (`0x08007704`), FIQ |
| ARM11 | `0x1FFAD000` (mapped by the MMU at `0xFFFF0000`) | Reset (`0xFFFF0058`), Undef (`0xFFF02520`), SVC (`0xFFF0220C`), Prefetch (`0xFFF02084`), Data (`0xFFF020CC`), IRQ (`0xFFF02144`), FIQ (`0xFFF005D0`) |

- **ARM9:** boots at `0x0801B01C` (`arm9_entry`), initialises the MPU (`c5/c6`), sets up the vectors and jumps to `kernel9_main` (`0x08006830`).
- **ARM11:** boots at `0x1FFAE034` (`arm11_entry`), configures per-mode stacks, the MMU (`TTBR0`/`TTBR1`) and jumps to `kernel11_main_init` (`0xFFF00030`). See `KERNEL_ANALYSIS.md` §2.

> New 3DS note: in the N3DS NATIVE_FIRM the ARM9 FIRM entry is the arm9loader at `0x0808AA3C` and the ARM11 entry is `0x1FFAF064`; see `../n3ds/docs/N3DS_VS_O3DS_FINDINGS.md`.

---

## 5. SVC and privileges

### 5.1 ARM11 (kernel11)
- User applications invoke **SVC** (number in `r0` or as an immediate, depending on the kernel11 convention) to request kernel services: thread creation, memory, PXI services, events, etc.
- The kernel validates the arguments (pointers, handles, rights) before executing.
- There are privilege levels: **user** (applications), **kernel** (kernel11 and privileged sysmodules). Some sysmodules run in kernel mode with direct access to hardware registers.

### 5.2 ARM9 (firm9)
- Has its own set of internal SVC/SWI for cryptography, key management, SD access and the PMIC.
- The ARM11 does not execute ARM9 SVCs directly; it requests them through PXI.

> [TO BE VERIFIED] SVC numbers, register conventions (what goes in r0-r3, return value in r0) and the kernel11 service table.

---

## 6. Hardware and peripheral access (reference)

| Peripheral | Main core | Notes |
|------------|-----------|-------|
| PMIC (power) | ARM9 | Power on/off, voltages; ARM11 requests through PXI |
| SD/MMC | ARM9 (secure mode) | Reading titles/FIRM; ARM11 accesses files through a sysmodule |
| Crypto (AES, RSA, SHA) | ARM9 | Console keys are not exposed to the ARM11 |
| PICA GPU | ARM11 | Render commands via DMA/command buffer |
| Keyboard / touch screen | ARM11 (through a sysmodule) | |
| PMU / performance counters | ARM11 (CP15) | See §7 |

> [TO BE VERIFIED] MMIO register maps of each peripheral; addresses are not included so as not to invent them.

---

## 7. PMU performance counters on ARM11 (CP15) — relevant for drivers/governors

The ARM11 MPCore implements its **Performance Monitoring Unit (PMU)** through **CP15 `c15, c12, 0..3`** `[VERIFIED]` in `arm11_section1.bin` (`0xFFF11074..0xFFF11768`):

| CP15 register | CRn/CRm/Opc2 | Use |
|---------------|--------------|-----|
| `PMNC` (PMN Control Register) | `c15, c12, 0` | Enable/disable counters, reset, events |
| `CCNT` (Cycle Counter) | `c15, c12, 1` | Clock cycles |
| `PMN0` (Event Counter 0) | `c15, c12, 2` | Event counter 0 |
| `PMN1` (Event Counter 1) | `c15, c12, 3` | Event counter 1 |

> `[VERIFIED]` Kernel11 exposes PMU control through **`SVC 0x3E`** (`0xFFF03664` → `0xFFF0AC44`), although none of the 58 retail SysModules nor the 5 FIRM modules has the `0x3E` bit enabled in its ExHeader. Using CP15 from user mode raises Undefined Instruction. See `KERNEL_ANALYSIS.md` §5.

---

## 8. Boot flow (high-level reference)

1. **bootROM (ARM9):** verifies the FIRM signature, decrypts `arm9.bin` (firm9) with the console keys, loads it into RAM and jumps to it.
2. **ARM9 (firm9):** initialises the PMIC and keys, validates and loads the ARM11 FIRM (`arm11.bin`) into RAM; starts the ARM11.
3. **ARM11 (arm11.bin):** initialises the MMU, vectors and kernel11, mounts the sysmodules, starts the PXI services and launches the first userland process.

> [TO BE VERIFIED] Exact sequence, load addresses and entry points of `arm9.bin`/`arm11.bin`.

---

## 9. Findings VERIFIED in a decrypted binary (this repository)

> Source: `extracted/SysModule_0004013000002102/raw/content.0000.00000005` decrypted with `ctrtool` + `aes_keys.txt`.
> Title: `0004013000002102` ("0430builder"), NCCH/CXI format. It is a user-level/application-kernel **ARM11** sysmodule (ExHeader name `pdn`).

| Finding | Verified value | Address | State |
|---------|----------------|---------|-------|
| Entry point (.code) | `0x00000000` (relative to load base) | `code.bin` offset 0 | CONFIRMED |
| Execution mode | ARM32 + Thumb (3DS GCC interworking) | whole `code.bin` | CONFIRMED |
| Endianness | Little-endian | whole `code.bin` | CONFIRMED |
| SVC instruction #1 | `svc 0x9e` (encoded `00f09eef`) | `0x0000006c` | CONFIRMED |
| SVC instruction #2 | `svc 0x76` (encoded `00f076ef`) | `0x000000bc` | CONFIRMED |
| Entry/init function | `fcn.00000000` (44 B, 2 blocks) | `0x00000000` | CONFIRMED |
| Large function (service?) | `fcn.00000164` (912 B, 37 blocks) | `0x00000164` | CONFIRMED |
| Largest function | `fcn.00001e68` (756 B, 35 blocks) | `0x00001e68` | CONFIRMED |
| ExHeader magic | `pdn\0` (`70646e00`) | `exheader.bin` 0x00 | CONFIRMED |
| Allowed syscalls (exheader) | 01,02,03,06,08,09,0A,0B,0C,0F,11,13…57 | `exheader.bin` 0x364+ | CONFIRMED |
| Arm9Capability | `none` | `exheader.bin` | CONFIRMED |

> These addresses are **relative to the start of the .code section**. To use them in the full binary, add the ExeFS load offset (see the `ctrtool` output: ExeFS offset `0x00000c00` in the NCCH).

> Total functions detected by radare2: **60** (full list in `decrypted_binaries/Module-PDN-Power-and-Clock-Domains-0004013000002102/r2_functions_clean.txt`).

### 9.1 Reproduction command example (radare2, verified)

```bash
r2 -q -a arm -b 32 -i analyze.r2 decrypted_binaries/Module-PDN-Power-and-Clock-Domains-0004013000002102/code.bin
# inside the analyze.r2 script:
#   aaa
#   afl        -> lists the 60 functions
#   pd 120 @ 0 -> disassembles the entry point
#   /ce svc    -> searches for SVC instructions (found at 0x6c and 0xbc)
```

---

## 10. Verification summary table

| Topic | State | Where to verify |
|-------|-------|-----------------|
| Binaries present are encrypted | `[VERIFIED IN THIS REPO]` | `00_STATUS_AND_METHODOLOGY.md` |
| SVCs `0x9e` and `0x76` in an ARM11 SysModule | `[VERIFIED IN THIS REPO]` | §9 + `decrypted_binaries/…` |
| 60 functions detected in an ARM11 SysModule | `[VERIFIED IN THIS REPO]` | §9 + `r2_functions_clean.txt` |
| ExHeader `pdn\0` + syscall bitmap | `[VERIFIED IN THIS REPO]` | §9 + `exheader.bin` |
| Existence of separate ARM11 + ARM9 | `[PUBLIC 3DS KNOWLEDGE]` | Re-read from decrypted `arm9.bin`/`arm11.bin` |
| PXI as the ARM11↔ARM9 channel | `[PUBLIC 3DS KNOWLEDGE]` | `arm11.bin` + PXI traces |
| Memory map (FCRAM/AXI WRAM) | `[PUBLIC 3DS KNOWLEDGE]` | Decrypted binaries + MMU |
| SVC numbers and privileges (kernel11) | `[TO BE VERIFIED]` | `arm11.bin` (SVC handler) — requires `movable.sed` |
| PMU/CP15 and governors | `[HYPOTHESIS]` | `arm11.bin` + ARM11 MPCore TRM — requires `movable.sed` |
