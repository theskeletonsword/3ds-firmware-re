# Complete Analysis of the ARM11 and ARM9 Kernels — Nintendo 3DS (EL1)

> **Status:** `[VERIFIED IN THIS REPO]` — The kernels were decrypted from the FIRM title (`extracted/FIRM_0004013800000002/raw/content.0000.0000006c`, `firm.bin`) into `decrypted_binaries/kernel/` using `ctrtool` + `aes_keys.txt` + `movable.sed`.
>
> **Evidence rules:**
> - `[VERIFIED]`: checked directly in `firm.bin`, `arm11_section1.bin`, `arm11.bin`, `arm9.bin` and the 58+5 decrypted SysModules.
> - `[PUBLIC 3DS KNOWLEDGE]`: standard 3dbrew symbolic names correlated with the binary evidence.
> - `[HYPOTHESIS]`: inference pending validation on real hardware.
>
> **New 3DS:** the N3DS equivalents (different FIRM layout, arm9loader + K9L2-encrypted ARM9) are documented in `../n3ds/docs/`.

---

## 1. Real FIRM structure (`firm.bin`) and kernels `[VERIFIED]`

Inspecting the FIRM header (`decrypted_binaries/kernel/exefs_dir/firm.bin`, magic `FIRM`), **3 sections** were verified:

| FIRM section | File | FIRM base (load) | Runtime base (MMU) | Entry point | Size | Real contents `[VERIFIED]` |
|--------------|------|------------------|--------------------|-------------|------|----------------------------|
| **Section 0** | `arm11.bin` (`separated/firm_0_1ff00000.bin`) | `0x1FF00000` | N/A (5 NCCHs) | — | 218,624 B (`0x35600`) | **5 SysModules embedded in FIRM** (NCCH containers): `fs` (`0x00000`), `loader` (`0x26600`), `pm` (`0x29A00`), `sm` (`0x2E800`), `pxi` (`0x32200`) |
| **Section 1** | `arm11_section1.bin` (`separated/firm_1_1ff80000.bin`) | `0x1FF80000` | `0xFFF00000` (vectors at `0xFFFF0000`) | **`0x1FFAE034`** | 204,800 B (`0x32000`) | **Real Kernel11** (ARMv6K MPCore): SVC dispatcher, 109-SVC table, vectors, GIC, CP15 PMU `c15,c12`, `K*` objects |
| **Section 2** | `arm9.bin` (`separated/firm_2_08006800.bin`) | `0x08006800` | Kernel9 `0x08006800` + Process9 `0x08028000` | **`0x0801B01C`** | 541,184 B (`0x84200`) | **Kernel9** (`0x08006800..0x0801C2FF`) + **Process9 NCCH** (file off `0x15B00`, `.code` `0x16700` → VA `0x08028000`) |

> **Critical correction with respect to earlier notes:**
> 1. The FIRM header entry point for ARM11 is **`0x1FFAE034`** (in `arm11_section1.bin`, offset `0x2E034`), not `0x1FF0AE034`.
> 2. `arm11.bin` (`0x1FF00000`) is not monolithic kernel code but the package of 5 system NCCHs (`fs`, `loader`, `pm`, `sm`, `pxi`). The real ARM11 kernel lives in **`arm11_section1.bin`** (`0x1FF80000` → `0xFFF00000`), where radare2 detects **415 functions** (540 total symbols including SVC table entries).
> 3. The earlier analysis of `arm9.bin` had labelled data of the `K*` RTTI table (`0x08018F64`: `0xFFFF8001`) as `SWI 0xFF8001` instructions. In reality, the Kernel9 SWI dispatcher is at `0x08007878` with its pointer table at `0x08007938`.

---

## 2. Verified exception vectors (ARM11 and ARM9) `[VERIFIED]`

### 2.1 ARM11 Kernel11 (`arm11_section1.bin`: `0x1FFAD000` → mapped at `0xFFFF0000`)

The vector page at `0x1FFAD000` (offset `0x2D000`) contains relative jumps to the code mapped at `0xFFF00000`:

| Vector | Offset / runtime VA | Instruction in table | Trampoline (`0xFFF0xxxx`) | Main handler (`0xFFF0xxxx` / Sec1 VA) | Verified behaviour |
|--------|---------------------|----------------------|---------------------------|----------------------------------------|--------------------|
| **Reset** | `0xFFFF0000` (`0x1FFAD000`) | `b 0xFFFF0058` | — | `0xFFFF0058` (`0x1FFAD058`) | `wfe; b .` (wait loop) |
| **Undefined** | `0xFFFF0004` (`0x1FFAD004`) | `b 0xFFF005FC` | `clrex; ldr pc, [0xFFF00604]` | **`0xFFF02520`** (`0x1FF82520`) | If User-mode ARM + VFP coprocessor instruction, performs a lazy VFP switch (`vmrs lr, fpexc`, `bl 0xFFFF05C0`) |
| **SVC** | `0xFFFF0008` (`0x1FFAD008`) | `b 0xFFF00608` | `clrex; ldr pc, [0xFFF00610]` | **`0xFFF0220C`** (`0x1FF8220C`) | **Kernel11 SVC Dispatcher** (see §3) |
| **Prefetch Abort** | `0xFFFF000C` (`0x1FFAD00C`) | `b 0xFFF00614` | `clrex; ldr pc, [0xFFF0061C]` | **`0xFFF02084`** (`0x1FF82084`) | `sub lr, lr, 4`; User mode (`0x10`) → `0xFFF144AC`; kernel → `0xFFF03508` |
| **Data Abort** | `0xFFFF0010` (`0x1FFAD010`) | `b 0xFFF00620` | `clrex; ldr pc, [0xFFF00628]` | **`0xFFF020CC`** (`0x1FF820CC`) | `sub lr, lr, 8`; includes the safe fixup range of kernel copies `[0xFFF15144, 0xFFF1532C)` |
| **Reserved** | `0xFFFF0014` (`0x1FFAD014`) | `b 0xFFFF0014` | — | — | Infinite loop |
| **IRQ** | `0xFFFF0018` (`0x1FFAD018`) | `b 0xFFF0062C` | `clrex; ldr pc, [0xFFF00634]` | **`0xFFF02144`** (`0x1FF82144`) | Saves context, switches to SVC, calls the GIC dispatcher `0xFFF06450` |
| **FIQ** | `0xFFFF001C` (`0x1FFAD01C`) | `b 0xFFF005D0` | — | **`0xFFF005D0`** (`0x1FF805D0`) | Sets bit 1 at `0xFFFCA104`, writes `0x3000F` to `0xFFFEFF00`, `subs pc, lr, 4` |

### 2.2 ARM9 Kernel9 (`arm9.bin`: `0x0800E7E0`, copied to `0x08000000` / `0xFFFF0000`)

Referenced in the literal pool of `arm9_entry` (`0x0801B108` = `0x0800E7E0`) and set up in ITCM `0x08000000` from `0x08007B5C`:

| Vector | Table address (`0x0800E7E0+`) | Literal pointer | Verified handler | Verified behaviour |
|--------|-------------------------------|-----------------|------------------|--------------------|
| **Reset** | `0x0800E7E0` (`b 0x0800E800`) | `0x0800E804` | `0x0800E800` | `ldr pc, [0x0800E804]` loop |
| **Undefined** | `0x0800E7E4` (`b 0x0800E808`) | `0x0800E80C` | **`0x08007B58`** | `bkpt 2` (and stub at `0x08007B5C` that writes vectors at `0x08000000`) |
| **SWI** | `0x0800E7E8` (`b 0x0800E810`) | `0x0800E814` | **`0x08007878`** | **Kernel9 SWI Dispatcher** (table at `0x08007938`) |
| **Prefetch Abort** | `0x0800E7EC` (`b 0x0800E818`) | `0x0800E81C` | **`0x08007700`** | `bkpt 3` |
| **Data Abort** | `0x0800E7F0` (`b 0x0800E820`) | `0x0800E824` | **`0x080076FC`** | `bkpt 4` |
| **Reserved** | `0x0800E7F4` | — | `0x0800E7F4` | Infinite loop `b .` |
| **IRQ** | `0x0800E7F8` (`b 0x0800E828`) | `0x0800E82C` | **`0x08007704`** | Saves state on the SVC stack and calls `0x08012248` |
| **FIQ** | `0x0800E7FC` | — | `0x0800E7FC` | `subs pc, lr, 4` |

---

## 3. SVC dispatcher and complete Kernel11 syscall table `[VERIFIED]`

### 3.1 SVC dispatcher flow (`0xFFF0220C` / Sec1 `0x1FF8220C`)

1. `srsdb sp!, 0x13` and `stmdb sp, {r8..lr} ^` save the user state.
2. Reads `spsr`; if Thumb (`0x20`), loads `ldrh r9, [lr, -2]`; if ARM, loads `ldr r9, [lr, -4]`; applies `and r9, r9, 0xff`.
3. Checks `cmp r9, 0x80`: if `>= 0x80`, jumps to `0xFFF02238` → `bl 0xFFF04DE4` (denied/invalid).
4. Points to the base table with `add r8, pc, 0xf8` → **`0xFFF02328`** (`126` useful slots `0x00..0x7D`; `0x7E` coincides with `0xFFF02520`, the Undef handler).
5. Checks the **process syscall permission bitmap** at `[sp + 0x20 + (svc >> 3)]` bit `svc & 7`; if not allowed, jumps to `0xFFF04DE4`.
6. Enables IRQ (`cpsie i`), calls `blx r8` (`table[svc]`), disables IRQ (`cpsid i`).
7. If the reschedule flag `[sp + 0x30]` is set, calls `0xFFF0401C`, restores registers and executes `rfeia sp!`.

### 3.2 Kernel11 SVC table (`0xFFF02328`) — 109 active entries

> **Evidence note:** The *Runtime VA*, *Sec1 VA* and *Binary evidence* columns are `[VERIFIED]` directly in `arm11_section1.bin` and in the 58+5 SysModules. The *Name (3dbrew)* column is `[PUBLIC 3DS KNOWLEDGE]` correlated with the calling modules and the handler behaviour. Module names in "e.g." lists are real ExHeader names.

| SVC # | Runtime VA (`0xFFF0xxxx`) | Sec1 VA (`0x1FF8xxxx`) | Name (3dbrew) `[PUBLIC 3DS KNOWLEDGE]` | Binary evidence `[VERIFIED]` |
|-------|-----------------------------|--------------------------|------------------------------------------------|------------------------------------|
| `0x01` | `0xFFF03640` | `0x1FF83640` | ControlMemory | Used by 46 modules (e.g. am, camera, codec, gsp) |
| `0x02` | `0xFFF03AB4` | `0x1FF83AB4` | QueryMemory | Used by 26 modules (e.g. am, camera, cfg, dsp) |
| `0x03` | `0xFFF043F0` | `0x1FF843F0` | ExitProcess | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x04` | `0xFFF05E98` | `0x1FF85E98` | GetProcessAffinityMask | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x05` | `0xFFF05F3C` | `0x1FF85F3C` | SetProcessAffinityMask | Used by 1 module (e.g. FIRM:pm) |
| `0x06` | `0xFFF0390C` | `0x1FF8390C` | GetProcessIdealProcessor | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x07` | `0xFFF06000` | `0x1FF86000` | SetProcessIdealProcessor | Used by 1 module (e.g. FIRM:pm) |
| `0x08` | `0xFFF037F4` | `0x1FF837F4` | CreateThread | Used by 51 modules (e.g. am, camera, codec, dsp) |
| `0x09` | `0xFFF042CC` | `0x1FF842CC` | ExitThread | Used by 51 modules (e.g. am, camera, codec, dsp) |
| `0x0A` | `0xFFF044E4` | `0x1FF844E4` | SleepThread | Used by 62 modules (e.g. am, camera, cfg, codec) |
| `0x0B` | `0xFFF03A14` | `0x1FF83A14` | GetThreadPriority | Used by 3 modules (e.g. socket, FIRM:fs) |
| `0x0C` | `0xFFF0539C` | `0x1FF8539C` | SetThreadPriority | Used by 7 modules (e.g. gsp, mp, friends, boss) |
| `0x0D` | `0xFFF05C00` | `0x1FF85C00` | GetThreadAffinityMask | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x0E` | `0xFFF05E10` | `0x1FF85E10` | SetThreadAffinityMask | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x0F` | `0xFFF039BC` | `0x1FF839BC` | GetThreadIdealProcessor | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x10` | `0xFFF05FF4` | `0x1FF85FF4` | SetThreadIdealProcessor | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x11` | `0xFFF06058` | `0x1FF86058` | GetCurrentProcessorNumber | `mrc p15, 0, r0, c0, c0, 5; and r0, r0, 3` |
| `0x12` | `0xFFF03BD4` | `0x1FF83BD4` | Run | Used by 1 module (e.g. FIRM:pm) |
| `0x13` | `0xFFF03720` | `0x1FF83720` | CreateMutex | Used by 25 modules (e.g. am, hid, spi, ac) |
| `0x14` | `0xFFF04528` | `0x1FF84528` | ReleaseMutex | Used by 13 modules (e.g. camera, ac, cecd, csnd) |
| `0x15` | `0xFFF03798` | `0x1FF83798` | CreateSemaphore | Used by 5 modules (e.g. http, ndm, ssl, FIRM:sm) |
| `0x16` | `0xFFF03B14` | `0x1FF83B14` | ReleaseSemaphore | Used by 5 modules (e.g. http, ndm, ssl, FIRM:sm) |
| `0x17` | `0xFFF036E4` | `0x1FF836E4` | CreateEvent | Used by 45 modules (e.g. camera, codec, dsp, gsp) |
| `0x18` | `0xFFF0440C` | `0x1FF8440C` | SignalEvent | Used by 43 modules (e.g. camera, codec, dsp, gsp) |
| `0x19` | `0xFFF0411C` | `0x1FF8411C` | ClearEvent | Used by 36 modules (e.g. camera, codec, dsp, gsp) |
| `0x1A` | `0xFFF03818` | `0x1FF83818` | CreateTimer | Used by 20 modules (e.g. codec, hid, mic, ptm) |
| `0x1B` | `0xFFF03C00` | `0x1FF83C00` | SetTimer | Used by 20 modules (e.g. codec, hid, mic, ptm) |
| `0x1C` | `0xFFF042E8` | `0x1FF842E8` | CancelTimer | Used by 14 modules (e.g. hid, ptm, ac, csnd) |
| `0x1D` | `0xFFF041F4` | `0x1FF841F4` | ClearTimer | Used by 5 modules (e.g. mp, boss, ns) |
| `0x1E` | `0xFFF03700` | `0x1FF83700` | CreateMemoryBlock | Used by 27 modules (e.g. gsp, hid, ac, csnd) |
| `0x1F` | `0xFFF0486C` | `0x1FF8486C` | MapMemoryBlock | Used by 25 modules (e.g. camera, gsp, hid, mic) |
| `0x20` | `0xFFF04F14` | `0x1FF84F14` | UnmapMemoryBlock | Used by 34 modules (e.g. camera, gsp, hid, mic) |
| `0x21` | `0xFFF036A8` | `0x1FF836A8` | CreateAddressArbiter | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x22` | `0xFFF03608` | `0x1FF83608` | ArbitrateAddress | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x23` | `0xFFF043C0` | `0x1FF843C0` | CloseHandle | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x24` | `0xFFF059B0` | `0x1FF859B0` | WaitSynchronization1 | Used by 39 modules (e.g. am, camera, cfg, codec) |
| `0x25` | `0xFFF03C6C` | `0x1FF83C6C` | WaitSynchronizationN | Used by 47 modules (e.g. am, camera, codec, dsp) |
| `0x26` | `0xFFF03C1C` | `0x1FF83C1C` | SignalAndWait | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x27` | `0xFFF03850` | `0x1FF83850` | DuplicateHandle | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x28` | `0xFFF04850` | `0x1FF84850` | GetSystemTick | Used by 46 modules (e.g. am, camera, cfg, gsp) |
| `0x29` | `0xFFF038B4` | `0x1FF838B4` | GetHandleInfo | Used by 1 module (e.g. dlp) |
| `0x2A` | `0xFFF03980` | `0x1FF83980` | GetSystemInfo | Used by 2 modules (e.g. FIRM:sm, FIRM:pm) |
| `0x2B` | `0xFFF03928` | `0x1FF83928` | GetProcessInfo | Used by 39 modules (e.g. am, camera, cfg, codec) |
| `0x2C` | `0xFFF039D8` | `0x1FF839D8` | GetThreadInfo | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x2D` | `0xFFF03624` | `0x1FF83624` | ConnectToPort | Used by 62 modules (e.g. am, camera, cfg, codec) |
| `0x2E` | `0xFFF04E6C` | `0x1FF84E6C` | SendSyncRequest1 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x2F` | `0xFFF04E78` | `0x1FF84E78` | SendSyncRequest2 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x30` | `0xFFF04E84` | `0x1FF84E84` | SendSyncRequest3 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x31` | `0xFFF04E90` | `0x1FF84E90` | SendSyncRequest4 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x32` | `0xFFF04B78` | `0x1FF84B78` | SendSyncRequest | Used by 62 modules (e.g. am, camera, cfg, codec) |
| `0x33` | `0xFFF03A4C` | `0x1FF83A4C` | OpenProcess | Used by 1 module (e.g. FIRM:pm) |
| `0x34` | `0xFFF03A68` | `0x1FF83A68` | OpenThread | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x35` | `0xFFF038D4` | `0x1FF838D4` | GetProcessId | Used by 60 modules (e.g. am, camera, cfg, codec) |
| `0x36` | `0xFFF038F0` | `0x1FF838F0` | GetProcessIdOfThread | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x37` | `0xFFF039A0` | `0x1FF839A0` | GetThreadId | Used by 13 modules (e.g. am, dsp, gsp, http) |
| `0x38` | `0xFFF03964` | `0x1FF83964` | GetResourceLimit | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x39` | `0xFFF06090` | `0x1FF86090` | GetResourceLimitLimitValues | Used by 1 module (e.g. FIRM:pm) |
| `0x3A` | `0xFFF06224` | `0x1FF86224` | GetResourceLimitCurrentValues | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x3B` | `0xFFF04E54` | `0x1FF84E54` | GetThreadContext | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x3C` | `0xFFF06340` | `0x1FF86340` | Break | Checks `r0 <= 4`, flag `0xFFF2E00A`, err `0xD8E007ED` |
| `0x3D` | `0xFFF05178` | `0x1FF85178` | OutputDebugString | Validates user string range, err `0xE0E01FFD` |
| `0x3E` | `0xFFF03664` | `0x1FF83664` | ControlPerformanceCounter | Calls `0xFFF0AC44` (PMU CP15 `c15, c12, 0..3`) |
| `0x47` | `0xFFF0373C` | `0x1FF8373C` | CreatePort | Used by 3 modules (e.g. am, FIRM:sm) |
| `0x48` | `0xFFF037D8` | `0x1FF837D8` | CreateSessionToPort | Used by 3 modules (e.g. am, FIRM:sm) |
| `0x49` | `0xFFF037B4` | `0x1FF837B4` | CreateSession | Used by 1 module (e.g. FIRM:fs) |
| `0x4A` | `0xFFF035EC` | `0x1FF835EC` | AcceptSession | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x4B` | `0xFFF03B4C` | `0x1FF83B4C` | ReplyAndReceive1 | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x4C` | `0xFFF03B68` | `0x1FF83B68` | ReplyAndReceive2 | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x4D` | `0xFFF03B84` | `0x1FF83B84` | ReplyAndReceive3 | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x4E` | `0xFFF03BA0` | `0x1FF83BA0` | ReplyAndReceive4 | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x4F` | `0xFFF03B30` | `0x1FF83B30` | ReplyAndReceive | Used by 63 modules (e.g. am, camera, cfg, codec) |
| `0x50` | `0xFFF0460C` | `0x1FF8460C` | BindInterrupt | Calls `0xFFF0D544` (IRQ bind/unbind helper) |
| `0x51` | `0xFFF04C78` | `0x1FF84C78` | UnbindInterrupt | Calls `0xFFF0D544` (IRQ bind/unbind helper) |
| `0x52` | `0xFFF06064` | `0x1FF86064` | InvalidateProcessDataCache | Calls `0xFFF0AE48` (process D-cache helper) |
| `0x53` | `0xFFF05E1C` | `0x1FF85E1C` | StoreProcessDataCache | Calls `0xFFF0AE48` (process D-cache helper) |
| `0x54` | `0xFFF05AE0` | `0x1FF85AE0` | FlushProcessDataCache | Calls `0xFFF0AE48` (process D-cache helper) |
| `0x55` | `0xFFF03C44` | `0x1FF83C44` | StartInterProcessDma | Used by 8 modules (e.g. camera, gsp, nwm, ns) |
| `0x56` | `0xFFF0402C` | `0x1FF8402C` | StopDma | Used by 8 modules (e.g. camera, gsp, nwm, ns) |
| `0x57` | `0xFFF03898` | `0x1FF83898` | GetDmaState | Used by 4 modules (e.g. camera, nwm, FIRM:fs) |
| `0x58` | `0xFFF03BBC` | `0x1FF83BBC` | RestartDma | Used by 1 module (e.g. nwm) |
| `0x59` | `0xFFF05AD0` | `0x1FF85AD0` | SetGpuProt | Used by 1 module (e.g. gsp) |
| `0x5A` | `0xFFF0485C` | `0x1FF8485C` | SetWifiEnabled | Used by 1 module (e.g. nwm) |
| `0x60` | `0xFFF03834` | `0x1FF83834` | DebugActiveProcess | Used by 1 module (e.g. FIRM:pm) |
| `0x61` | `0xFFF050E4` | `0x1FF850E4` | BreakDebugProcess | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x62` | `0xFFF05E48` | `0x1FF85E48` | TerminateDebugProcess | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x63` | `0xFFF05718` | `0x1FF85718` | GetProcessDebugEvent | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x64` | `0xFFF05464` | `0x1FF85464` | ContinueDebugEvent | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x65` | `0xFFF03948` | `0x1FF83948` | GetProcessList | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x66` | `0xFFF039F8` | `0x1FF839F8` | GetThreadList | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x67` | `0xFFF05B0C` | `0x1FF85B0C` | GetDebugThreadContext | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x68` | `0xFFF05CC0` | `0x1FF85CC0` | SetDebugThreadContext | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x69` | `0xFFF03A84` | `0x1FF83A84` | QueryDebugProcessMemory | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x6A` | `0xFFF0529C` | `0x1FF8529C` | ReadProcessMemory | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x6B` | `0xFFF05508` | `0x1FF85508` | WriteProcessMemory | Calls `0xFFF14864` (debug, err `0xD9002002`) |
| `0x6C` | `0xFFF05DAC` | `0x1FF85DAC` | SetHardwareBreakPoint | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x6D` | `0xFFF0386C` | `0x1FF8386C` | GetDebugThreadParam | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x70` | `0xFFF0368C` | `0x1FF8368C` | ControlProcessMemory | Used by 1 module (e.g. ro) |
| `0x71` | `0xFFF04A08` | `0x1FF84A08` | MapProcessMemory | Used by 1 module (e.g. ro) |
| `0x72` | `0xFFF05030` | `0x1FF85030` | UnmapProcessMemory | Used by 1 module (e.g. ro) |
| `0x73` | `0xFFF036C4` | `0x1FF836C4` | CreateCodeSet | Used by 1 module (e.g. FIRM:loader) |
| `0x74` | `0xFFF03A30` | `0x1FF83A30` | — (kernel table only) | In table `0xFFF02328` (kernel only / unused by SysModules) |
| `0x75` | `0xFFF03760` | `0x1FF83760` | CreateProcess | Used by 1 module (e.g. FIRM:loader) |
| `0x76` | `0xFFF04E9C` | `0x1FF84E9C` | TerminateProcess | Used by 1 module (e.g. FIRM:pm) |
| `0x77` | `0xFFF055F8` | `0x1FF855F8` | SetProcessResourceLimits | Used by 1 module (e.g. FIRM:pm) |
| `0x78` | `0xFFF0377C` | `0x1FF8377C` | CreateResourceLimit | Used by 1 module (e.g. FIRM:pm) |
| `0x79` | `0xFFF061AC` | `0x1FF861AC` | — (used by FIRM:pm) | Used by 1 module (e.g. FIRM:pm) |
| `0x7A` | `0xFFF04E60` | `0x1FF84E60` | — (stub 0xF8C007F4) | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x7C` | `0xFFF15980` | `0x1FF95980` | KernelSetState | 10-case switch (0..9), writes `0xFFFEFF00` |
| `0x7D` | `0xFFF03AE4` | `0x1FF83AE4` | — (used by ro) | Used by 1 module (e.g. ro) |

---

## 4. Kernel9 SWI table (`0x08007938`) and `K*` objects `[VERIFIED]`

- **ARM9 SWI dispatcher:** `0x08007878` (same permission-bitmap structure as Kernel11).
- **SWI pointer table:** `0x08007938` — contains **40 non-null entries** in `0x08..0x7C`:
  `0x08` (`0x08007C64`), `0x09` (`0x08008910`), `0x0A` (`0x08008B0C`), `0x0B` (`0x08007D58`), `0x0C` (`0x08008EA0`), `0x13` (`0x08007C2C`), `0x14` (`0x08008B50`), `0x15` (`0x08007C48`), `0x16` (`0x08007D74`), `0x17` (`0x08007C10`), `0x18` (`0x08008A34`), `0x19` (`0x08008760`), `0x1A` (`0x08007C88`), `0x1B` (`0x08007DA8`), `0x1C` (`0x0800892C`), `0x1D` (`0x08008838`), `0x21` (`0x08007BF4`), `0x22` (`0x08007BD8`), `0x23` (`0x08008A04`), `0x24` (`0x08008F64`), `0x25` (`0x08007DEC`), `0x27` (`0x08007CA4`), `0x28` (`0x08008D50`), `0x2A` (`0x08007CFC`), `0x2B` (`0x08007CDC`), `0x2C` (`0x08007D38`), `0x37` (`0x08007D1C`), `0x3C` (`0x080091FC`), `0x3D` (`0x08008E50`), `0x50` (`0x08008C30`), `0x51` (`0x08008D5C`), `0x52` (`0x08009180`), `0x53` (`0x08009104`), `0x54` (`0x08009088`), `0x55` (`0x08007DC4`), `0x56` (`0x08008670`), `0x57` (`0x08007CC0`), `0x58` (`0x08007D90`), `0x7B` (`0x08007B30`), `0x7C` (`0x0800A06C`).
- **`K*` objects in Kernel11 (`0x1FFB0910..0x1FFB09EA`):** `KDebug`, `KAddressArbiter`, `KAutoObject`, `KClientPort`, `KClientSession`, `KCodeSet`, `KDmaObject`, `KEvent`, `KMutex`, `KPort`, `KProcess`, `KResourceLimit`, `KSemaphore`, `KServerPort`, `KServerSession`, `KSession`, `KSharedMemory`, `KSynchronizationObject`, `KThread`, `KTimer`.
- **`K*` objects in Kernel9 (`0x080193E4..0x08019455`, table at `0x08018F28..0x08018F5C`):** `KAddressArbiter`, `KAutoObject`, `KCodeSet`, `KDmaObject`, `KEvent`, `KMutex`, `KProcess`, `KSemaphore`, `KSynchronizationObject`, `KThread`, `KTimer`.

---

## 5. CP15 and PMU on ARM11 (629 instructions) vs ARM9 (117 instructions) `[VERIFIED]`

### 5.1 Critical PMU finding on the ARM11 MPCore

Earlier documentation assumed the ARMv7 mapping (`c9, c12` / `c9, c13`). **Direct verification in `arm11_section1.bin`:** there are **0 accesses** to `c9, c12/c13`. The ARM11 MPCore (ARMv6K) implements its PMU in **`CP15 c15, c12, 0..3`**, and Kernel11 uses it extensively between `0xFFF11074` and `0xFFF11768` (`0x1FF91074..0x1FF91768`):

| CP15 register | CRn | CRm | Opcode2 | Count (`mrc` / `mcr`) | Example addresses (Sec1) | Verified function |
|---------------|-----|-----|---------|-----------------------|--------------------------|-------------------|
| **PMNC** (Control) | `c15` | `c12` | `0` | 9 `mrc` / 6 `mcr` | `0x1FF91074`, `0x1FF911BC`, `0x1FF9145C`, `0x1FF9165C` | Enable/reset counters and select events |
| **CCNT** (Cycle Counter) | `c15` | `c12` | `1` | 1 `mrc` / 1 `mcr` | `0x1FF91510`, `0x1FF91734` | Read/write the cycle counter |
| **PMN0** (Event Counter 0) | `c15` | `c12` | `2` | 1 `mrc` / 2 `mcr` | `0x1FF911A0`, `0x1FF91538`, `0x1FF91768` | Read/write event counter 0 |
| **PMN1** (Event Counter 1) | `c15` | `c12` | `3` | 1 `mrc` / 2 `mcr` | `0x1FF911B0`, `0x1FF9155C`, `0x1FF916BC` | Read/write event counter 1 |

**Exposure through SVC:**
- **`SVC 0x3E` (`0xFFF03664` → `0xFFF0AC44`)** exposes a 9-case dispatcher (`0..8`) to the PMU functions `0xFFF11070..0xFFF11668`, including reads of `PMN0` (`r1=0`), `PMN1` (`r1=1`) and `CCNT` (`r1=2`) at `0xFFF11498`.
- **Permission in ExHeaders:** None of the 58 SysModules nor of the 5 FIRM modules has the `0x3E` bit enabled in its ExHeader syscall bitmap `[VERIFIED]`; only processes that declare `0x3E` in their ExHeader can invoke it.

### 5.2 Other CP15 registers verified in Kernel11 (`arm11_section1.bin`)

| CP15 group | Count | Verified purpose |
|------------|-------|------------------|
| `c0, c0, 5` (`mrc`) | 59 | MPIDR — core ID (`and rX, rX, 3`), also used in `SVC 0x11` (`0xFFF06058`) |
| `c1, c0, 0..2` | 9 | SCTLR, ACTLR, CPACR (system control and VFP) |
| `c2, c0, 0..2` / `c3, c0, 0` | 12 | TTBR0, TTBR1, TTBCR, DACR (MMU page tables) |
| `c5, c0, 0..1` / `c6, c0, 0` | 6 | DFSR, IFSR, FAR (abort diagnostics at `0xFFF02084`/`0xFFF020CC`/`0xFFF184xx`) |
| `c7` (`c7, c4..c14`) | 491 | I-cache/D-cache clean/invalidate and barriers (`c7,c10,5` DMB: 371 occurrences; `c7,c10,4` DSB: 43) |
| `c8, c7, 0/2/3` | 11 | TLB invalidation |
| `c13, c0, 1/3` | 9 | CONTEXTIDR / ASID and TPIDR (user TLS `0xFFFF9000`) |

On the **ARM9 (`arm9.bin`)**, 117 CP15 instructions were verified, including `c5, c0, 3` and `c6, c2/c5/c7, 0` (`0x0800A118..0x0800A134`) to configure regions of the ARM946E-S **MPU** (Memory Protection Unit) (it does not use an MMU with TTBR).

---

## 6. Verified PXI communication (ARM11 ↔ ARM9) `[VERIFIED]`

By extracting the **`pxi`** SysModule (`0004013000001402`, embedded in `arm11.bin` at `0x32200`, code `15,180 B`), its MMIO registers, IRQs and services were verified directly (full protocol in `PXI_PROTOCOL.md`):

- **ARM11 PXI physical address:** `0x10163000`, mapped in the ExHeader by descriptor `0xFFE1EC63` to virtual address **`0x1EC63000`** (referenced in `pxi/code.bin` at `0x00101188`, `0x00101FC0`, `0x00101FDC`, `0x00101FF4`, `0x00102094`, etc.).
- **Registers verified in `pxi/code.bin`:**
  - `+0x00` (`PXI_SYNC`, 32-bit): cleared to `0` during init/reset (`0x00101158`).
  - `+0x04` (`PXI_CNT`, 16-bit `ldrh`/`strh`):
    - Bit 1 (`0x0002`, `0x00101FCC`): **SEND FIFO Full** (polling before writing `+0x08`).
    - Bit 3 (`0x0008`, `0x0010115C`): **Flush Send FIFO**; then writes `0xC008` (`0x00101180`) to enable the FIFOs.
    - Bit 8 (`0x0100`, `0x00101FB0`): **RECV FIFO Empty** (polling before reading `+0x0C`).
    - Bits `0x0004` / `0x0400` (`0x00102014..0x00102044`): TX/RX interrupt masks.
  - `+0x08` (`PXI_SEND`, 32-bit `str`): write to the TX FIFO (`0x00101FD4`).
  - `+0x0C` (`PXI_RECV`, 32-bit `ldr`): read from the RX FIFO (`0x00101FB8`, drained 8× in init `0x00101164..0x00101174`).
- **PXI IRQs in the ExHeader and `pxi/code.bin`:** `80, 81, 82, 83` (`0x50..0x53`), bound through `svcBindInterrupt` (`SVC 0x50` at `0x00102BD4`): **`0x52` (82)** for reception (`0x0010204C`) and **`0x53` (83)** for sending (`0x00102020`). *(`PXI_PROTOCOL.md` §2.1 refines the per-IRQ roles verified in `0x001021A8`.)*
- **Services registered by `pxi`:** `pxi:am9`, `pxi:dev`, `pxi:mc`, `pxi:ps9` (strings at `0x00103866..0x0010387D`).
- **ARM9 side (`arm9.bin`):** The literal **`0x10008000`** (ARM9 PXI MMIO base) is verified in Kernel9 (`0x0800A148`) and in 12 places of Process9 (`0x0801D4F0..0x0804D28C`).

---

## 7. Deep analysis with C pseudocode (REA + Ghidra 12.2) `[VERIFIED]`

Using **REA `6.10.1` + Ghidra `12.2`**, **654 functions of `arm11_section1.bin`** (`pseudocode_k11/`, 0 failures) and **2,673 functions of `arm9.bin`** (`pseudocode_arm9/`, 14 failures due to overlapping ARM/Thumb instructions) were decompiled to C.

### 7.1 Strict confidence criterion (`CONFIRMED` vs `EVIDENCE_BASED`)
- **`CONFIRMED`:** Deterministic anchoring in a hardware/format contract or 100 % self-contained semantics verified line by line in ASM/C (FIRM header, ARM vectors, the 109 SVCs at `0xFFF02328`, the 40 SWIs at `0x08007938`, C++ vtables + `destructor` + `GetTypeObj`, exact literal CP15/MMIO accesses, atomic primitives `ldrex`/`strex`/`dmb`, complete CRT/EABI routines in C, and direct XREFs to real strings).
- **`EVIDENCE_BASED`:** Membership of a subsystem/class demonstrated through C, `Result` codes, shared vtable slots or a direct callgraph without CRT contamination, but whose full contract or original source name still needs callers/structures to be cross-checked.
- **`HYPOTHESIS`: 0** (all non-code false positives were purged).

### 7.2 Verified findings in the Kernel11 C pseudocode (`arm11_section1.bin`)
- **Start-up of the embedded modules (`kernel11_launch_firm_sysmodules` @ `0xFFF00EAC`):** Directly iterates the virtual region **`[0xDFF00000..0xDFF355FC)`** (exactly `0x35600` bytes = the 5 NCCHs embedded in FIRM Section 0 `arm11.bin`), validates the ExHeader (`0xFFF025C4`), creates the `KCodeSet` and launches the initial processes (`fs`, `loader`, `pm`, `sm`, `pxi`).
- **Priority inheritance (`KMutex_acquire_and_inherit_priority` @ `0xFFF2917C` / `KMutex_release_and_restore_priority` @ `0xFFF290DC`):** They manipulate the thread's owned-mutex list (`KThread+0x60/0x64` via `0xFFF2A9C0`/`0xFFF2AA20`), walk the queue looking for the lowest priority (`< 0x3f` at `thread+0x6c`) and update the owner's dynamic priority (`0xFFF1B4BC`/`0xFFF1B56C`).
- **CDMA PL330 microcode compiler (`0xFFF2B48C` 392L, `0xFFF285D8`, `0xFFF286F8`, `0xFFF287E0`):** Dynamically emits ARM PL330 engine instructions (`0xBC` 6-byte CCR at `0xFFF285D8`, `DMALP` `0x20 | lc<<1` at `0xFFF286F8`, `DMALPEND` `0x38 | lc<<2` at `0xFFF287E0`) for 1D/2D transfers.
- **Most frequent `Result` codes in Kernel11 C:** `0xE0E01BF5` / `0xE0A01BF5` (30+11 funcs, `InvalidAddress`), `0xD8E007FD` (21 funcs, `InvalidState/Busy`), `0xD86007F3` (18 funcs, `OutOfMemory`), `0xD8E007F7` (18 funcs, `InvalidHandle`), `0xD8E007F6` (14 funcs, `InvalidEnum/Cmd`), `0xF8C007F4` (13 funcs, fatal `NotImplemented`), `0xC8601801` (8 funcs, `ResourceLimitReached`), `0xD920060D` (3 funcs, `Timeout`).

### 7.3 Verified findings in the ARM9 C pseudocode (`arm9.bin`)
- **Real separation of CRT vs subsystems:** The following were identified in C: `p9_memcpy` (`0x08056CBC`, 121 callers), `p9_memcpy32_aligned` (`0x08056B28`), `p9_memset_byte` (`0x08056014`), `p9_memzero32_aligned` (`0x08056C68`), `p9_memcmp` (`0x08056C38`), `p9_aeabi_uidivmod` (`0x08056D90`), `p9_aeabi_lmul` (`0x08055B6C`), `p9_utf16_strlen` (`0x08055AF0`), `k9_critical_section_enter/leave` (`0x080124F4`/`0x08012628`) and `k9_slab_alloc/free` (`0x080122AC`/`0x08011738`), preventing their callers from inheriting false domains.
- **Dispatch tables and interfaces in Process9 `.rodata` (`0x08083214..0x08089000`):** **252 pointer tables** were identified, including 35 tables with the common stub **`0x0807CE35`** (`a9=0x08071D34`, `movs r0, 0; push {r4, lr}; ...`) for unimplemented methods/commands and 39 tables tied to concrete subsystems (`dbs` 15 slots, `ctx` 23 slots, `quota` 14 slots, `sha` 4 slots, `aes`, `sysdata`, `spi9`, `firm`).
- **Relocatable `FIRMLaunch` payload in Process9 `.rodata` (`0x08089074..0x08089B8C`):** Although the ExHeader places `.text` at `0x08028000..0x0808E314` (`a9_va 0x0801CF00..0x08083214`) and `.rodata` at `0x0808E314..0x08094C8C` (`a9_va 0x08083214..0x08089B8C`), the stretch `0x08089074..0x08089B8C` (referenced by `0x0807A470` as runtime `0x08094174`) contains executable **Thumb + ARM32 code** that Ghidra detected (`0x080892A0..0x08089678`) and which reconfigures the MPU (`c6, c4, 0 = 0x18000035` Region 4 VRAM/RAM and Region 5) while accessing `SHA` (`0x1000A000`), `AES` (`0x10009000`) and `NDMA` (`0x10002000`).
