# PXI Protocol (ARM11 ↔ ARM9) — Verified Analysis of ARM11 (`FIRM:pxi`) and ARM9 (`Process9`)

> `[VERIFIED]` All information marked `[VERIFIED]` comes directly from static analysis (Ghidra `12.2` via REA + `radare2 5.9.8` disassembly + decoded ExHeaders) of the decrypted binaries in this repository:
> - ARM11 FIRM module `pxi`: [`code.bin`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/pxi/code.bin), [`exheader.bin`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/pxi/exheader.bin), table [`pxi_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/pxi/pxi_friendly.sym) (`111` symbols, `0 HYPOTHESIS`)
> - ARM9 Kernel9 + Process9: [`arm9.bin`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/kernel/arm9.bin), table [`arm9_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/kernel/arm9_friendly.sym) (`4,849` symbols, `0 HYPOTHESIS`)
> - Verified ARM11 clients: `FIRM:fs`, `FIRM:loader`, `SysModule ptm` (`0004013000002202`)
>
> **New 3DS:** the `pxi` module of the N3DS NATIVE_FIRM is byte-identical to this one (all 111 symbols `exact`, same addresses); on the ARM9 side, the Process9 functions sampled (e.g. `p9_movable_sed_path_handler`, `p9_memcpy`) are shifted by −0x200 (see `../n3ds/docs/N3DS_VS_O3DS_FINDINGS.md`).

---

## 1. Overview

The **PXI** hardware controller (*Processor eXchange Interface*) is the only direct bidirectional messaging and synchronisation channel between the application processor (**ARM11 MPCore**) and the security processor (**ARM946E-S**). In the 3DS firmware:

- **ARM11 side (`FIRM:pxi`, TitleID `0x0004013000001402`)**: runs in userland with a kernel-mapped privilege (ExHeader without `srv:` ACLs, `.text=0x00100000+0x3844`, `.rodata=0x00104000+0x2BC`, `.data=0x00105000+0x4C`, `.bss=0x196D8`). It exposes **9 IPC services** to userland/sysmodules through `srv:RegisterService` (`0x00100994`) and translates every ARM11 IPC request into the hardware PXI FIFO towards the ARM9 (`0x001013FC`).
- **ARM9 side (`Kernel9 + Process9` in `arm9.bin`)**: Kernel9 handles the physical PXI interrupt (IRQ `12`, controller `0x10008000`) and Process9 (`0x08081DBC` in the `0x08006800` load view, relocated by `+0xB100` at run time) initialises the PXI queues, serves every channel through its ARM jump tables and returns the answer through the reverse FIFO.

---

## 2. Hardware MMIO Registers and Interrupts `[VERIFIED]`

### 2.1 ARM11 ExHeader capabilities (`pxi/exheader.bin`)

- **Kernel11 descriptors**: static IO map `0xFFE1EC63` → page `0x1EC63000..0x1EC63FFF`.
- **Interrupts granted in the ExHeader**: IRQs `[80, 81, 82, 83]` (`0x50..0x53`).
- **Interrupts actually bound** in `pxi_hw_bind_irqs_80_82_83` (`0x001021A8`, via `SVC 0x50 BindInterrupt`):
  - **IRQ `80` (`0x50`)**: PXI Remote SYNC IRQ (`param_1`). Sets bit `0x80` in `PXI_SYNC + 3` (`*(byte*)(base + 3) |= 0x80`).
  - **IRQ `82` (`0x52`)**: PXI SEND FIFO Empty IRQ (`param_3`). Sets bit `0x0004` in `PXI_CNT` (`*(ushort*)(base + 4) = (*(ushort*)(base + 4) & 0x8404) | 4`).
  - **IRQ `83` (`0x53`)**: PXI RECV FIFO Not-Empty IRQ (`param_2`). Sets bit `0x0400` in `PXI_CNT` (`*(ushort*)(base + 4) = (*(ushort*)(base + 4) & 0x8404) | 0x400`).
  - *(IRQ `81` is granted in the ExHeader but neither `0x001021A8` nor `0x00101FF8` binds it.)*

### 2.2 PXI register map (`0x1EC63000` ARM11 ↔ `0x10008000` ARM9)

Verified in `pxi` (`0x0010114C`, `0x00101190`, `0x00101C48`, `0x00101FA8`, `0x00101FC4`, `0x001021A8`, `0x00102E14`) and ARM9 (`0x0801DE10`, `0x08020034`, `0x08023B68`, `0x08026AD4`):

| Offset | Width | Hardware name `[PUBLIC 3DS KNOWLEDGE]` | Behaviour observed in the binary `[VERIFIED]` |
|---|---|---|---|
| `+0x00` | `u32` / byte `+3` | `PXI_SYNC` | `pxi_hw_map_mmio` (`0x0010114C`) writes `0` to `+0x00`. At `+0x03`: bit `0x80` enables the local SYNC IRQ (`0x001021A8` / `0x00101FF8`); writing a mask to `+0x03` (`0x08023B68`: `*(byte*)(base+3) \|= val`, ARM11 `0x00101C48` / `0x00101C7C`) triggers a SYNC signal to the remote core (`0x40`) or controls the handshake. |
| `+0x04` | `u16` | `PXI_CNT` | • **Bit 1 (`0x0002`)**: `SEND_FIFO_FULL` — `pxi 0x00101C48`/`0x00101FC4` wait while `(*(u16*)(base+4) & 2) != 0`; ARM9 `0x08026AD4` waits with `lsls r3, r3, 0x1e; bmi`.<br>• **Bit 2 (`0x0004`)**: `SEND_FIFO_EMPTY_IRQ_EN` — set at `0x001021A8`.<br>• **Bit 3 (`0x0008`)**: `SEND_FIFO_CLEAR` / reset — `0x0010114C` and `0x001011A8` write `8`, iterate a delay (`i < 0x10`, step `2`) and write `0` and then `uVar2` (bit `0x8000` enable in masks `0x8404`/`0x8004`/`0x8400`).<br>• **Bit 8 (`0x0100`)**: `RECV_FIFO_EMPTY` — ARM11 `0x00101FA8`/`0x00102E14` wait for `(*(u16*)(base+4) & 0x100) != 0`; ARM9 `0x0801DE10` returns `((u16)PXI_CNT & 0x1ff) >> 8` and `0x08020034` polls with `lsls r3, r3, 0x17; bmi`.<br>• **Bit 10 (`0x0400`)**: `RECV_FIFO_NOT_EMPTY_IRQ_EN` — set at `0x001021A8`. |
| `+0x08` | `u32` (WO) | `PXI_SEND` FIFO | Writes of 32-bit words (`pxi 0x00101FC4`/`0x00101C48`, ARM9 `0x08026AD4`). |
| `+0x0C` | `u32` (RO) | `PXI_RECV` FIFO | Reads of 32-bit words (`pxi 0x00101FA8`/`0x00102E14`, ARM9 `0x08020034`). |

On ARM9 (`kernel9`), the physical handling uses base `0x10008000` (`k9_pxi9_drv_01_0x0800A0D0` and `p9_pxi9_*` helpers between `0x0801D4D4` and `0x0804D280`) serving IRQ `12` in `k9_irq_dispatch` (`0x08012248`).

---

## 3. The 9 PXI channels and the registration table (`0x00104044`) `[VERIFIED]`

In ARM11 `pxi/code.bin` (`.rodata` @ `0x00104044`, 9 entries of `12` bytes), each descriptor holds `[u32 str_ptr, u8 ch_id, u8 buf_start_slot, u8 max_sessions, u8 pad, u32 unk_init]`. The main loop `pxi_server_main_loop` (`0x001000AC`) registers them in `srv:` and indexes the internal slots by **`ch_id` (`0..8`)** (`0x11BCE4 + ch_id * 0x14`):

| `ch_id` (wire) | Table `0x104044` index | ARM11 service | `byte+5` (first free slot) | Max. 4 KB static buffers allowed | `max_sessions` (`byte+6`) | ARM9 Process9 dispatcher (`0x08081DBC`, load view / `+0xB100` runtime) |
|---:|---:|---|---:|---:|---:|---|
| **`0`** | 7 | `pxi:mc` | `0` | **0** (`4 - 0` slots released) | `1` | `0x0807F0F4` (runtime `0x0808A1F4`), `13` cases (`0x00..0x0C`) |
| **`1`** | 0 | `PxiFS0` | `2` | **2** (`4 - 2` slots released) | `1` | `0x0807C61C` (runtime `0x0808771C`), `87` cases (`0x00..0x56`) |
| **`2`** | 1 | `PxiFS1` | `2` | **2** | `1` | Shares `0x0807C61C` |
| **`3`** | 2 | `PxiFSB` | `2` | **2** | `1` | Shares `0x0807C61C` |
| **`4`** | 3 | `PxiFSR` | `2` | **2** | `1` | Shares `0x0807C61C` |
| **`5`** | 4 | `PxiPM` | `1` | **1** (`4 - 1` slots released) | `1` | `0x0807F2B0` (runtime `0x0808A3B0`), `4` cases (`0x00..0x03`) |
| **`6`** | 6 | `pxi:dev` | `4` | **4** (`0` released, expected) | `2` | `0x0807AE24` (runtime `0x08085F24`), `16` cases (`0x00..0x0F`) |
| **`7`** | 5 | `pxi:am9` | `4` | **4** | `1` | `0x0807F8FC` (runtime `0x0808A9FC`), `110` cases (`0x00..0x6D`) |
| **`8`** | 8 | `pxi:ps9` | `4` | **4** | `1` | `0x0807F4B0` (runtime `0x0808A5B0`), `14` cases (`0x00..0x0D`) |
| *(ARM9 slot 9)* | — | *(internal)* | — | — | — | Stub `0x08081C30` (`SVC 0x18 SignalEvent`) initialised in loop `10` of `0x08081DBC` (`0x08065BDA`) |

> **Note on `byte +5` in `pxi 0x001013FC` (lines 551–565):** after receiving an IPC request, `pxi` always allocates up to `4` shared `4 KB` pages for the reply at `TLS+0x180`, but immediately releases from the `local_5c` mask the slots from `uVar8 = *(byte*)(local_4c + 0x0F)` (copied from `table_entry + 5`) up to `3`. If a request carries buffer descriptors that no longer have a retained slot, they are discarded by channel policy (`pxi:mc` = `0` static buffers, `PxiPM` = `1`, `PxiFS*` = `2`, `pxi:dev/am9/ps9` = `4`).

---

## 4. Wire FIFO frame format and buffer translation `[VERIFIED]`

### 4.1 Message encapsulation (`pxi_send_command_body` `0x00101CC8` ↔ `pxi_rx_dispatch_from_fifo` `0x00102A04`)

1. **TX mutual-exclusion acquisition** (`0x00101CC8`): waits for the PXI mutex (`SVC 0x24` or `0x00102B20`).
2. **Word 0 (`ch_id`)**: the channel identifier byte (`0..8`) is written to `PXI_SEND` (`0x00101FC4`).
3. **SYNC check/trigger**: queries `0x00101C7C` (`*(u16*)(base+4) >> 1 & 1`) and enters `0x00101C48`.
4. **Strict IPC frame length computation**:
   ```c
   uint32_t total_words = (cmd_hdr & 0x3F) + ((cmd_hdr & 0xFC0) >> 6) + 1;
   ```
   - `cmd_hdr & 0x3F`: number of normal parameters (`N`, bits `0..5`).
   - `(cmd_hdr & 0xFC0) >> 6`: number of translate words (`T`, bits `6..11`).
   - `+ 1`: includes the `cmd_hdr` header itself.
   - **Hard limit verified** in both directions: both the IPC sender (`0x001013FC`, `if (0x100 < uVar8) Break()`) and the FIFO receiver (`0x00102A04`, `if (0x40 < iVar4 + 1U) Break()`) enforce **`total_words <= 0x40` (`<= 64` words = `256` bytes maximum)**.
5. **Word transmission**: `0x00101C48` writes `total_words` 32-bit words to `PXI_SEND` (`+0x08`) polling `SEND_FIFO_FULL` (`+0x04 & 2`), and releases the mutex (`SVC 0x14`).
6. **Reception and queuing on ARM11 (`0x00102A04` and `0x00102F08`)**:
   - Reads `ch_id` with `0x00101FA8`, validates `0 <= ch_id < param_1[1]` (`9`).
   - Checks that the channel has no active reception (`puVar6[4] == 0`), reads `cmd_hdr`, validates `total_words <= 0x40` and reads `total_words - 1` words through `0x00102E14` into `puVar6[3]`.
   - Executes the callback `(**puVar6)(puVar6, puVar6[3])`; if it returns `0`, it links the reply in the IPC thread list and wakes the server `0x001013FC` (`SVC 0x4F ReplyAndReceive`) through `ArbitrateAddress` (`0x00101EF0`), which copies `total_words * 4` bytes to `TLS + 0x80` via `0x00102830`.
   - If the callback returns non-zero (e.g. `0x00102F08`), it decrements the semaphore through `ArbitrateAddress` (`0x00101BD0`), marks the reply as received and calls `ReleaseSemaphore` (`0x00101BB8`) and `SVC 0x18 SignalEvent` when `byte+0x34 > 1`.

### 4.2 Static buffer translation with `4 KB` pages (`0x001013FC`)

Because the ARM9 core does not see the virtual address space paged by the MMU of each ARM11 userland process:
- `pxi` keeps a bitmap of free **`4 KB` (`0x1000` bytes)** pages in `local_28[7]` over a linear base region `local_28[6]`.
- In `0x001013FC` (lines 326–345 and 577–599), before executing `SVC 0x4F ReplyAndReceive`, it allocates up to `4` indices using **`LZCOUNT(local_28[7])`** (`slot = 31 - clz`):
  - If a slot is available: writes to `TLS + 0x180 + i*8` the kernel receive static-buffer descriptor **`0x04000002`** and the address **`local_28[6] + slot * 0x1000`**.
  - If there are no slots: writes `2` (empty buffer).
- On the way to the ARM9 (`pxi` → Process9) the static buffers have already landed in contiguous physical/shared memory; when finishing and replying to the ARM11 client (lines 488–502), the corresponding bits are set again in `local_28[7]` (`*puVar13 |= 1 << (slot & 0x1F)`).

---

## 5. Verified detail of each channel and Process9 handlers

### 5.1 Channel 0 — `pxi:mc` (Power control, Sleep/Wake and CFG9) `[VERIFIED]`

- **Sleep lock on ARM11 (`pxi 0x001013FC`, lines 532–549)**:
  - `pxi` explicitly intercepts every request addressed to **channel `0` (`pxi:mc`) with command `5` (`cmd_hdr >> 16 == 5`)**:
  - If `[TLS + 0x84] != 0`: if the global lock `*(puVar6 + 0x68)` was already active it raises `Break()`, otherwise it sets **`*(puVar6 + 0x68) = 1`** and marks `local_40 = 1`. While this lock is active, `0x001013FC` only sends urgent-marked messages to the ARM9 and holds new normal transmissions (`local_40 == 0` is retained if `*(puVar6 + 0x68) != 0`).
  - If `[TLS + 0x84] == 0` (`cmd 5` with argument `0`): requires the lock to have been active and marks `local_40 = 2`. When the reply completes (`cVar4 == 2`, lines 482–487), it checks `in_flight == 0` and clears `*(puVar6 + 0x68) = 0`.
- **`SysModule ptm` client (`0x001010F8`)**: connects to the `"pxi:mc"` service (`DAT_00101200 -> 0x0010D31A`), creates an event with `SVC 0x17` (`0x0010BC00`) and starts thread `0x0010268F` (`0x0010268E` Thumb → `0x00103184`), which coordinates the state/sleep transition (`0x00103F6C` / `0x00104378` / `0x001043BC` and `SVC 0x7C KernelSetState` at `0x001053F0`). In addition, `pxi_server_main_loop` (`0x001000AC`) sends `pxi:mc cmd 1` (`0x00010000`) during its `srv:` shutdown/notification sequence.
- **ARM9 handlers (`0x0807F0F4`, load view; `13` entries `0..0xC`)**:
  - `cmd 0x00` (`0x0807F268`): invalid (`hdr=0x40`, returns `0xD900182F`).
  - `cmd 0x01` (`0x0807F14C`): calls `0x0807B954(r1)` — fires `SVC 0x18 SignalEvent` on two handles (`[r0]` and `[r4+4]`) and writes **`*(u32*)0x10010000 = 1`** (`CFG9_EXT` at `0x0807B980`), returns `hdr=0x00010040`, `[4]=res`.
  - `cmd 0x02` (`0x0807F168`): stub `hdr=0x00020040`, `[4]=0`.
  - `cmd 0x03` (`0x0807F17C`): writes `hdr=0x000300C0`, `[4]=0`, `[8]=r1`, `[12]=r0`.
  - `cmd 0x04` (`0x0807F198`): stub `hdr=0x00040040`, `[4]=0`.
  - `cmd 0x05` (`0x0807F1AC`): reads signed byte `[r4+4]` and calls `0x0807B9D4(r2, s8)` — if `param_2 != 0` sets `*(param_1+8) = 3` and executes `SVC 0x18 SignalEvent`; if `param_2 == 0` calls `0x0807ADD0`. On wake-up (`0x0807B9A0`), if `*(param_1+8) == 3`, executes **`SVC 0x7C`** and clears the state. Returns `hdr=0x00050040`.
  - `cmd 0x06` (`0x0807F1CC`): stub `hdr=0x00060040`, `[4]=0`.
  - `cmd 0x07` (`0x0807F1E0`): returns `hdr=0x00070080`, `[4]=0` and byte `[r4+8]=r0`.
  - `cmd 0x08` (`0x0807F1F8`) and `cmd 0x09` (`0x0807F204`): explicitly return **`0xE0C0EC03`** with header `0x00080040` / `0x00090040`.
  - `cmd 0x0A` (`0x0807F210`): passes 3 words `[r4+4..+12]` to Thumb `0x08033290` (invokes `0x080331F8` and `0x08055884`, fills struct `0x08094F60+0x8..+0x14`, writes `*(u8*)0x08094F60 = 1`), returns `hdr=0x000A0040`, `[4]=0`.
  - `cmd 0x0B` (`0x0807F238`): stub `hdr=0x000B0040`, `[4]=0`.
  - `cmd 0x0C` (`0x0807F24C`): copies `0x80` bytes from the stack to `[r4+4]` via `0x08056B28` (`p9_memcpy32_aligned`), returns `hdr=0x000C0040`, `[4]=0`.

### 5.2 Channels 1..4 — `PxiFS0`, `PxiFS1`, `PxiFSB`, `PxiFSR` `[VERIFIED]`

- **ARM11 side (`FIRM:fs`)**: [`fs_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/fs/fs_friendly.sym) verifies **`83+` `swi 0x32` wrappers** between `0x0012F410..0x00130ACC` (plus `0x00124CE4`, `0x00125450`, `0x001254F4`). All headers match the ARM9 bit by bit:
  - Example verified against the table: `cmd 0x01` uses `0x000101C2` (`7` normal, `2` translate; `fs:0x00130958` ↔ ARM9 `0x0807C7B4`), `cmd 0x02` uses `0x00020142` (`0x0012F494` ↔ `0x0807C8D4`), `cmd 0x03` uses `0x00030244` (`0x0012F5F4` ↔ `0x0807C9CC`), `cmd 0x05` uses `0x00050202` (`0x0012F410` ↔ `0x0807CC78`), `cmd 0x41` uses `0x00410000` (`0x0012F46C` ↔ `0x0807E63C` / `0x0806A894`), `cmd 0x55` uses `0x00550082` (`0x0012FA84` ↔ `0x0807EF1C`), `cmd 0x56` uses `0x00560102` (`0x00130764` ↔ `0x0807EF84`).
- **ARM9 side (`0x0807C61C`, `87` entries `0x00..0x56`)**: `cmd 0x00` is invalid (`0x0807F044`), while all entries `0x01..0x56` are active and dispatch file/direct-file operations, SDMC (`0x08025F30`), NAND DB (`0x0806F15C`), ExtData (`0x0806C354`), CTRCARD/NTRCARD (`0x0804576C`, `0x0806B164`), SPICard (`0x0806B238`, `0x0807043C`) and key management (`0x0806A970`).

### 5.3 Channel 5 — `PxiPM` (Process loading and registration) `[VERIFIED]`

Exact correlation verified between **`FIRM:loader`** and **`Process9 @ 0x0807F2B0`**:

| `cmd` | Entry header | `FIRM:loader` client | ARM9 handler (`0x0807F2B0`) + verified behaviour |
|---:|---|---|---|
| `0x01` | `0x00010082` (desc `(w3&0xff)==4`, `len>=0x400`) | `ldr_pxipm_GetProgramInfo_0x10082` (`0x14001B70`) | `0x0807F308`: calls Thumb **`0x0803366C`** to obtain the `ExHeader` (`0x400` B); replies `hdr=0x00010041`, `[4]=res`, `[8]=4`. |
| `0x02` | `0x00020200` (`u64 ProgramInfo` + `ProgramUpdateInfo`) | `ldr_RegisterProgram` (`0x14000F80` → `0x14002E48`) | `0x0807F378`: copies `ProgramInfo` (`[r4+4..+0x20]`), validates permissions/media and calls Thumb **`0x08033448`**; replies `hdr=0x000200C0`, `[4]=res`, `[8..12]=out_program_handle` (`u64`). |
| `0x03` | `0x00030080` (`u64 program_handle`) | `ldr_UnregisterProgram` (`0x14001E28` → `0x14002EB0`) | `0x0807F474`: calls Thumb **`0x08033604`** (`0x08033BBC` + `0x0807684A`) to unregister the program; replies `hdr=0x00030040`, `[4]=res`. |

### 5.4 Channel 6 — `pxi:dev` (Devices / Cartridge / CardIO) `[VERIFIED]`

ARM9 table **`0x0807AE24`** (`16` entries `0x00..0x0F`, `max_sessions = 2` in `pxi`):
- `0x00`: invalid (`0x0807B3E8`, `0xD9001830`).
- Active commands `0x01..0x0F` with verified headers:
  - `0x01` (`0x000101C2` → `0x0807B464`), `0x02` (`0x000201C2` → `0x0807B544`), `0x03` (`0x00030102` → `0x0807B4D4`), `0x04` (`0x00040102` → `0x0807B5B4`), `0x05` (`0x00050102`), `0x06` (`0x00060102`), `0x07` (`0x00070040`), `0x08..0x0B` (call `p9_ntrcard_caller_*` helpers `0x0806C8C8..0x0806CB78`, headers `0x00080040`, `0x00090040`, `0x000A0080`, `0x000B0080`), `0x0C` (`0x000C0042` → `0x0806CAD4`), `0x0D` (`0x000D0688`), `0x0E` (`0x000E0284`), `0x0F` (`0x000F0080` → `0x0807B8AC`).

### 5.5 Channel 7 — `pxi:am9` (ARM9 Application Manager) `[VERIFIED]`

ARM9 table **`0x0807F8FC`** (`110` entries `0x00..0x6D`, load view `0x0807F920`):
- `0x00`, `0x2B..0x38`, `0x3A`, `0x66` point to the default error handler `0x08081B18` (runtime `0x0808CC18`).
- The **`93` active commands** are: `0x01..0x2A`, `0x39`, `0x3B..0x65`, `0x67..0x6D`, invoking internal Thumb/ARM functions at `0x080347D0..0x0803D7DC` and `0x0807C610`.

### 5.6 Channel 8 — `pxi:ps9` (RSA/AES cryptography and random generation) `[VERIFIED]`

ARM9 table **`0x0807F4B0`** (`14` entries `0x00..0x0D`):
- `0x00`: invalid (`0x0807F894`, `0xD9001830`).
- `0x01` (`0x000100C6` → `0x0807BF54`), `0x02` (`0x00020284` → `0x0807BAD4`, signature/modular operation up to `0x800` bits), `0x03` (`0x00030284` → `0x0807BBF8`, RSA verification up to `0x800` bits = `2048`-bit), `0x04` (`0x000401C4` → `0x0807BCDC`), `0x05` (`0x00050284`), `0x06` (`0x00060140` → `0x0807C528`, generates `0x10` random bytes via `0x08042958`), `0x07` (`0x00070180` → `0x0807C568`, PRNG/DRBG `0x08042958` + `0x0804D976`), `0x08` (`0x00080080`), `0x09` (`0x00090080`), `0x0A` (`0x000A00C0`), `0x0B` (`0x000B0080`), `0x0C` (`0x000C0042`), `0x0D` (`0x000D0042` → `0x08042014`).

---

## 6. Differences from generic knowledge `[VERIFIED]`

1. **`.rodata` table order vs wire `ch_id`**: in `pxi 0x00104044`, the first entry is `PxiFS0` (`ch_id=1`) and entry `7` is `pxi:mc` (`ch_id=0`); channel `0` is not necessarily entry `0` of the static array, but the `byte +4` value of the registration struct.
2. **Automatic discarding of static descriptors (`byte +5`)**: `pxi:mc` forces `0` retained static buffers, `PxiPM` retains `1` (`ExHeader` `0x400` B), `PxiFS*` retain `2`, and only `pxi:dev/am9/ps9` retain up to `4`.
3. **Interrupt `81` unused**: although the `FIRM:pxi` ExHeader grants `80, 81, 82, 83`, the verified code at `0x001021A8` binds only `80`, `82` and `83`.
4. **ARM11 SHA11 in `FIRM:fs`**: `FS` hash operations on ARM11 no longer necessarily travel to `pxi:ps9` — `FIRM:fs` directly maps the `SHA11` hardware engine (`0x1EC01000` / `0x1EE01000`, `0x00130C08..0x00131054`) in its own ExHeader.
