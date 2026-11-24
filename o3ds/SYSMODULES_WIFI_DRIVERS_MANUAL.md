# Technical Manual of Base SysModules, Hardware Drivers, WiFi (`nwm`) and the StreetPass Antenna (`cecd`) — Nintendo 3DS

> ⚠️ **CRITICAL HARDWARE AND NAND SAFETY WARNING — READ BEFORE TOUCHING A REAL CONSOLE**
>
> **ALWAYS make a full backup of the NAND and of your console's critical recovery files BEFORE modifying, injecting, patching or testing code against critical SysModules (`mcu`, `ptm`, `i2c`, `pxi`, `nwm`, `cecd`, `gsp`, `fs`, `pm`).**
> - The `mcu` (`i2c::MCU`) and `ptm` (`pxi:mc`) SysModules directly control the PMIC/reset/power-off microcontroller and persistent RTC/NVRAM counters; a wrong command on real hardware can force immediate shutdowns, configuration corruption (`ptmdb:`, RTC/MCU) or boot failures.
> - The `nwm` SysModule operates directly on the SDIO2 controller of the Atheros AR6014 WiFi chip through kernel DMA (`SVC 0x55..0x58`), electrical radio control (`SVC 0x5A`) and `cfg:u`/`ps:ps`/`mcu::NWM`, and can saturate IPC/DMA buffers or hang the console if corrupt payloads are sent.
> - **Minimum requirements before experimenting:** full SysNAND backup (e.g. via **GodMode9**), an external copy of `movable.sed`, `otp.bin`, `seeds` / `essential.exefs`, an intact copy of `FIRM`/`arm9.bin`/`arm11.bin`, and a guaranteed recovery method (**ntrboot** + Boot9strap or **hardmod / NAND programmer**). Always test first on dumps/emulation before a real console.

---

> **Evidence status:** `0 HYPOTHESIS` `[VERIFIED IN THIS REPO]` — All symbols, C signatures, ExHeader maps, MMIO registers, IRQ interrupts, real ARM SVCs, registered services and IPC tables documented in this manual were verified directly on the decrypted binaries (`code.bin`, `exheader.bin`, `arm11.bin`), their ARM/Thumb disassembly (`radare2 5.9.8`) and their full C decompilation (`REA + Ghidra 12.2`). The few general hardware contextualisations carry an explicit `[PUBLIC 3DS KNOWLEDGE]` label.
>
> **New 3DS:** the shared TitleIDs (`0004013000xxxxxx`) of `cecd`, `hid`, `nwm`, and the FIRM modules `fs`, `loader`, `pxi`, `sm` are byte-identical on N3DS, so everything below applies unchanged; `gsp`, `i2c`, `mcu`, `ptm`, FIRM `pm` have separate N3DS builds (see `../n3ds/docs/N3DS_VS_O3DS_FINDINGS.md`).

---

## 1. Critical Clarification of Paths: Old `Modulo-*` Folders vs Real Identity in `exheader.bin` `[VERIFIED]`

When `decrypted_binaries/` was originally organised, the folders `SysModule_<TitleID>` were renamed to `Modulo-<Prefix>-<TitleID>`, **but several descriptive prefixes ended up shifted with respect to the real program declared in the first 8 bytes of `exheader.bin`**. A module must never be assumed from its folder name; the authoritative anchor is always the **TitleID + `exheader.bin[0:8]`**.

**Resolved:** all directories have since been renamed to English names built from the real ExHeader name (`Module-<REAL-NAME>-<Role>[-SafeMode]-<TitleID>`; mapping in `decrypted_binaries/RENAME_MAP.tsv`). The tables below use the new directory names.

### 1.1 Exact map of the 7 analysed SysModules (`0 HYPOTHESIS`)

| Real identity (`exheader.bin[0:8]`) | TitleID | Directory on disk (now) | Old (misleading) directory | C pseudocode (`Ghidra 12.2`) | `.sym` table (`0 HYPOTHESIS`) |
|-------------------------------------|---------|-------------------------|----------------------------|------------------------------|-------------------------------|
| **`gsp`** | `0004013000001C02` | [`Module-GSP-GPU-Service-0004013000001C02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-GSP-GPU-Service-0004013000001C02) | `Modulo-GPIO-Pines-Entrada-Salida-…` | **336** `.c` files | [`gsp_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-GSP-GPU-Service-0004013000001C02/gsp_friendly.sym) (**352**: 147 `CONFIRMED`, 205 `EVIDENCE_BASED`) |
| **`hid`** | `0004013000001D02` | [`Module-HID-Buttons-and-Touch-Input-0004013000001D02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-HID-Buttons-and-Touch-Input-0004013000001D02) | `Modulo-I2C-Bus-Hardware-…` | **250** `.c` files | [`hid_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-HID-Buttons-and-Touch-Input-0004013000001D02/hid_friendly.sym) (**263**: 97 `CONFIRMED`, 166 `EVIDENCE_BASED`) |
| **`i2c`** | `0004013000001E02` | [`Module-I2C-I2C-Bus-0004013000001E02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-I2C-I2C-Bus-0004013000001E02) | `Modulo-MCU-Microcontrolador-Energia-…` | **142** `.c` files | [`i2c_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-I2C-I2C-Bus-0004013000001E02/i2c_friendly.sym) (**153**: 59 `CONFIRMED`, 94 `EVIDENCE_BASED`) |
| **`mcu`** | `0004013000001F02` | [`Module-MCU-Microcontroller-Power-0004013000001F02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-MCU-Microcontroller-Power-0004013000001F02) | `Modulo-PDN-Energia-y-Relojes-…` | **243** `.c` files | [`mcu_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-MCU-Microcontroller-Power-0004013000001F02/mcu_friendly.sym) (**257**: 87 `CONFIRMED`, 170 `EVIDENCE_BASED`) |
| **`ptm`** | `0004013000002202` | [`Module-PTM-Battery-and-Pedometer-0004013000002202`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-PTM-Battery-and-Pedometer-0004013000002202) | `Modulo-PTM-Bateria-y-Podometro-…` | **624** `.c` files | [`ptm_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-PTM-Battery-and-Pedometer-0004013000002202/ptm_friendly.sym) (**769**: 59 `CONFIRMED`, 710 `EVIDENCE_BASED`) |
| **`cecd`** | `0004013000002602` | [`Module-CECD-StreetPass-0004013000002602`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602) | `Modulo-CECD-StreetPass-…` | **1,323** `.c` files | [`cecd_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602/cecd_friendly.sym) (**1,676**: 58 `CONFIRMED`, 1,618 `EVIDENCE_BASED`) |
| **`nwm`** | `0004013000002D02` | [`Module-NWM-WiFi-0004013000002D02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02) | `Modulo-NWM-WiFi-…` | **2,039** `.c` files | [`nwm_friendly.sym`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02/nwm_friendly.sym) (**2,784**: 87 `CONFIRMED`, 2,697 `EVIDENCE_BASED`) |

> **Other shifted prefixes that existed in the old `Modulo-*` directories (`exheader.bin[0:8]` verified):**
> `0004013000001502`/`1503` = **`am`** (was `Modulo-FS-*`), `1602` = **`camera`** (`Modulo-PM-*`), `1702`/`1703` = **`cfg`** (`Modulo-SM-*`), `1802`/`1803` = **`codec`** (`Modulo-PXI-*`), `1A02`/`1A03` = **`dsp`** (`Modulo-NS-*`), `1B02`/`1B03` = **`gpio`** (`Modulo-CFG-*`), `2002` = **`mic`** (`Modulo-SPI-*`), `2102`/`2103` = **`pdn`** (`Modulo-PS-*`), `2302`/`2303` = **`spi`** (`Modulo-CAM-*`), `2402`/`2403` = **`ac`** (`Modulo-CSND-*`), `2702`/`2703` = **`csnd`** (`Modulo-DSP-*`), `2902`/`2903` = **`http`** (`Modulo-HID-*`), `3102`/`3103` = **`ps`** (`Modulo-BOSS-*`), `3402` = **`boss`** (`Modulo-L2B-*`), `3502` = **`news`** (`Modulo-MVD-*`). Each of the 7 analyses in this guide also generated ready-to-load scripts: `symbols_<mod>_friendly.r2` and `symbols_<mod>_friendly_ghidra.py`.

---

## 2. The 5 Modules Embedded in FIRM (`arm11.bin` Section 0) `[VERIFIED]`

Extracted from [`decrypted_binaries/kernel/arm11.bin`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/kernel/arm11.bin) into [`decrypted_binaries/firm_modules/`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules) (real load order by `kernel11_launch_firm_sysmodules` in Kernel11: `pxi`, `fs`, `pm`, `sm`, `loader`; ExHeaders without external dependencies `deps=[]`).

| Module | TitleID | `.text` / `.ro` / `.data` base (`bss`) | ExHeader priority | Hardware capabilities / ACL | Symbols (`0 HYP`) and Ghidra C | Paths |
|--------|---------|------------------------------------------|-------------------|-----------------------------|--------------------------------|-------|
| **`pxi`** | `0004013000001402` | `0x00100000` (`0x3844`) / `0x104000` / `0x105000` (`0x196D8`) | `0x2D` | MMIO `0x1EC63000` (`0xFFE1EC63`), IRQs `80..83` (`0xEA146953`), `SVC 0x50/0x51` | **111** (**77** `CONFIRMED`, **34** `EVIDENCE_BASED`), **103** `.c` | [`pxi/`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/pxi/pxi_friendly.sym) |
| **`sm`** | `0004013000001002` | `0x00100000` (`0x4190`) / `0x105000` / `0x106000` (`0x5148`) | `0x34` | Registers kernel ports `'srv:'` and `'srv:pm'`; no IO/IRQ or ACL | **107** (**67** `CONFIRMED`, **40** `EVIDENCE_BASED`), **100** `.c` | [`sm/`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/sm/sm_friendly.sym) |
| **`loader`** | `0004013000001302` | **`0x14000000`** (`0x3898`) / `0x14004000` / `0x14005000` (`0x1104`) | `0x34` | ACL `fs:LDR`; uses `SVC 0x73` (`CreateCodeSet`) and `SVC 0x75` (`CreateProcess`) | **115** (**78** `CONFIRMED`, **37** `EVIDENCE_BASED`), **110** `.c` | [`loader/`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/loader/loader_friendly.sym) |
| **`pm`** | `0004013000001202` | `0x00100000` (`0x5F38`) / `0x106000` / `0x107000` (`0x3804`) | `0x34` | ACL `fs:REG`; `SVC 0x76..0x79`, `0x7C` (`KernelSetState`), `0x60` | **142** (**97** `CONFIRMED`, **45** `EVIDENCE_BASED`), **135** `.c` | [`pm/`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/pm/pm_friendly.sym) |
| **`fs`** | `0004013000001102` | `0x00100000` (`0x33FB0`) / `0x134000` / `0x136000` (`0x32A28`) | `0x2E` | MMIO `0x1EC01000`, `0x1EE01000`; DMA/Cache `SVC 0x53..0x57` | **1,572** (**153** `CONFIRMED`, **1,419** `EVIDENCE_BASED`), **1,568** `.c` | [`fs/`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/firm_modules/fs/fs_friendly.sym) |

### 2.1 Roles and invariants confirmed in C code
- **`pxi` (`0004013000001402`):** ARM11 ↔ ARM9 hardware bridge over MMIO `0x1EC63000` (physical `0x10163000`). Registers 9 IPC services (`pxi:mc`, `pxi:dev`, `pxi:am9`, `pxi:ps9`, `PxiFS0/1/B/R`, `PxiPM`), binds IRQs `80`, `82` (`RECV`) and `83` (`SEND`) via `SVC 0x50` (`0x102BD4`), and serialises TX FIFO packets with `pxi_send_command_arm11_to_arm9` (`0x101CC4`) and 3 threads (`0x100DA8`, `0x100DBC`, `0x100DC8`). Complete bit-by-bit specification in [`PXI_PROTOCOL.md`](file:///home/skels/3ds-reversing/o3ds/PXI_PROTOCOL.md).
- **`sm` (`0004013000001002`):** Central service manager (`sm_server_main_loop` @ `0x001000A0`). Creates ports `'srv:'` and `'srv:pm'`, parses ExHeader ACL blobs in `sm_exheader_acl_table_parse` (`0x00101204`), checks per-PID u64 permissions in `sm_check_process_service_acl` (`0x0010189C`), handles name lookup of `1..8` bytes in `sm_find_registered_service_or_port` (`0x00102030`) and wakes waiters through a 16-notification circular queue (`sm_notif_ring_push` @ `0x00101994`).
- **`loader` (`0004013000001302`):** Runs at the special base `0x14000000`. Registers the `'Loader'` service (`ldr_server_main_loop` @ `0x14000054`), connects to `'PxiPM'`, `'fs:LDR'` and `'fs:USER'` (`0x140004A4`), decompresses the compressed `.code` in memory with Nintendo BLZ (`ldr_blz_decompress_in_place` @ `0x14000E28`, footer `-4/-8/-12`), reads ExeFS sections (`0x1400113C`), delegates validation to `PxiPM` (`ldr_RegisterProgram` @ `0x14000F80`) and instantiates ARM11 processes via `SVC 0x73` (`0x14000EBC`) + `SVC 0x75` (`0x14000ED8`).
- **`pm` (`0004013000001202`):** Registers `pm:app` and `pm:dbg` (`pm_server_main_loop` @ `0x00100084`). Initialises the `APPMEMALLOC` memory layout and ResourceLimits via `GetSystemInfo` + `SVC 0x77/0x78/0x79/0x7C` (`pm_init_builtin_and_appmemalloc` @ `0x00100524`), resolves dependency lists from the ExHeader (`pm_build_dependency_list` @ `0x00101CFC` and `pm_launch_dependency_titles` @ `0x00101ED8`) and launches processes in coordination with `Loader` and `fs:REG` (`pm_launch_title_ex` @ `0x0010167C`, using `SVC 0x76` for termination).
- **`fs` (`0004013000001102`):** ARM11 storage server (`fs_main_server_init` @ `0x00122AD0`). Maps MMIO pages `0x1EC01000` and `0x1EE01000` (`CTR_CARD` / FS controller), registers `fs:USER`, `fs:LDR`, `fs:REG` (`0x00123198`) and opens 4 independent PXI channels to the ARM9 (`PxiFS0`, `PxiFS1`, `PxiFSB`, `PxiFSR`) using verified stubs such as `fs_pxifs_swi32_cmd_0x47_n1_t2` (`0x00124CE4`, 1W+2T -> ARM9 `0x08042008`) and `fs_pxifs_swi32_cmd_0x4F_n2_t0` (`0x00125450`, 2W -> ARM9 `0x0806B424`), protected with recursive mutexes (`fs_reclock_lock` @ `0x0011E2E0`) and SHA checks (`fs_sha11_oneshot_hash` @ `0x0011D104`).

---

## 3. The 5 Hardware, Video, Input, I2C Bus and Power SysModules `[VERIFIED]`

### 3.1 `i2c` (`0004013000001E02`) — Multi-domain I2C Master Bus
- **Location:** [`Module-I2C-I2C-Bus-0004013000001E02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-I2C-I2C-Bus-0004013000001E02) (`i2c_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0x4740)`, `.ro=0x00105000`, `.data=0x00106000`, `.bss=0x2200`, `prio=0x14`, `deps=[]`, client ACL `=[]`.
- **Verified hardware MMIO & IRQs:**
  - 3 I2C controllers mapped through `0xFFE`: **`0x1EC61000`**, **`0x1EC44000`**, **`0x1EC48000`** (`.rodata 0x105040..0x105054` stores base `+0` and control register `+1`).
  - IRQs authorised by descriptor `0xEA956E7F`: **`84`**, **`85`**, **`92`** (bound with `SVC 0x50` at `0x1018F8` / ARM site `0x101900`, initialised in `i2c_hw_init_controllers_irqs` @ `0x00102508`).
- **Registered services and confirmed architecture:**
  - `.rodata 0x105000..0x10503C` and `.data 0x106004..0x10601C` declare **7 ports**: `i2c::MCU`, `i2c::CAM`, `i2c::LCD`, `i2c::DEB`, `i2c::HID`, `i2c::IR`, `i2c::EEP`.
  - `.data 0x106020..0x106038` launches **7 ARM32 worker threads** (`0x1044A4..0x1046E0`, `r0 = 0..6`) that enter the common loop `i2c_service_session_loop` (`0x00102148`) and the **`i2c_ipc_dispatcher`** (`0x00101AC4`, **21 cases** `0x01..0x15`).
  - **Per-device access control:** `i2c_check_bus_device_permission` (`0x00102BC0`) filters which service `0..6` may address which `dev_id < 0xF` index in the `.rodata 0x105058..0x1050A0` table (verified hardware slave addresses: `0x4A`, `0x7A`, `0x78`, `0x40`, `0xD6`, `0xD0`, `0xA4`...) and the real operations run over FIFO/control (`reg+0`, `reg+1`: STOP bits `0xC5`, SELECT `0xE1`, WRITE `0xC2`, READ `0xC0`, ACK `&0x10 >> 4`) in `i2c_hw_bus_transfer` (`0x0010267C`).

### 3.2 `mcu` (`0004013000001F02`) — Microcontroller, Power and RTC Proxy
- **Location:** [`Module-MCU-Microcontroller-Power-0004013000001F02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-MCU-Microcontroller-Power-0004013000001F02) (`mcu_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0x8290)`, `.ro=0x00109000`, `.data=0x0010A000`, `.bss=0x2DE8`, `prio=0x14`, `deps=['0004013000001B02' (gpio), '0004013000001E02' (i2c)]`.
- **Service ACL:** `['gpio:MCU', 'i2c::MCU', 'ptm:s']`. It maps no MMIO or IRQs of its own: it delegates all PMIC reads/writes to `i2c::MCU` + the `gpio:MCU` interrupt line in `mcu_hw_and_i2c_init` (`0x0010086C`).
- **Table of 9 services and verified dispatchers (`.data 0x10A034..0x10A078`):**

| Index | Service | ARM32 worker thread | Target dispatcher | Active commands | Main function |
|-------|---------|---------------------|-------------------|-----------------|---------------|
| `[0]` | **`mcu::CAM`** | `0x107DD8` | `0x1022D8` | **2** | Camera power / LED |
| `[1]` | **`mcu::GPU`** | `0x107EE0` -> `0x101E74` | `0x1024E0` | **14** | LCD backlight, 3D/GPU status LEDs |
| `[2]` | **`mcu::HID`** | `0x107FDC` -> `0x101F20` | `0x1028D4` | **15** | HOME/POWER/WiFi/volume/lid button events |
| `[3]` | **`mcu::RTC`** | `0x10812C` -> `0x102078` | `0x1048F0` | **92** | Hardware RTC clock, alarms, battery, PMIC reset/poweroff |
| `[4]` | **`mcu::SND`** | `0x108238` | `0x10222C` -> `0x106400` | **3** | MCU audio volume slider/amplifier |
| `[5]` | **`mcu::NWM`** | `0x1080D4` -> `0x101FCC` | `0x104648` | **8** | WiFi LED and NWM reset/power line control |
| `[6]` | **`mcu::HWC`** | `0x107E30` -> `0x102434` | `0x106500` | **17** | Calibration and HW register / MCU hardware info |
| `[7]` | **`mcu::PLS`** | `0x107E88` | `0x106354` -> `0x106A9C` | **9** | Dedicated LED/status control/data for `ps` |
| `[8]` | **`mcu::CDC`** | `0x1081E0` | `0x102124` | **1** | Hardware codec status / interface |

### 3.3 `ptm` (`0004013000002202`) — Power, Battery, Pedometer, Play History and Sleep/Reboot
- **Location:** [`Module-PTM-Battery-and-Pedometer-0004013000002202`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-PTM-Battery-and-Pedometer-0004013000002202) (`ptm_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0xC4DC)`, `.ro=0x0010D000`, `.data=0x0010E000`, `.bss=0x351C`, `prio=0x34`, `deps=[cfg, gpio, i2c, mcu, pdn, spi]`.
- **ACL & special SVCs:** `['mcu::RTC', 'fs:USER', 'cfg:s', 'pxi:mc', 'pm:app', 'pdn:s']`; authorised for `SVC 0x7C` (`KernelSetState`, used together with the 26 SVCs of the binary).
- **`pxi:mc` and `ptmdb:` subsystem:**
  - `ptm_init_subsystems_fs_mcu_cfg` (`0x001007EC`) connects `fs:USER`/`pdn:s`/`mcu::RTC`/`cfg:s` and opens the **`ptmdb:`** file in SysNAND.
  - `ptm_connect_pximc_and_spawn` (`0x001010F8`) connects to the PXI channel **`pxi:mc`** and starts thread `0x10268E` -> `ptm_pximc_state_worker` (`0x00103184`) and `ptm_pximc_ipc_shutdown_or_reset` (`0x00103F6C`) to coordinate sleep, wake and shutdown/reboot with the ARM9.
- **6 services registered in `ptm_main_server_loop` (`0x00100100`, `.rodata 0x10D004`, table `0x10D068`):**
  - `ptm:u` and `ptm:s`: share the Thumb dispatcher `0x109D25` (Switch 1 `0x01..0x0C` + inline `0x0D..0x0F`, commands `0x0401..0x0404`, Switch 2 `0x0405..0x0409`, `0x040A`, Switch 3 `0x0801..0x0818` of **24 cases** via `-0x3F7` using helper `__gnu_thumb1_case_uqi` at `0x00106ECC`).
  - `ptm:sysm`: `0x109A3D` (**15 cases** `0x01..0x0F` — System Manager control / sleep/shutdown notifications).
  - `ptm:sets`: `0x10A8C9` (`0x01 -> 0x10AD84` — RTC/system settings).
  - `ptm:play`: `0x10A91D` (**9 cases** `0x01..0x0F` — usage log/Play History).
  - `ptm:gets`: `0x10A59D` (**8 cases** `0x01..0x0F+` — status queries).

### 3.4 `hid` (`0004013000001D02`) — Keypad, Touch Screen, Accelerometer, Gyroscope and QTM/NFC
- **Location:** [`Module-HID-Buttons-and-Touch-Input-0004013000001D02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-HID-Buttons-and-Touch-Input-0004013000001D02) (`hid_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0x94B4)`, `.ro=0x0010A000`, `.data=0x0010C000`, `.bss=0xBF4`, `prio=0x14`, `deps=[cfg, ptm]`, ACL `['gpio:HID', 'cdc:HID', 'mcu::HID', 'i2c::HID', 'cfg:s', 'ptm:s']`.
- **Hardware MMIO:** Single page `0xFFE1EC46` -> **`0x1EC46000`** (`HID_PAD` physical IO `0x10146000`). `hid_pad_mmio_init_poll` (`0x00101D3C`) reads `*(uint16_t*)0x1EC46000 ^ 0xFFF` (active-low logic for the 12 standard buttons).
- **Service architecture and sampling:**
  - `hid_main_service_server` (`0x00100180`) registers 4 services (`.rodata 0x10A02C..0x10A038`): **`hid:SPVR`**, **`hid:USER`**, **`hid:QTM`**, **`hid:NFC`**, and initialises peripherals in `hid_hw_and_subsystems_init` (`0x00100790`).
  - `hid_spawn_session_worker` (`0x00100A4C`) allocates up to **7 session slots**, creates **5 Kernel events** (Pad, Touch, Gyro, Accel and Debug; skipped at index `3`) and starts the per-session thread `hid_session_recv_entry` (`0x001013D4`) -> `hid_session_loop` (`0x00102178`) -> dispatcher `0x102FC8` (**24 cases** `0x01..0x18`, validating the `hid:SPVR` privilege through `*(param_1 + 1) == 0`).
  - The periodic worker `hid_sampling_sharedmem_worker` (`0x001022CC`) reads PAD (`0x1EC46000`), touch/accelerometer (`cdc:HID`/`i2c::HID`) and gyroscope (calibration in `hid_gyro_calib_load` @ `0x00101AB4`, with fallback `0x08000800` / `0x0334xxxx` if `cfg:s` fails) and writes the ring buffers into HID shared memory.

### 3.5 `gsp` (`0004013000001C02`) — PICA200 GPU, LCD Controllers, VRAM and GX Command Queue
- **Location:** [`Module-GSP-GPU-Service-0004013000001C02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-GSP-GPU-Service-0004013000001C02) (`gsp_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0xC5B8)`, `.ro=0x0010D000`, `.data=0x0010E000`, `.bss=0x18EC`, `prio=0x10`, ACL `['pdn:g', 'i2c::LCD', 'mcu::GPU', 'cfg:s', 'ptm:s']`.
- **Verified hardware MMIO, VRAM and IRQs:**
  - `0xFFE` pages: **`0x1ED02000`** (`LCD`), **`0x1ED0F000`**.
  - `0xFF8/0xFF9` ranges: **`0x1EF00000..0x1EF20000 (RW)`** (GPU PICA/PPF/PSC registers), **`0x1F000000..0x1F600000 (RO)`** (VRAM mapping `0x18000000`, referenced together with `0x08000000..0x08600000` in `gsp_map_vram_and_init_bufs` @ `0x00100248`).
  - Authorised IRQs (`0xE50A552B`, `0xE58B7FFF`): **`40`, `41`, `42`, `43`, `44`, `45`** (PDC0/PDC1 VBlank, PSC0/PSC1 DMA fill, PPF display transfer and P3D GPU finish), bound via `SVC 0x50` at `0x1036A4`.
  - Uses **36 ARM SVCs** including `0x50..0x56` and **`SVC 0x59` (`SetGpuProt`)**.
- **2 services and confirmed dispatchers (`gsp_main_server_and_lcd_irq` @ `0x00100550`):**
  - Handle index `0` -> `gsp_dispatch_vram_or_irq_event` (`0x001010D4`, GPU/LCD hardware IRQ signals).
  - Handle index `1` -> **`gsp::Lcd`** (`.data 0x10E008`, `max_sessions=1`): `gsp_lcd_ipc_dispatcher` (`0x001014FC`, **21 commands** `0x01..0x15` + static-buf `0x1019FC`).
  - Handle index `2` -> **`gsp::Gpu`** (`.data 0x10E004`, `max_sessions=4`): each client instantiates a session thread `gsp_gpu_session_loop` (`0x0010285C`) that serves the dispatcher **`0x00103F24`** (**31 commands** `0x01..0x1F`) and routes the 5 graphics commands (Memory Fill, Display Transfer, Texture Copy, Cache Flush, GX DMA) through `gsp_gx_command_queue_proc` (`0x00103A4C`).
- **New 3DS:** the N3DS build (`0004013020001C02`) additionally uses the service `qtm:sp` and depends on the N3DS-only module `qtm` (`0004013020004202`).

---

## 4. WiFi and Local Network Driver (`nwm`, `0004013000002D02`) `[VERIFIED]`

- **Location:** [`Module-NWM-WiFi-0004013000002D02`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02) (`nwm_friendly.sym` / `symbols_nwm_friendly.r2` / `symbols_nwm_friendly_ghidra.py`)
- **Full ExHeader:**
  - `.text=0x00100000 (0x3CB74)` | `.rodata=0x0013D000 (0x169F4)` | `.data=0x00154000 (0xBD0)` | `.bss=0xAF38` | `stack=0x2000` | `prio=0x26`.
  - Dependencies: `cfg` (`1702`), `mcu` (`1F02`), `ps` (`3102`), `ptm` (`2202`).
  - **Service ACL:** `['cfg:u', 'mcu::NWM', 'ps:ps', 'ptm:s']`.

### 4.1 Underlying hardware: SDIO2 controller, kernel DMA, radio kill-switch and the Atheros AR6014 chip

1. **MMIO ranges mapped in the ExHeader (`0xFF8/0xFF9`):**
   - **`0x1EC22000..0x1EC23000 (RW)`** and **`0x1EE22000..0x1EE23000 (RW)`** (registers of the WLAN SDIO2 controller and its secondary window).
   - Verified directly at `0x133a0c` (`DAT_00133abc = 0x1EC22000` when `param_1 == 2`, `DAT_00133ac0 = 0x1EC00000` for the alternative branch) and in `nwm_sdio_mmio_helper_1338f8` / `nwm_sdio_mmio_helper_133a0c` (`0x1338F8`, `0x133A0C`, `0x133AEC`, `0x133B08`, `0x133B38`).
2. **Verified interrupts and RF power:**
   - **ExHeader IRQs (`0xE8107FFF`):** **`64` (`0x40`)** and **`65` (`0x41`)**. In [`0x12442c.c`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02/pseudocode/functions/0x12442c.c) (`nwm_sdio_irq_bind`), when the port is SDIO2 (`*(char*)(iVar3 + 0x24) == 2`), it passes `uVar2 = 0x40` (IRQ `64`) to `0x133798` -> `0x127642` -> **`nwm_svc_0x50_BindInterrupt_13c938`** (`0x13C938`, `swi 0x50`).
   - **Hardware radio on/off:** `nwm` is authorised for **`SVC 0x5A` (`SetWifiEnabled`)**, whose verified implementation in Kernel11 is `k11_hw_set_wifi_enabled` (`0xFFF06D94`, `svc_0x5A_SetWifiEnabled` @ `0xFFF0485C`), and in `nwm` it appears invoked at `0x12e618`/`SVC` (`SVCs used` lists exactly **`0x5A`** and the DMA set **`0x55, 0x56, 0x57, 0x58`**). The WiFi LED/hardware state on the PMIC is additionally controlled through the **`mcu::NWM`** session (`0x13D4F4`).
3. **SDIO ↔ AR6014 DMA transfers (`[VERIFIED]` + Atheros AR6K `[PUBLIC 3DS KNOWLEDGE]`):**
   - `nwm_sdio_cmd_submit` (`0x00124854`) sends SDIO commands (`CMD52`/`CMD53`) and configures the controller; `nwm_sdio_block_xfer_0x200` (`0x00126168`) runs block transfers (`0x100`/`0x200` bytes).
   - Uses the 4 Kernel11 DMA SVCs (`SVC 0x55 StartInterProcessDma`, `0x56 StopDma`, `0x57 GetDmaState`, `0x58 RestartDma`) together with cache invalidate/clean (`SVC 0x52`/`0x53`), verified in functions `0x11c6b8.c`, `0x11d2f8.c`, `0x1257dc.c`, `0x12c3be.c` and `0x137ea8.c`.
4. **AR6014 stack (`sdio_hcd` / `HTC` / `WMI`) and embedded WPA supplicant (`[VERIFIED]`):**
   - Initialisation of the SDIO host driver `'sdio_hcd'` (`0x12575C`) in [`0x1256b0.c`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02/pseudocode/functions/0x1256b0.c) (`block=0x200`, `500` ms timeout).
   - Embedded messages verified in `.code`/`.rodata`: `'SDIO Bus Driver: SD Switch Status Block Error'` (`0x116658`, `0x11CBF4`), `'BAD HTC Recv PKT'` (`0x11C150`), QoS queues `'WMI CONTROL'` (`0x12F660`), `'WMI DATA BE'`, `'WMI DATA BK'`, `'WMI DATA VI'`, `'WMI DATA VO'` (`0x12F670..0x12F694`), `'sdio_wlan'` (`0x15489C`), `'MACFilter'` (`0x141317`).
   - **Verified WiFi supplicant:** `'wpa_supplicant v0.5.10-Devicescape'` (`0x13F3DA`), `'Devicescape Agent Supplicant 2.5'` (`0x13F3B9`) with a BSD notice at `0x13F320`. Implements **RFC 3394 AES Key Unwrap** decryption for WPA/WPA2 keys (`0x12e618.c`, 6-round loop `5..0` checking IV `0xA6 x 8`). Reads NVRAM/WiFi configuration via `cfg:u`/`cfg:i`/`cfg:s` (`0x13F31A..0x13F40C`) and derives randomness/cryptography through **`ps:ps`** (`0x13D168`, `0x13E2D6`).

### 4.2 The 7 IPC services of `nwm` and their dual concurrency model (`nwm_main_server_loop` @ `0x001016F8`)

In [`0x1016f8.c`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02/pseudocode/functions/0x1016f8.c), `nwm` reads the service configuration table at `.rodata 0x13D0F8`:
- Table of service strings (`0x13D120..0x13D156`), flags (`0x13D0FC`: `[1, 1, 1, 1, 0, 1, 0, 0]`) and per-session maximum limits.
- When `flag == 0` (`nwm::CEC`, `nwm::TST`), it accepts sessions in the main loop itself. When `flag == 1` and index != `5`, it places the session object in worker queues (`nwm_session_slot_dispatch` @ `0x00102118`).
- **Special case index `5` (`nwm::EXT`):** in `0x1016f8.c` lines `130..163`, it looks for a free slot (`max 2` in `nwm_ext_find_free_slot` @ `0x001045B0`) and **spawns a dedicated thread (`SVC CreateThread`)** with entry point `nwm_ext_thread_entry` (`0x00102428`), private loop `nwm_ext_session_loop` (`0x0010759C`), `0x300`-byte static TLS buffer (`nwm_ext_tls_static_buf_setup` @ `0x001094FC`) and its own dispatcher `0x109580`.

| Index | Service | Flag / Thread | Max sessions | On-Connect routine (`0x1233B8`) | IPC dispatcher (`0x12334C`) | Active cases and role |
|-------|---------|---------------|--------------|---------------------------------|-----------------------------|-----------------------|
| `[0]` | **`nwm::UDS`** | Worker pool | **2** | `0x10497D` (`nwm_uds_on_connect`) | `0x105B01` (`nwm_uds_ipc_dispatcher`) | **16** (`0x01..0x10`): wireless DS/3DS local multiplayer (beacon, nodes, DataFrame) |
| `[1]` | **`nwm::INF`** | Worker pool | **4** | `0x104995` (`nwm_inf_on_connect`) | `0x105E69` (`nwm_inf_ipc_dispatcher`) | **13** (`0x01..0x0D`): Infrastructure WiFi management used by `ac` (`0004013000002402`) |
| `[2]` | **`nwm::SOC`** | Worker pool | **2** | `0x10492F` (`nwm_soc_on_connect`) | `0x1051E1` (`nwm_soc_ipc_dispatcher`) | **44** (`0x01..0x2C`): IP/socket data plane towards the `socket` SysModule (`0004013000002E02`) |
| `[3]` | **`nwm::SAP`** | Worker pool | **4** | `0x10490D` (`nwm_sap_on_connect`) | `0x1049CD` (`nwm_sap_ipc_dispatcher`) | **30** (`0x01..0x1E`): local access point / WEP-WPA SoftAP |
| `[4]` | **`nwm::CEC`** | Main loop | **6** | `0x10492D` | `0x10508D` (`nwm_cec_ipc_dispatcher`) | **9** (`0x01..0x09`): low-level StreetPass radio consumed by `cecd` |
| `[5]` | **`nwm::EXT`** | **Dedicated thread** (`0x102429`) | **2** | `NULL` (uses `0x1094FC` in thread) | `NULL` -> thread `0x10759C` -> `0x109581` | **35** cmds: extended network-state control (`ndm`, `mp`, `friends`, `nfc`, `ns`) |
| `[6]` | **`nwm::TST`** | Main loop | **1** | `0x105AC9` (`nwm_tst_on_connect`) | `0x106159` (`nwm_tst_ipc_dispatcher`) | **70** (`0x01..0x46`): RF diagnostics, factory tests and calibration |

---

## 5. StreetPass Antenna (`cecd`, `0004013000002602` + `nwm::CEC` interface) `[VERIFIED]`

- **Location:** [`Module-CECD-StreetPass-0004013000002602`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602) (`cecd_friendly.sym` / `symbols_cecd_friendly.r2` / `symbols_cecd_friendly_ghidra.py`)
- **Full ExHeader:**
  - `.text=0x00100000 (0x21EA4)` | `.rodata=0x00122000 (0x145C)` | `.data=0x00124000 (0x135C)` | `.bss=0x94E8` | `stack=0x4000` | `prio=0x3C`.
  - Dependencies: `cfg` (`1702`), `ptm` (`2202`), `nwm` (`2D02`), `friends` (`3202`).
  - **Service ACL:** `['nwm::CEC', 'fs:USER', 'ptm:s', 'ps:ps', 'cfg:s', 'frd:u']`.

### 5.1 Complete StreetPass flow (`cecd` ↔ `nwm::CEC` ↔ `fs:USER` ↔ `ps:ps` ↔ `ndm`)

1. **Session and storage initialisation (`cecd_main_server_loop` @ `0x00100154`):**
   - Registers the 3 services of the `.rodata 0x122328` table with the dispatcher table at `0x122340`:
     - **`cecd:u`** (`max_sessions=4`, dispatcher **`0x0011A5BD`**): **22** active cases (`0x01..0x12`, `0x1E..0x21`) for games/applications (read/write OutBox/InBox, launch StreetPass tasks).
     - **`cecd:s`** (`max_sessions=4`, dispatcher **`0x0011AF51`**): **19** active cases (`0x01..0x12`, `0x1E` + inline cases `0x1F..0x21`, `0x040A`, `0x040F+`) for system processes (`boss`, `news`, Home Menu).
     - **`cecd:ndm`** (`max_sessions=1`, dispatcher **`0x0011AD69`**): **8** cases (`0x01..0x08`) called exclusively by **`ndm` (`0004013000002B02`)** to arbitrate the antenna in idle/spotpass (`NDM_STATUS_WORKING`, `NDM_STATUS_IDLE`, `NDM_STATUS_SUSPENDING`, `NDM_STATUS_SUSPENDED`, `NDM_RESUME`, `NDM_SUSPEND`, `NDM_SUSPEND_IMMEDIATE`, `OVER_BOSS`, `OVER_BOSS_FORCE`, `OVER_BOSS_FORCE_WAIT` @ `0x124B08..0x124E74`).
   - Instantiates 3 internal threads/queues with parameters `0x100`, `0x105` and `0x106` (verified in [`0x100154.c`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602/pseudocode/functions/0x100154.c) lines `60..89`).
2. **NAND mailbox store (`cecd_init_fs_session` @ `0x0010079C`):**
   - Opens a **`fs:USER`** session (`0x122437`) to the module's system save file to operate the CEC paths verified in `code.bin`:
     - Root and temporaries: **`data:/CEC`**, **`data:/CEC/TMP`**, `data:/CEC/test`
     - Global metadata: **`data:/CEC/MBoxList____`**, **`data:/CEC/SessionId___`**, **`data:/CEC/MacFilter___`**, **`eventlog.dat`**
     - Per game box (CEC `TitleID`): **`MBoxInfo____`**, **`MBoxData`**, **`BoxInfo_____`**, **`InBox___`** and **`OutBox__`** (`0x109B54..0x1136C0`).
   - Protects/signs CEC messages through **`ps:ps`** (`0x1222AC`).
3. **Hardware antenna via dual `nwm::CEC` session (`cecd_init_nwm_cec_sessions` @ `0x00102700`):**
   - In [`0x102700.c`](file:///home/skels/3ds-reversing/o3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602/pseudocode/functions/0x102700.c), it opens **2 parallel session handles** (`DAT_00102744[0]` and `DAT_00102744[1]`) to the **`nwm::CEC`** port (`0x12244C`) through `0x1040e0`. If the second handle fails, it closes the first cleanly and in order.
   - Issues IPC requests to `nwm::CEC` (`0x105CD4..0x10601C`), verified in `cecd_friendly.sym` with exact headers: `cecd_nwmc_client_cmd_0x06` (`0x00105E9A`, `0W+2T`), `cecd_nwmc_client_cmd_0x0B` (`0x00105E5A`, `1W+2T`), `cecd_nwmc_client_cmd_0x0C` (`0x00105DDA`, `1W+2T`), `cecd_nwmc_client_cmd_0x16` (`0x00105ED6`, `1W+2T`), `cecd_nwmc_client_cmd_0x1C` (`0x00105E1A`, `1W+2T`) and `cecd_nwmc_client_cmd_0x1D` (`0x00105F16`, `0W+0T`), plus `cecd_nwmc_client_cmd_1_recv_or_tx` (`0x00105CD4`).
   - The **`nwm::CEC`** server (`0x0010508C`, **9 cases**) handles the periodic transmission and scanning of 802.11 IE/StreetPass frames directly on the SDIO2 AR6014 hardware when `ndm`/`cecd:ndm` authorises the radio window in active console or Sleep mode.

---

## 6. Quick Use of Tables and Ingestion in `radare2` / `Ghidra` `[VERIFIED]`

All tables keep the binary standard intact (`0 HYPOTHESIS`) and support non-destructive loading:

```bash
# Example: NWM WiFi driver (0004013000002D02, ARM base 0x00100000)
r2 -a arm -b 32 -m 0x00100000 \
  -i decrypted_binaries/Module-NWM-WiFi-0004013000002D02/symbols_nwm_friendly.r2 \
  decrypted_binaries/Module-NWM-WiFi-0004013000002D02/exefs_dir/code.bin

# Example: embedded FIRM module 'loader' (NOTE: real base 0x14000000)
r2 -a arm -b 32 -m 0x14000000 \
  -i decrypted_binaries/firm_modules/loader/symbols_loader_friendly.r2 \
  decrypted_binaries/firm_modules/loader/code.bin
```

For **Ghidra 12.2+**, import `code.bin` with architecture `ARM:LE:32:v6k`, `Image Base = 0x00100000` (or **`0x14000000`** for `firm_modules/loader`), run Auto-Analyze and launch the `symbols_<mod>_friendly_ghidra.py` script included in the corresponding folder.
