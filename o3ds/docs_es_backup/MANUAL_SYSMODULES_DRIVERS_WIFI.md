# Manual Técnico de SysModules Base, Drivers de Hardware, WiFi (`nwm`) y Antena StreetPass (`cecd`) — Nintendo 3DS

> ⚠️ **ADVERTENCIA CRÍTICA DE SEGURIDAD HARDWARE Y NAND — LÉASE ANTES DE TOCAR CONSOLA REAL**
>
> **SIEMPRE realice un respaldo completo de la NAND y de los archivos críticos de recuperación de su consola ANTES de modificar, inyectar, parchear o probar código contra SysModules críticos (`mcu`, `ptm`, `i2c`, `pxi`, `nwm`, `cecd`, `gsp`, `fs`, `pm`).**
> - Los SysModules `mcu` (`i2c::MCU`) y `ptm` (`pxi:mc`) controlan directamente el microcontrolador PMIC/reset/apagado de hardware y contadores persistentes RTC/NVRAM; un comando erróneo en hardware real puede forzar apagados inmediatos, corrupción de configuración (`ptmdb:`, RTC/MCU) o fallos de arranque.
> - El SysModule `nwm` opera directamente sobre el controlador SDIO2 del chip WiFi Atheros AR6014 mediante DMA kernel (`SVC 0x55..0x58`), control eléctrico de radio (`SVC 0x5A`) y `cfg:u`/`ps:ps`/`mcu::NWM`, y puede saturar buffers IPC/DMA o colgar la consola si se envían payloads corruptos.
> - **Requisitos mínimos antes de experimentar:** respaldo completo de SysNAND (p. ej. vía **GodMode9**), copia externa de `movable.sed`, `otp.bin`, `seeds` / `essential.exefs`, copia intacta de `FIRM`/`arm9.bin`/`arm11.bin`, y un método de recuperación garantizado (**ntrboot** + Boot9strap o **hardmod / programador NAND**). Probar siempre primero sobre dumps/emulación antes que en consola real.

---

> **Estado de evidencia:** `0 HYPOTHESIS` `[VERIFICADO EN ESTE REPO]` — Todos los símbolos, firmas C, mapas ExHeader, registros MMIO, interrupciones IRQ, SVCs ARM reales, servicios registrados y tablas IPC documentados en este manual fueron verificados directamente sobre los binarios descifrados (`code.bin`, `exheader.bin`, `arm11.bin`), su desensamblado ARM/Thumb (`radare2 5.9.8`) y su decompilación C completa (`REA + Ghidra 12.2`). Las pocas contextualizaciones generales de hardware llevan etiqueta explícita `[CONOCIMIENTO PÚBLICO 3DS]`.

---

## 1. Aclaración Crítica de Rutas: Carpetas `Modulo-*` vs Identidad Real en `exheader.bin` `[VERIFICADO]`

Durante la organización de [`binarios_descifrados/`](file:///home/skels/3ds-reversing/binarios_descifrados), las carpetas originales `SysModule_<TitleID>` fueron renombradas a `Modulo-<Prefijo>-<TitleID>`, **pero varios prefijos descriptivos quedaron desplazados respecto al verdadero programa declarado en los primeros 8 bytes de `exheader.bin`**. Nunca debe asumirse el módulo por el nombre de la carpeta; el ancla autoritativa es siempre el **TitleID + `exheader.bin[0:8]`**.

### 1.1 Mapa Exacto de los 7 SysModules Analizados (`0 HYPOTHESIS`)

| Identidad Real (`exheader.bin[0:8]`) | TitleID | Carpeta en Disco (Real) | Pseudocódigos C (`Ghidra 12.2`) | Tabla `.sym` (`0 HYPOTHESIS`) |
|--------------------------------------|---------|-------------------------|---------------------------------|--------------------------------|
| **`gsp`** | `0004013000001C02` | [`Modulo-GPIO-Pines-Entrada-Salida-0004013000001C02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-GPIO-Pines-Entrada-Salida-0004013000001C02) | **336** archivos `.c` | [`gsp_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-GPIO-Pines-Entrada-Salida-0004013000001C02/gsp_friendly.sym) (**352**: 147 `CONFIRMED`, 205 `EVIDENCE_BASED`) |
| **`hid`** | `0004013000001D02` | [`Modulo-I2C-Bus-Hardware-0004013000001D02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-I2C-Bus-Hardware-0004013000001D02) | **250** archivos `.c` | [`hid_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-I2C-Bus-Hardware-0004013000001D02/hid_friendly.sym) (**263**: 97 `CONFIRMED`, 166 `EVIDENCE_BASED`) |
| **`i2c`** | `0004013000001E02` | [`Modulo-MCU-Microcontrolador-Energia-0004013000001E02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-MCU-Microcontrolador-Energia-0004013000001E02) | **142** archivos `.c` | [`i2c_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-MCU-Microcontrolador-Energia-0004013000001E02/i2c_friendly.sym) (**153**: 59 `CONFIRMED`, 94 `EVIDENCE_BASED`) |
| **`mcu`** | `0004013000001F02` | [`Modulo-PDN-Energia-y-Relojes-0004013000001F02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-PDN-Energia-y-Relojes-0004013000001F02) | **243** archivos `.c` | [`mcu_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-PDN-Energia-y-Relojes-0004013000001F02/mcu_friendly.sym) (**257**: 87 `CONFIRMED`, 170 `EVIDENCE_BASED`) |
| **`ptm`** | `0004013000002202` | [`Modulo-PTM-Bateria-y-Podometro-0004013000002202`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-PTM-Bateria-y-Podometro-0004013000002202) | **624** archivos `.c` | [`ptm_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-PTM-Bateria-y-Podometro-0004013000002202/ptm_friendly.sym) (**769**: 59 `CONFIRMED`, 710 `EVIDENCE_BASED`) |
| **`cecd`** | `0004013000002602` | [`Modulo-CECD-StreetPass-0004013000002602`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-CECD-StreetPass-0004013000002602) | **1,323** archivos `.c` | [`cecd_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-CECD-StreetPass-0004013000002602/cecd_friendly.sym) (**1,676**: 58 `CONFIRMED`, 1,618 `EVIDENCE_BASED`) |
| **`nwm`** | `0004013000002D02` | [`Modulo-NWM-WiFi-0004013000002D02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02) | **2,039** archivos `.c` | [`nwm_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02/nwm_friendly.sym) (**2,784**: 87 `CONFIRMED`, 2,697 `EVIDENCE_BASED`) |

> **Otros prefijos desplazados observados en `binarios_descifrados/Modulo-*` (`exheader.bin[0:8]` verificados):**
> `0004013000001502`/`1503` = **`am`** (en `Modulo-FS-*`), `1602` = **`camera`** (`Modulo-PM-*`), `1702`/`1703` = **`cfg`** (`Modulo-SM-*`), `1802`/`1803` = **`codec`** (`Modulo-PXI-*`), `1A02`/`1A03` = **`dsp`** (`Modulo-NS-*`), `1B02`/`1B03` = **`gpio`** (`Modulo-CFG-*`), `2002` = **`mic`** (`Modulo-SPI-*`), `2102`/`2103` = **`pdn`** (`Modulo-PS-*`), `2302`/`2303` = **`spi`** (`Modulo-CAM-*`), `2402`/`2403` = **`ac`** (`Modulo-CSND-*`), `2702`/`2703` = **`csnd`** (`Modulo-DSP-*`), `2902`/`2903` = **`http`** (`Modulo-HID-*`), `3102`/`3103` = **`ps`** (`Modulo-BOSS-*`), `3402` = **`boss`** (`Modulo-L2B-*`), `3502` = **`news`** (`Modulo-MVD-*`). Cada uno de los 7 análisis de esta guía generó además scripts listos para carga directa: `symbols_<mod>_friendly.r2` y `symbols_<mod>_friendly_ghidra.py`.

---

## 2. Los 5 Módulos Integrados en FIRM (`arm11.bin` Sección 0) `[VERIFICADO]`

Extraídos de [`binarios_descifrados/kernel/arm11.bin`](file:///home/skels/3ds-reversing/binarios_descifrados/kernel/arm11.bin) en [`binarios_descifrados/firm_modulos/`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos) (orden real de carga por `kernel11_launch_firm_sysmodules` en Kernel11: `pxi`, `fs`, `pm`, `sm`, `loader`; ExHeaders sin dependencias externas `deps=[]`).

| Módulo | TitleID | Base `.text` / `.ro` / `.data` (`bss`) | Prioridad ExHeader | Capacidades Hardware / ACL | Símbolos (`0 HYP`) y C Ghidra | Rutas |
|--------|---------|------------------------------------------|--------------------|----------------------------|-------------------------------|-------|
| **`pxi`** | `0004013000001402` | `0x00100000` (`0x3844`) / `0x104000` / `0x105000` (`0x196D8`) | `0x2D` | MMIO `0x1EC63000` (`0xFFE1EC63`), IRQs `80..83` (`0xEA146953`), `SVC 0x50/0x51` | **111** (**77** `CONFIRMED`, **34** `EVIDENCE_BASED`), **103** `.c` | [`pxi/`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/pxi/pxi_friendly.sym) |
| **`sm`** | `0004013000001002` | `0x00100000` (`0x4190`) / `0x105000` / `0x106000` (`0x5148`) | `0x34` | Registra puertos kernel `'srv:'` y `'srv:pm'`; sin IO/IRQ ni ACL | **107** (**67** `CONFIRMED`, **40** `EVIDENCE_BASED`), **100** `.c` | [`sm/`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/sm/sm_friendly.sym) |
| **`loader`** | `0004013000001302` | **`0x14000000`** (`0x3898`) / `0x14004000` / `0x14005000` (`0x1104`) | `0x34` | ACL `fs:LDR`; usa `SVC 0x73` (`CreateCodeSet`) y `SVC 0x75` (`CreateProcess`) | **115** (**78** `CONFIRMED`, **37** `EVIDENCE_BASED`), **110** `.c` | [`loader/`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/loader/loader_friendly.sym) |
| **`pm`** | `0004013000001202` | `0x00100000` (`0x5F38`) / `0x106000` / `0x107000` (`0x3804`) | `0x34` | ACL `fs:REG`; `SVC 0x76..0x79`, `0x7C` (`KernelSetState`), `0x60` | **142** (**97** `CONFIRMED`, **45** `EVIDENCE_BASED`), **135** `.c` | [`pm/`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/pm/pm_friendly.sym) |
| **`fs`** | `0004013000001102` | `0x00100000` (`0x33FB0`) / `0x134000` / `0x136000` (`0x32A28`) | `0x2E` | MMIO `0x1EC01000`, `0x1EE01000`; DMA/Cache `SVC 0x53..0x57` | **1,572** (**153** `CONFIRMED`, **1,419** `EVIDENCE_BASED`), **1,568** `.c` | [`fs/`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/fs/fs_friendly.sym) |

### 2.1 Roles e Invariantes Confirmados en Código C
- **`pxi` (`0004013000001402`):** Puente hardware ARM11 ↔ ARM9 sobre MMIO `0x1EC63000` (física `0x10163000`). Registra 9 servicios IPC (`pxi:mc`, `pxi:dev`, `pxi:am9`, `pxi:ps9`, `PxiFS0/1/B/R`, `PxiPM`), enlaza IRQs `80`, `82` (`RECV`) y `83` (`SEND`) vía `SVC 0x50` (`0x102BD4`), y serializa paquetes TX FIFO con `pxi_send_command_arm11_to_arm9` (`0x101CC4`) y 3 hilos (`0x100DA8`, `0x100DBC`, `0x100DC8`). Especificación bit-a-bit completa en [`PROTOCOLO_PXI.md`](file:///home/skels/3ds-reversing/PROTOCOLO_PXI.md).
- **`sm` (`0004013000001002`):** Gestor central de servicios (`sm_server_main_loop` @ `0x001000A0`). Crea puertos `'srv:'` y `'srv:pm'`, parsea blobs ACL de ExHeader en `sm_exheader_acl_table_parse` (`0x00101204`), verifica permisos u64 por PID en `sm_check_process_service_acl` (`0x0010189C`), gestiona búsqueda por nombre `1..8` bytes en `sm_find_registered_service_or_port` (`0x00102030`) y despierta waiters vía cola circular de 16 notificaciones (`sm_notif_ring_push` @ `0x00101994`).
- **`loader` (`0004013000001302`):** Ejecuta en base especial `0x14000000`. Registra servicio `'Loader'` (`ldr_server_main_loop` @ `0x14000054`), conecta a `'PxiPM'`, `'fs:LDR'` y `'fs:USER'` (`0x140004A4`), descomprime `.code` comprimido en memoria con Nintendo BLZ (`ldr_blz_decompress_in_place` @ `0x14000E28`, footer `-4/-8/-12`), lee secciones ExeFS (`0x1400113C`), delega validación a `PxiPM` (`ldr_RegisterProgram` @ `0x14000F80`) e instancia procesos ARM11 vía `SVC 0x73` (`0x14000EBC`) + `SVC 0x75` (`0x14000ED8`).
- **`pm` (`0004013000001202`):** Registra `pm:app` y `pm:dbg` (`pm_server_main_loop` @ `0x00100084`). Inicializa el layout de memoria `APPMEMALLOC` y ResourceLimits vía `GetSystemInfo` + `SVC 0x77/0x78/0x79/0x7C` (`pm_init_builtin_and_appmemalloc` @ `0x00100524`), resuelve listas de dependencias desde ExHeader (`pm_build_dependency_list` @ `0x00101CFC` y `pm_launch_dependency_titles` @ `0x00101ED8`) y lanza procesos coordinándose con `Loader` y `fs:REG` (`pm_launch_title_ex` @ `0x0010167C`, usando `SVC 0x76` para terminación).
- **`fs` (`0004013000001102`):** Servidor de almacenamiento ARM11 (`fs_main_server_init` @ `0x00122AD0`). Mapea páginas MMIO `0x1EC01000` y `0x1EE01000` (`CTR_CARD` / controlador FS), registra `fs:USER`, `fs:LDR`, `fs:REG` (`0x00123198`) y abre 4 canales PXI independientes hacia ARM9 (`PxiFS0`, `PxiFS1`, `PxiFSB`, `PxiFSR`) usando stubs verificados como `fs_pxifs_swi32_cmd_0x47_n1_t2` (`0x00124CE4`, 1W+2T -> ARM9 `0x08042008`) y `fs_pxifs_swi32_cmd_0x4F_n2_t0` (`0x00125450`, 2W -> ARM9 `0x0806B424`), protegidos con mutex recursivos (`fs_reclock_lock` @ `0x0011E2E0`) y verificaciones SHA (`fs_sha11_oneshot_hash` @ `0x0011D104`).

---

## 3. Los 5 SysModules de Hardware, Video, Entrada, Bus I2C y Energía `[VERIFICADO]`

### 3.1 `i2c` (`0004013000001E02`) — Bus Maestro I2C Multidominio
- **Ubicación:** [`Modulo-MCU-Microcontrolador-Energia-0004013000001E02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-MCU-Microcontrolador-Energia-0004013000001E02) (`i2c_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0x4740)`, `.ro=0x00105000`, `.data=0x00106000`, `.bss=0x2200`, `prio=0x14`, `deps=[]`, ACL clientes `=[]`.
- **MMIO & IRQs Hardware Verificados:**
  - 3 controladores I2C mapeados vía `0xFFE`: **`0x1EC61000`**, **`0x1EC44000`**, **`0x1EC48000`** (`.rodata 0x105040..0x105054` almacena base `+0` y registro de control `+1`).
  - IRQs autorizadas por descriptor `0xEA956E7F`: **`84`**, **`85`**, **`92`** (enlazadas con `SVC 0x50` en `0x1018F8` / sitio ARM `0x101900`, inicializadas en `i2c_hw_init_controllers_irqs` @ `0x00102508`).
- **Servicios Registrados y Arquitectura Confirmada:**
  - `.rodata 0x105000..0x10503C` y `.data 0x106004..0x10601C` declaran **7 puertos**: `i2c::MCU`, `i2c::CAM`, `i2c::LCD`, `i2c::DEB`, `i2c::HID`, `i2c::IR`, `i2c::EEP`.
  - `.data 0x106020..0x106038` lanza **7 hilos worker ARM32** (`0x1044A4..0x1046E0`, `r0 = 0..6`) que entran al bucle común `i2c_service_session_loop` (`0x00102148`) y al dispatcher **`i2c_ipc_dispatcher`** (`0x00101AC4`, **21 casos** `0x01..0x15`).
  - **Control de acceso por dispositivo:** `i2c_check_bus_device_permission` (`0x00102BC0`) filtra qué servicio `0..6` puede dirigir qué índice `dev_id < 0xF` en la tabla `.rodata 0x105058..0x1050A0` (direcciones esclavo hardware verificadas: `0x4A`, `0x7A`, `0x78`, `0x40`, `0xD6`, `0xD0`, `0xA4`...) y las operaciones reales se ejecutan sobre FIFO/control (`reg+0`, `reg+1`: bits STOP `0xC5`, SELECT `0xE1`, WRITE `0xC2`, READ `0xC0`, ACK `&0x10 >> 4`) en `i2c_hw_bus_transfer` (`0x0010267C`).

### 3.2 `mcu` (`0004013000001F02`) — Proxy de Microcontrolador, Energía y RTC
- **Ubicación:** [`Modulo-PDN-Energia-y-Relojes-0004013000001F02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-PDN-Energia-y-Relojes-0004013000001F02) (`mcu_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0x8290)`, `.ro=0x00109000`, `.data=0x0010A000`, `.bss=0x2DE8`, `prio=0x14`, `deps=['0004013000001B02' (gpio), '0004013000001E02' (i2c)]`.
- **ACL de Servicios:** `['gpio:MCU', 'i2c::MCU', 'ptm:s']`. No mapea MMIO ni IRQs propios: delega todas las lecturas/escrituras PMIC sobre `i2c::MCU` + línea de interrupción `gpio:MCU` en `mcu_hw_and_i2c_init` (`0x0010086C`).
- **Tabla de 9 Servicios y Dispatchers Verificados (`.data 0x10A034..0x10A078`):**

| Índice | Servicio | Hilo Worker ARM32 | Dispatcher Destino | Comandos Activos | Función Principal |
|--------|----------|-------------------|--------------------|------------------|-------------------|
| `[0]` | **`mcu::CAM`** | `0x107DD8` | `0x1022D8` | **2** | Energía / LED cámara |
| `[1]` | **`mcu::GPU`** | `0x107EE0` -> `0x101E74` | `0x1024E0` | **14** | Backlight LCD, LEDs 3D/estado GPU |
| `[2]` | **`mcu::HID`** | `0x107FDC` -> `0x101F20` | `0x1028D4` | **15** | Eventos botones HOME/POWER/WiFi/volumen/tapa |
| `[3]` | **`mcu::RTC`** | `0x10812C` -> `0x102078` | `0x1048F0` | **92** | Reloj hardware RTC, alarmas, batería, reset/poweroff PMIC |
| `[4]` | **`mcu::SND`** | `0x108238` | `0x10222C` -> `0x106400` | **3** | Slider/amplificador volumen audio MCU |
| `[5]` | **`mcu::NWM`** | `0x1080D4` -> `0x101FCC` | `0x104648` | **8** | Control LED WiFi y línea reset/alimentación NWM |
| `[6]` | **`mcu::HWC`** | `0x107E30` -> `0x102434` | `0x106500` | **17** | Calibración y registro HW / hardware info MCU |
| `[7]` | **`mcu::PLS`** | `0x107E88` | `0x106354` -> `0x106A9C` | **9** | Control/datos dedicados de LED/estado para `ps` |
| `[8]` | **`mcu::CDC`** | `0x1081E0` | `0x102124` | **1** | Estado / interfaz codec hardware |

### 3.3 `ptm` (`0004013000002202`) — Energía, Batería, Podómetro, Play History y Sleep/Reboot
- **Ubicación:** [`Modulo-PTM-Bateria-y-Podometro-0004013000002202`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-PTM-Bateria-y-Podometro-0004013000002202) (`ptm_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0xC4DC)`, `.ro=0x0010D000`, `.data=0x0010E000`, `.bss=0x351C`, `prio=0x34`, `deps=[cfg, gpio, i2c, mcu, pdn, spi]`.
- **ACL & SVCs Especiales:** `['mcu::RTC', 'fs:USER', 'cfg:s', 'pxi:mc', 'pm:app', 'pdn:s']`; autorizado a `SVC 0x7C` (`KernelSetState`, usado junto a los 26 SVCs del binario).
- **Subsistema `pxi:mc` y `ptmdb:`:**
  - `ptm_init_subsystems_fs_mcu_cfg` (`0x001007EC`) conecta `fs:USER`/`pdn:s`/`mcu::RTC`/`cfg:s` y abre archivo **`ptmdb:`** en SysNAND.
  - `ptm_connect_pximc_and_spawn` (`0x001010F8`) conecta al canal PXI **`pxi:mc`** y lanza el hilo `0x10268E` -> `ptm_pximc_state_worker` (`0x00103184`) y `ptm_pximc_ipc_shutdown_or_reset` (`0x00103F6C`) para coordinar sleep, wake y shutdown/reboot con ARM9.
- **6 Servicios Registrados en `ptm_main_server_loop` (`0x00100100`, `.rodata 0x10D004`, tabla `0x10D068`):**
  - `ptm:u` y `ptm:s`: comparten el dispatcher Thumb `0x109D25` (Switch 1 `0x01..0x0C` + inline `0x0D..0x0F`, comandos `0x0401..0x0404`, Switch 2 `0x0405..0x0409`, `0x040A`, Switch 3 `0x0801..0x0818` de **24 casos** vía `-0x3F7` usando helper `__gnu_thumb1_case_uqi` en `0x00106ECC`).
  - `ptm:sysm`: `0x109A3D` (**15 casos** `0x01..0x0F` — control System Manager / notificaciones sleep/apagado).
  - `ptm:sets`: `0x10A8C9` (`0x01 -> 0x10AD84` — ajustes RTC/sistema).
  - `ptm:play`: `0x10A91D` (**9 casos** `0x01..0x0F` — registro de uso/Play History).
  - `ptm:gets`: `0x10A59D` (**8 casos** `0x01..0x0F+` — consultas de estado).

### 3.4 `hid` (`0004013000001D02`) — Keypad, Touch Screen, Acelerómetro, Giroscopio y QTM/NFC
- **Ubicación:** [`Modulo-I2C-Bus-Hardware-0004013000001D02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-I2C-Bus-Hardware-0004013000001D02) (`hid_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0x94B4)`, `.ro=0x0010A000`, `.data=0x0010C000`, `.bss=0xBF4`, `prio=0x14`, `deps=[cfg, ptm]`, ACL `['gpio:HID', 'cdc:HID', 'mcu::HID', 'i2c::HID', 'cfg:s', 'ptm:s']`.
- **MMIO Hardware:** Página única `0xFFE1EC46` -> **`0x1EC46000`** (`HID_PAD` IO físico `0x10146000`). `hid_pad_mmio_init_poll` (`0x00101D3C`) lee `*(uint16_t*)0x1EC46000 ^ 0xFFF` (lógica activa en bajo para los 12 botones estándar).
- **Arquitectura de Servicios y Muestreo:**
  - `hid_main_service_server` (`0x00100180`) registra 4 servicios (`.rodata 0x10A02C..0x10A038`): **`hid:SPVR`**, **`hid:USER`**, **`hid:QTM`**, **`hid:NFC`**, e inicializa periféricos en `hid_hw_and_subsystems_init` (`0x00100790`).
  - `hid_spawn_session_worker` (`0x00100A4C`) asigna hasta **7 slots de sesión**, crea **5 eventos Kernel** (Pad, Touch, Gyro, Accel y Debug; omite en índice `3`) y lanza el hilo por sesión `hid_session_recv_entry` (`0x001013D4`) -> `hid_session_loop` (`0x00102178`) -> dispatcher `0x102FC8` (**24 casos** `0x01..0x18`, validando privilegio `hid:SPVR` mediante `*(param_1 + 1) == 0`).
  - El worker periódico `hid_sampling_sharedmem_worker` (`0x001022CC`) lee PAD (`0x1EC46000`), táctil/acelerómetro (`cdc:HID`/`i2c::HID`) y giroscopio (calibración en `hid_gyro_calib_load` @ `0x00101AB4`, con fallback `0x08000800` / `0x0334xxxx` si `cfg:s` falla) y escribe los ringbuffers en memoria compartida HID.

### 3.5 `gsp` (`0004013000001C02`) — GPU PICA200, Controladores LCD, VRAM y GX Command Queue
- **Ubicación:** [`Modulo-GPIO-Pines-Entrada-Salida-0004013000001C02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-GPIO-Pines-Entrada-Salida-0004013000001C02) (`gsp_friendly.sym` / `.r2` / `_ghidra.py`)
- **ExHeader:** `.text=0x00100000 (0xC5B8)`, `.ro=0x0010D000`, `.data=0x0010E000`, `.bss=0x18EC`, `prio=0x10`, ACL `['pdn:g', 'i2c::LCD', 'mcu::GPU', 'cfg:s', 'ptm:s']`.
- **MMIO, VRAM e IRQs Hardware Verificados:**
  - Páginas `0xFFE`: **`0x1ED02000`** (`LCD`), **`0x1ED0F000`**.
  - Rangos `0xFF8/0xFF9`: **`0x1EF00000..0x1EF20000 (RW)`** (registros GPU PICA/PPF/PSC), **`0x1F000000..0x1F600000 (RO)`** (mapeo VRAM `0x18000000`, referenciado junto a `0x08000000..0x08600000` en `gsp_map_vram_and_init_bufs` @ `0x00100248`).
  - IRQs autorizadas (`0xE50A552B`, `0xE58B7FFF`): **`40`, `41`, `42`, `43`, `44`, `45`** (PDC0/PDC1 VBlank, PSC0/PSC1 DMA fill, PPF display transfer y P3D GPU finish), enlazadas vía `SVC 0x50` en `0x1036A4`.
  - Usa **36 SVCs ARM** incluyendo `0x50..0x56` y **`SVC 0x59` (`SetGpuProt`)**.
- **2 Servicios y Dispatchers Confirmados (`gsp_main_server_and_lcd_irq` @ `0x00100550`):**
  - Handle index `0` -> `gsp_dispatch_vram_or_irq_event` (`0x001010D4`, señales IRQ hardware GPU/LCD).
  - Handle index `1` -> **`gsp::Lcd`** (`.data 0x10E008`, `max_sessions=1`): `gsp_lcd_ipc_dispatcher` (`0x001014FC`, **21 comandos** `0x01..0x15` + static-buf `0x1019FC`).
  - Handle index `2` -> **`gsp::Gpu`** (`.data 0x10E004`, `max_sessions=4`): cada cliente instancia un hilo de sesión `gsp_gpu_session_loop` (`0x0010285C`) que atiende el dispatcher **`0x00103F24`** (**31 comandos** `0x01..0x1F`) y encauza los 5 comandos gráficos (Memory Fill, Display Transfer, Texture Copy, Cache Flush, GX DMA) mediante `gsp_gx_command_queue_proc` (`0x00103A4C`).

---

## 4. Driver WiFi y Red Local (`nwm`, `0004013000002D02`) `[VERIFICADO]`

- **Ubicación:** [`Modulo-NWM-WiFi-0004013000002D02`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02) (`nwm_friendly.sym` / `symbols_nwm_friendly.r2` / `symbols_nwm_friendly_ghidra.py`)
- **ExHeader Completo:**
  - `.text=0x00100000 (0x3CB74)` | `.rodata=0x0013D000 (0x169F4)` | `.data=0x00154000 (0xBD0)` | `.bss=0xAF38` | `stack=0x2000` | `prio=0x26`.
  - Dependencias: `cfg` (`1702`), `mcu` (`1F02`), `ps` (`3102`), `ptm` (`2202`).
  - **ACL de Servicios:** `['cfg:u', 'mcu::NWM', 'ps:ps', 'ptm:s']`.

### 4.1 Hardware Subyacente: Controlador SDIO2, DMA del Kernel, Radio Kill-Switch y Chip Atheros AR6014

1. **Rangos MMIO Mapeados en ExHeader (`0xFF8/0xFF9`):**
   - **`0x1EC22000..0x1EC23000 (RW)`** y **`0x1EE22000..0x1EE23000 (RW)`** (registros del controlador SDIO2 WLAN y su ventana secundaria).
   - Verificado directamente en `0x133a0c` (`DAT_00133abc = 0x1EC22000` cuando `param_1 == 2`, `DAT_00133ac0 = 0x1EC00000` para rama alternativa) y en `nwm_sdio_mmio_helper_1338f8` / `nwm_sdio_mmio_helper_133a0c` (`0x1338F8`, `0x133A0C`, `0x133AEC`, `0x133B08`, `0x133B38`).
2. **Interrupciones y Energía RF Verificadas:**
   - **IRQs ExHeader (`0xE8107FFF`):** **`64` (`0x40`)** y **`65` (`0x41`)**. En [`0x12442c.c`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02/pseudocodigo/functions/0x12442c.c) (`nwm_sdio_irq_bind`), cuando el puerto es SDIO2 (`*(char*)(iVar3 + 0x24) == 2`), pasa `uVar2 = 0x40` (IRQ `64`) a `0x133798` -> `0x127642` -> **`nwm_svc_0x50_BindInterrupt_13c938`** (`0x13C938`, `swi 0x50`).
   - **Encendido/apagado hardware de radio:** `nwm` está autorizado a **`SVC 0x5A` (`SetWifiEnabled`)**, cuya implementación verificada en Kernel11 es `k11_hw_set_wifi_enabled` (`0xFFF06D94`, `svc_0x5A_SetWifiEnabled` @ `0xFFF0485C`), y en `nwm` aparece invocado en `0x12e618`/`SVC` (`SVCs used` lista exactamente **`0x5A`** y el set de DMA **`0x55, 0x56, 0x57, 0x58`**). El LED/estado hardware WiFi en el PMIC se controla además a través de la sesión **`mcu::NWM`** (`0x13D4F4`).
3. **Transferencias DMA SDIO ↔ AR6014 (`[VERIFICADO]` + Atheros AR6K `[CONOCIMIENTO PÚBLICO 3DS]`):**
   - `nwm_sdio_cmd_submit` (`0x00124854`) envía comandos SDIO (`CMD52`/`CMD53`) y configura el controlador; `nwm_sdio_block_xfer_0x200` (`0x00126168`) ejecuta transferencias por bloques (`0x100`/`0x200` bytes).
   - Utiliza los 4 SVCs DMA de Kernel11 (`SVC 0x55 StartInterProcessDma`, `0x56 StopDma`, `0x57 GetDmaState`, `0x58 RestartDma`) junto a invalidación/clean de caché (`SVC 0x52`/`0x53`), verificados en funciones `0x11c6b8.c`, `0x11d2f8.c`, `0x1257dc.c`, `0x12c3be.c` y `0x137ea8.c`.
4. **Pila AR6014 (`sdio_hcd` / `HTC` / `WMI`) y Supplicant WPA Embebido (`[VERIFICADO]`):**
   - Inicialización del driver host SDIO `'sdio_hcd'` (`0x12575C`) en [`0x1256b0.c`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02/pseudocodigo/functions/0x1256b0.c) (`block=0x200`, `500` ms timeout).
   - Mensajes embebidos verificados en `.code`/`.rodata`: `'SDIO Bus Driver: SD Switch Status Block Error'` (`0x116658`, `0x11CBF4`), `'BAD HTC Recv PKT'` (`0x11C150`), colas QoS `'WMI CONTROL'` (`0x12F660`), `'WMI DATA BE'`, `'WMI DATA BK'`, `'WMI DATA VI'`, `'WMI DATA VO'` (`0x12F670..0x12F694`), `'sdio_wlan'` (`0x15489C`), `'MACFilter'` (`0x141317`).
   - **Supplicant WiFi verificado:** `'wpa_supplicant v0.5.10-Devicescape'` (`0x13F3DA`), `'Devicescape Agent Supplicant 2.5'` (`0x13F3B9`) con aviso BSD en `0x13F320`. Implementa descifrado **RFC 3394 AES Key Unwrap** para claves WPA/WPA2 (`0x12e618.c`, bucle de 6 rondas `5..0` verificando IV `0xA6 x 8`). Lee configuración NVRAM/WiFi vía `cfg:u`/`cfg:i`/`cfg:s` (`0x13F31A..0x13F40C`) y deriva aleatoriedad/criptografía vía **`ps:ps`** (`0x13D168`, `0x13E2D6`).

### 4.2 Los 7 Servicios IPC de `nwm` y su Modelo Dual de Concurrencia (`nwm_main_server_loop` @ `0x001016F8`)

En [`0x1016f8.c`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02/pseudocodigo/functions/0x1016f8.c), `nwm` lee la tabla de configuración de servicios en `.rodata 0x13D0F8`:
- Tabla de strings de servicios (`0x13D120..0x13D156`), flags (`0x13D0FC`: `[1, 1, 1, 1, 0, 1, 0, 0]`) y límites máximos por sesión.
- Cuando `flag == 0` (`nwm::CEC`, `nwm::TST`), acepta sesiones en el propio bucle principal. Cuando `flag == 1` y índice != `5`, coloca el objeto de sesión en colas de worker (`nwm_session_slot_dispatch` @ `0x00102118`).
- **Caso especial índice `5` (`nwm::EXT`):** en `0x1016f8.c` línea `130..163`, busca slot libre (`max 2` en `nwm_ext_find_free_slot` @ `0x001045B0`) y **spawnea un hilo dedicado (`SVC CreateThread`)** con punto de entrada `nwm_ext_thread_entry` (`0x00102428`), bucle privado `nwm_ext_session_loop` (`0x0010759C`), buffer estático TLS `0x300` bytes (`nwm_ext_tls_static_buf_setup` @ `0x001094FC`) y dispatcher propio `0x109580`.

| Índice | Servicio | Flag / Hilo | Max Sesiones | Rutina On-Connect (`0x1233B8`) | Dispatcher IPC (`0x12334C`) | Casos Activos y Rol |
|--------|----------|-------------|--------------|---------------------------------|-------------------------------|---------------------|
| `[0]` | **`nwm::UDS`** | Worker pool | **2** | `0x10497D` (`nwm_uds_on_connect`) | `0x105B01` (`nwm_uds_ipc_dispatcher`) | **16** (`0x01..0x10`): juego multijugador local DS/3DS inalámbrico (beacon, nodos, DataFrame) |
| `[1]` | **`nwm::INF`** | Worker pool | **4** | `0x104995` (`nwm_inf_on_connect`) | `0x105E69` (`nwm_inf_ipc_dispatcher`) | **13** (`0x01..0x0D`): gestión WiFi Infraestructura usada por `ac` (`0004013000002402`) |
| `[2]` | **`nwm::SOC`** | Worker pool | **2** | `0x10492F` (`nwm_soc_on_connect`) | `0x1051E1` (`nwm_soc_ipc_dispatcher`) | **44** (`0x01..0x2C`): plano de datos IP/sockets hacia el SysModule `socket` (`0004013000002E02`) |
| `[3]` | **`nwm::SAP`** | Worker pool | **4** | `0x10490D` (`nwm_sap_on_connect`) | `0x1049CD` (`nwm_sap_ipc_dispatcher`) | **30** (`0x01..0x1E`): punto de acceso local / WEP-WPA SoftAP |
| `[4]` | **`nwm::CEC`** | Loop principal | **6** | `0x10492D` | `0x10508D` (`nwm_cec_ipc_dispatcher`) | **9** (`0x01..0x09`): radio StreetPass de bajo nivel consumida por `cecd` |
| `[5]` | **`nwm::EXT`** | **Hilo dedicado** (`0x102429`) | **2** | `NULL` (usa `0x1094FC` en hilo) | `NULL` -> hilo `0x10759C` -> `0x109581` | **35** cmds: control de estado extendido de red (`ndm`, `mp`, `friends`, `nfc`, `ns`) |
| `[6]` | **`nwm::TST`** | Loop principal | **1** | `0x105AC9` (`nwm_tst_on_connect`) | `0x106159` (`nwm_tst_ipc_dispatcher`) | **70** (`0x01..0x46`): diagnóstico RF, pruebas fábrica y calibración |

---

## 5. Antena StreetPass (`cecd`, `0004013000002602` + Interfaz `nwm::CEC`) `[VERIFICADO]`

- **Ubicación:** [`Modulo-CECD-StreetPass-0004013000002602`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-CECD-StreetPass-0004013000002602) (`cecd_friendly.sym` / `symbols_cecd_friendly.r2` / `symbols_cecd_friendly_ghidra.py`)
- **ExHeader Completo:**
  - `.text=0x00100000 (0x21EA4)` | `.rodata=0x00122000 (0x145C)` | `.data=0x00124000 (0x135C)` | `.bss=0x94E8` | `stack=0x4000` | `prio=0x3C`.
  - Dependencias: `cfg` (`1702`), `ptm` (`2202`), `nwm` (`2D02`), `friends` (`3202`).
  - **ACL de Servicios:** `['nwm::CEC', 'fs:USER', 'ptm:s', 'ps:ps', 'cfg:s', 'frd:u']`.

### 5.1 Flujo Completo StreetPass (`cecd` ↔ `nwm::CEC` ↔ `fs:USER` ↔ `ps:ps` ↔ `ndm`)

1. **Inicialización de Sesiones y Almacenamiento (`cecd_main_server_loop` @ `0x00100154`):**
   - Registra los 3 servicios de la tabla `.rodata 0x122328` con tabla de dispatchers en `0x122340`:
     - **`cecd:u`** (`max_sessions=4`, dispatcher **`0x0011A5BD`**): **22** casos activos (`0x01..0x12`, `0x1E..0x21`) para juegos/aplicaciones (leer/escribir OutBox/InBox, lanzar tareas StreetPass).
     - **`cecd:s`** (`max_sessions=4`, dispatcher **`0x0011AF51`**): **19** casos activos (`0x01..0x12`, `0x1E` + casos inline `0x1F..0x21`, `0x040A`, `0x040F+`) para procesos del sistema (`boss`, `news`, Home Menu).
     - **`cecd:ndm`** (`max_sessions=1`, dispatcher **`0x0011AD69`**): **8** casos (`0x01..0x08`) llamados exclusivamente por **`ndm` (`0004013000002B02`)** para arbitrar antena en reposo/spotpass (`NDM_STATUS_WORKING`, `NDM_STATUS_IDLE`, `NDM_STATUS_SUSPENDING`, `NDM_STATUS_SUSPENDED`, `NDM_RESUME`, `NDM_SUSPEND`, `NDM_SUSPEND_IMMEDIATE`, `OVER_BOSS`, `OVER_BOSS_FORCE`, `OVER_BOSS_FORCE_WAIT` @ `0x124B08..0x124E74`).
   - Instancia 3 hilos/colas internos con parámetros `0x100`, `0x105` y `0x106` (verificado en [`0x100154.c`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-CECD-StreetPass-0004013000002602/pseudocodigo/functions/0x100154.c) líneas `60..89`).
2. **Almacén NAND de Buzones (`cecd_init_fs_session` @ `0x0010079C`):**
   - Abre sesión **`fs:USER`** (`0x122437`) hacia el archivo de guardado sistema del módulo para operar las rutas CEC verificadas en `code.bin`:
     - Raíz y temporales: **`data:/CEC`**, **`data:/CEC/TMP`**, `data:/CEC/test`
     - Metadatos globales: **`data:/CEC/MBoxList____`**, **`data:/CEC/SessionId___`**, **`data:/CEC/MacFilter___`**, **`eventlog.dat`**
     - Por cada caja de juego (`TitleID` CEC): **`MBoxInfo____`**, **`MBoxData`**, **`BoxInfo_____`**, **`InBox___`** y **`OutBox__`** (`0x109B54..0x1136C0`).
   - Protege/firma mensajes CEC mediante **`ps:ps`** (`0x1222AC`).
3. **Antena Hardware vía Doble Sesión `nwm::CEC` (`cecd_init_nwm_cec_sessions` @ `0x00102700`):**
   - En [`0x102700.c`](file:///home/skels/3ds-reversing/binarios_descifrados/Modulo-CECD-StreetPass-0004013000002602/pseudocodigo/functions/0x102700.c), abre **2 handles de sesión paralelos** (`DAT_00102744[0]` y `DAT_00102744[1]`) hacia el puerto **`nwm::CEC`** (`0x12244C`) mediante `0x1040e0`. Si falla el segundo handle, cierra el primero limpia y ordenadamente.
   - Emite peticiones IPC hacia `nwm::CEC` (`0x105CD4..0x10601C`), verificadas en `cecd_friendly.sym` con cabeceras exactas: `cecd_nwmc_client_cmd_0x06` (`0x00105E9A`, `0W+2T`), `cecd_nwmc_client_cmd_0x0B` (`0x00105E5A`, `1W+2T`), `cecd_nwmc_client_cmd_0x0C` (`0x00105DDA`, `1W+2T`), `cecd_nwmc_client_cmd_0x16` (`0x00105ED6`, `1W+2T`), `cecd_nwmc_client_cmd_0x1C` (`0x00105E1A`, `1W+2T`) y `cecd_nwmc_client_cmd_0x1D` (`0x00105F16`, `0W+0T`), además de `cecd_nwmc_client_cmd_1_recv_or_tx` (`0x00105CD4`).
   - El servidor **`nwm::CEC`** (`0x0010508C`, **9 casos**) gestiona la transmisión y escaneo periódico de tramas 802.11 IE/frames StreetPass directamente sobre el hardware SDIO2 AR6014 cuando `ndm`/`cecd:ndm` autoriza la ventana radio en consola activa o modo Sleep.

---

## 6. Uso Rápido de Tablas e Ingesta en `radare2` / `Ghidra` `[VERIFICADO]`

Todas las tablas conservan el estándar binario intacto (`0 HYPOTHESIS`) y soportan carga no destructiva:

```bash
# Ejemplo: Driver WiFi NWM (0004013000002D02, base ARM 0x00100000)
r2 -a arm -b 32 -m 0x00100000 \
  -i binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02/symbols_nwm_friendly.r2 \
  binarios_descifrados/Modulo-NWM-WiFi-0004013000002D02/exefs_dir/code.bin

# Ejemplo: Módulo FIRM integrado 'loader' (OJO: base real 0x14000000)
r2 -a arm -b 32 -m 0x14000000 \
  -i binarios_descifrados/firm_modulos/loader/symbols_loader_friendly.r2 \
  binarios_descifrados/firm_modulos/loader/code.bin
```

Para **Ghidra 12.2+**, importar `code.bin` con arquitectura `ARM:LE:32:v6k`, `Image Base = 0x00100000` (o **`0x14000000`** para `firm_modulos/loader`), ejecutar Auto-Analyze y lanzar el script `symbols_<mod>_friendly_ghidra.py` incluido en la carpeta correspondiente.
