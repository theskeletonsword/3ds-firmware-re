# Análisis Completo de Kernels ARM11 y ARM9 — Nintendo 3DS (EL1)

> **Estado:** `[VERIFICADO EN ESTE REPO]` — Los kernels fueron descifrados del título FIRM (`extraidos/FIRM_0004013800000002/raw/content.0000.0000006c`, `firm.bin`) en `binarios_descifrados/FIRM_0002/` usando `ctrtool` + `aes_keys.txt` + `movable.sed`.
>
> **Reglas de evidencia:**
> - `[VERIFICADO]`: comprobado directamente en `firm.bin`, `arm11_section1.bin`, `arm11.bin`, `arm9.bin` y los 58+5 SysModules descifrados.
> - `[CONOCIMIENTO PÚBLICO 3DS]`: nombres simbólicos estándar de 3dbrew correlacionados con la evidencia binaria.
> - `[HIPÓTESIS]`: inferencia pendiente de validación en hardware real.

---

## 1. Estructura Real del FIRM (`firm.bin`) y Kernels `[VERIFICADO]`

Al inspeccionar el header FIRM (`binarios_descifrados/FIRM_0002/exefs_dir/firm.bin`, magia `FIRM`), se verificaron **3 secciones**:

| Sección FIRM | Archivo | Base FIRM (Carga) | Base Runtime (MMU) | Entry Point | Tamaño | Contenido Real `[VERIFICADO]` |
|--------------|---------|-------------------|--------------------|-------------|--------|--------------------------------|
| **Section 0** | `arm11.bin` (`separated/firm_0_1ff00000.bin`) | `0x1FF00000` | N/A (5 NCCHs) | — | 218,624 B (`0x35600`) | **5 SysModules integrados en FIRM** (contenedores NCCH): `fs` (`0x00000`), `loader` (`0x26600`), `pm` (`0x29A00`), `sm` (`0x2E800`), `pxi` (`0x32200`) |
| **Section 1** | `arm11_section1.bin` (`separated/firm_1_1ff80000.bin`) | `0x1FF80000` | `0xFFF00000` (vectores en `0xFFFF0000`) | **`0x1FFAE034`** | 204,800 B (`0x32000`) | **Kernel11 real** (ARMv6K MPCore): dispatcher SVC, tabla de 109 SVCs, vectores, GIC, PMU CP15 `c15,c12`, objetos `K*` |
| **Section 2** | `arm9.bin` (`separated/firm_2_08006800.bin`) | `0x08006800` | Kernel9 `0x08006800` + Process9 `0x08028000` | **`0x0801B01C`** | 541,184 B (`0x84200`) | **Kernel9** (`0x08006800..0x0801C2FF`) + **Process9 NCCH** (file off `0x15B00`, `.code` `0x16700` → VA `0x08028000`) |

> **Corrección crítica respecto a notas previas:**
> 1. El entry point del header FIRM para ARM11 es **`0x1FFAE034`** (en `arm11_section1.bin`, offset `0x2E034`), no `0x1FF0AE034`.
> 2. `arm11.bin` (`0x1FF00000`) no es código monolítico de kernel, sino el paquete de 5 NCCHs de sistema (`fs`, `loader`, `pm`, `sm`, `pxi`). El kernel ARM11 real reside en **`arm11_section1.bin`** (`0x1FF80000` → `0xFFF00000`), donde radare2 detecta **415 funciones** (540 símbolos totales con entradas de tabla SVC).
> 3. El análisis previo en `arm9.bin` había etiquetado datos de la tabla RTTI `K*` (`0x08018F64`: `0xFFFF8001`) como instrucciones `SWI 0xFF8001`. En realidad, el dispatcher SWI de Kernel9 está en `0x08007878` con su tabla de punteros en `0x08007938`.

---

## 2. Vectores de Excepción Verificados (ARM11 y ARM9) `[VERIFICADO]`

### 2.1 ARM11 Kernel11 (`arm11_section1.bin`: `0x1FFAD000` → mapeado en `0xFFFF0000`)

La página de vectores en `0x1FFAD000` (offset `0x2D000`) contiene saltos relativos hacia el código mapeado en `0xFFF00000`:

| Vector | Offset / VA Runtime | Instrucción en Tabla | Trampolín (`0xFFF0xxxx`) | Handler Principal (`0xFFF0xxxx` / Sec1 VA) | Comportamiento Verificado |
|--------|---------------------|----------------------|--------------------------|-------------------------------------------|---------------------------|
| **Reset** | `0xFFFF0000` (`0x1FFAD000`) | `b 0xFFFF0058` | — | `0xFFFF0058` (`0x1FFAD058`) | `wfe; b .` (bucle de espera) |
| **Undefined** | `0xFFFF0004` (`0x1FFAD004`) | `b 0xFFF005FC` | `clrex; ldr pc, [0xFFF00604]` | **`0xFFF02520`** (`0x1FF82520`) | Si modo User ARM + instrucción coprocesador VFP, hace lazy VFP switch (`vmrs lr, fpexc`, `bl 0xFFFF05C0`) |
| **SVC** | `0xFFFF0008` (`0x1FFAD008`) | `b 0xFFF00608` | `clrex; ldr pc, [0xFFF00610]` | **`0xFFF0220C`** (`0x1FF8220C`) | **Kernel11 SVC Dispatcher** (ver §3) |
| **Prefetch Abort** | `0xFFFF000C` (`0x1FFAD00C`) | `b 0xFFF00614` | `clrex; ldr pc, [0xFFF0061C]` | **`0xFFF02084`** (`0x1FF82084`) | `sub lr, lr, 4`; modo User (`0x10`) → `0xFFF144AC`; kernel → `0xFFF03508` |
| **Data Abort** | `0xFFFF0010` (`0x1FFAD010`) | `b 0xFFF00620` | `clrex; ldr pc, [0xFFF00628]` | **`0xFFF020CC`** (`0x1FF820CC`) | `sub lr, lr, 8`; incluye rango de fixup seguro de copias kernel `[0xFFF15144, 0xFFF1532C)` |
| **Reserved** | `0xFFFF0014` (`0x1FFAD014`) | `b 0xFFFF0014` | — | — | Bucle infinito |
| **IRQ** | `0xFFFF0018` (`0x1FFAD018`) | `b 0xFFF0062C` | `clrex; ldr pc, [0xFFF00634]` | **`0xFFF02144`** (`0x1FF82144`) | Guarda contexto, cambia a SVC, llama dispatcher GIC `0xFFF06450` |
| **FIQ** | `0xFFFF001C` (`0x1FFAD01C`) | `b 0xFFF005D0` | — | **`0xFFF005D0`** (`0x1FF805D0`) | Activa bit 1 en `0xFFFCA104`, escribe `0x3000F` en `0xFFFEFF00`, `subs pc, lr, 4` |

### 2.2 ARM9 Kernel9 (`arm9.bin`: `0x0800E7E0`, copiado a `0x08000000` / `0xFFFF0000`)

Referenciado en el literal pool de `arm9_entry` (`0x0801B108` = `0x0800E7E0`) y configurado en ITCM `0x08000000` desde `0x08007B5C`:

| Vector | Dirección Tabla (`0x0800E7E0+`) | Puntero en Literal | Handler Verificado | Comportamiento Verificado |
|--------|-----------------------------------|--------------------|--------------------|---------------------------|
| **Reset** | `0x0800E7E0` (`b 0x0800E800`) | `0x0800E804` | `0x0800E800` | Bucle `ldr pc, [0x0800E804]` |
| **Undefined** | `0x0800E7E4` (`b 0x0800E808`) | `0x0800E80C` | **`0x08007B58`** | `bkpt 2` (y stub en `0x08007B5C` que escribe vectores en `0x08000000`) |
| **SWI** | `0x0800E7E8` (`b 0x0800E810`) | `0x0800E814` | **`0x08007878`** | **Kernel9 SWI Dispatcher** (tabla en `0x08007938`) |
| **Prefetch Abort** | `0x0800E7EC` (`b 0x0800E818`) | `0x0800E81C` | **`0x08007700`** | `bkpt 3` |
| **Data Abort** | `0x0800E7F0` (`b 0x0800E820`) | `0x0800E824` | **`0x080076FC`** | `bkpt 4` |
| **Reserved** | `0x0800E7F4` | — | `0x0800E7F4` | Bucle infinito `b .` |
| **IRQ** | `0x0800E7F8` (`b 0x0800E828`) | `0x0800E82C` | **`0x08007704`** | Guarda estado en pila SVC y llama a `0x08012248` |
| **FIQ** | `0x0800E7FC` | — | `0x0800E7FC` | `subs pc, lr, 4` |

---

## 3. SVC Dispatcher y Tabla Completa de Syscalls del Kernel11 `[VERIFICADO]`

### 3.1 Flujo del SVC Dispatcher (`0xFFF0220C` / Sec1 `0x1FF8220C`)

1. `srsdb sp!, 0x13` y `stmdb sp, {r8..lr} ^` guardan el estado de usuario.
2. Lee `spsr`; si es Thumb (`0x20`), carga `ldrh r9, [lr, -2]`; si es ARM, carga `ldr r9, [lr, -4]`; aplica `and r9, r9, 0xff`.
3. Comprueba `cmp r9, 0x80`: si `>= 0x80`, salta a `0xFFF02238` → `bl 0xFFF04DE4` (denegado/inválido).
4. Apunta a la tabla base con `add r8, pc, 0xf8` → **`0xFFF02328`** (`126` slots útiles `0x00..0x7D`; `0x7E` coincide con `0xFFF02520`, el handler Undef).
5. Verifica el **bitmap de permisos de syscall del proceso** en `[sp + 0x20 + (svc >> 3)]` bit `svc & 7`; si no está permitido, salta a `0xFFF04DE4`.
6. Habilita IRQ (`cpsie i`), llama `blx r8` (`tabla[svc]`), deshabilita IRQ (`cpsid i`).
7. Si la bandera de replanificación `[sp + 0x30]` está activa, llama a `0xFFF0401C`, restaura registros y ejecuta `rfeia sp!`.

### 3.2 Tabla de SVCs del Kernel11 (`0xFFF02328`) — 109 Entradas Activas

> **Nota de evidencia:** Las columnas *VA Runtime*, *VA Sec1* y *Evidencia Binaria* son `[VERIFICADO]` directamente en `arm11_section1.bin` y en los 58+5 SysModules. La columna *Nombre (3dbrew)* es `[CONOCIMIENTO PÚBLICO 3DS]` correlacionado con los módulos llamadores y el comportamiento del handler.

| SVC # | VA Runtime (`0xFFF0xxxx`) | VA Sec1 (`0x1FF8xxxx`) | Nombre (3dbrew) `[CONOCIMIENTO PÚBLICO 3DS]` | Evidencia Binaria `[VERIFICADO]` |
|-------|-----------------------------|--------------------------|------------------------------------------------|------------------------------------|
| `0x01` | `0xFFF03640` | `0x1FF83640` | ControlMemory | Usado por 46 mód. (ej: am, camera, codec, gsp) |
| `0x02` | `0xFFF03AB4` | `0x1FF83AB4` | QueryMemory | Usado por 26 mód. (ej: am, camera, cfg, dsp) |
| `0x03` | `0xFFF043F0` | `0x1FF843F0` | ExitProcess | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x04` | `0xFFF05E98` | `0x1FF85E98` | GetProcessAffinityMask | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x05` | `0xFFF05F3C` | `0x1FF85F3C` | SetProcessAffinityMask | Usado por 1 mód. (ej: FIRM:pm) |
| `0x06` | `0xFFF0390C` | `0x1FF8390C` | GetProcessIdealProcessor | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x07` | `0xFFF06000` | `0x1FF86000` | SetProcessIdealProcessor | Usado por 1 mód. (ej: FIRM:pm) |
| `0x08` | `0xFFF037F4` | `0x1FF837F4` | CreateThread | Usado por 51 mód. (ej: am, camera, codec, dsp) |
| `0x09` | `0xFFF042CC` | `0x1FF842CC` | ExitThread | Usado por 51 mód. (ej: am, camera, codec, dsp) |
| `0x0A` | `0xFFF044E4` | `0x1FF844E4` | SleepThread | Usado por 62 mód. (ej: am, camera, cfg, codec) |
| `0x0B` | `0xFFF03A14` | `0x1FF83A14` | GetThreadPriority | Usado por 3 mód. (ej: socket, FIRM:fs) |
| `0x0C` | `0xFFF0539C` | `0x1FF8539C` | SetThreadPriority | Usado por 7 mód. (ej: gsp, mp, friends, boss) |
| `0x0D` | `0xFFF05C00` | `0x1FF85C00` | GetThreadAffinityMask | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x0E` | `0xFFF05E10` | `0x1FF85E10` | SetThreadAffinityMask | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x0F` | `0xFFF039BC` | `0x1FF839BC` | GetThreadIdealProcessor | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x10` | `0xFFF05FF4` | `0x1FF85FF4` | SetThreadIdealProcessor | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x11` | `0xFFF06058` | `0x1FF86058` | GetCurrentProcessorNumber | `mrc p15, 0, r0, c0, c0, 5; and r0, r0, 3` |
| `0x12` | `0xFFF03BD4` | `0x1FF83BD4` | Run | Usado por 1 mód. (ej: FIRM:pm) |
| `0x13` | `0xFFF03720` | `0x1FF83720` | CreateMutex | Usado por 25 mód. (ej: am, hid, spi, ac) |
| `0x14` | `0xFFF04528` | `0x1FF84528` | ReleaseMutex | Usado por 13 mód. (ej: camera, ac, cecd, csnd) |
| `0x15` | `0xFFF03798` | `0x1FF83798` | CreateSemaphore | Usado por 5 mód. (ej: http, ndm, ssl, FIRM:sm) |
| `0x16` | `0xFFF03B14` | `0x1FF83B14` | ReleaseSemaphore | Usado por 5 mód. (ej: http, ndm, ssl, FIRM:sm) |
| `0x17` | `0xFFF036E4` | `0x1FF836E4` | CreateEvent | Usado por 45 mód. (ej: camera, codec, dsp, gsp) |
| `0x18` | `0xFFF0440C` | `0x1FF8440C` | SignalEvent | Usado por 43 mód. (ej: camera, codec, dsp, gsp) |
| `0x19` | `0xFFF0411C` | `0x1FF8411C` | ClearEvent | Usado por 36 mód. (ej: camera, codec, dsp, gsp) |
| `0x1A` | `0xFFF03818` | `0x1FF83818` | CreateTimer | Usado por 20 mód. (ej: codec, hid, mic, ptm) |
| `0x1B` | `0xFFF03C00` | `0x1FF83C00` | SetTimer | Usado por 20 mód. (ej: codec, hid, mic, ptm) |
| `0x1C` | `0xFFF042E8` | `0x1FF842E8` | CancelTimer | Usado por 14 mód. (ej: hid, ptm, ac, csnd) |
| `0x1D` | `0xFFF041F4` | `0x1FF841F4` | ClearTimer | Usado por 5 mód. (ej: mp, boss, ns) |
| `0x1E` | `0xFFF03700` | `0x1FF83700` | CreateMemoryBlock | Usado por 27 mód. (ej: gsp, hid, ac, csnd) |
| `0x1F` | `0xFFF0486C` | `0x1FF8486C` | MapMemoryBlock | Usado por 25 mód. (ej: camera, gsp, hid, mic) |
| `0x20` | `0xFFF04F14` | `0x1FF84F14` | UnmapMemoryBlock | Usado por 34 mód. (ej: camera, gsp, hid, mic) |
| `0x21` | `0xFFF036A8` | `0x1FF836A8` | CreateAddressArbiter | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x22` | `0xFFF03608` | `0x1FF83608` | ArbitrateAddress | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x23` | `0xFFF043C0` | `0x1FF843C0` | CloseHandle | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x24` | `0xFFF059B0` | `0x1FF859B0` | WaitSynchronization1 | Usado por 39 mód. (ej: am, camera, cfg, codec) |
| `0x25` | `0xFFF03C6C` | `0x1FF83C6C` | WaitSynchronizationN | Usado por 47 mód. (ej: am, camera, codec, dsp) |
| `0x26` | `0xFFF03C1C` | `0x1FF83C1C` | SignalAndWait | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x27` | `0xFFF03850` | `0x1FF83850` | DuplicateHandle | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x28` | `0xFFF04850` | `0x1FF84850` | GetSystemTick | Usado por 46 mód. (ej: am, camera, cfg, gsp) |
| `0x29` | `0xFFF038B4` | `0x1FF838B4` | GetHandleInfo | Usado por 1 mód. (ej: dlp) |
| `0x2A` | `0xFFF03980` | `0x1FF83980` | GetSystemInfo | Usado por 2 mód. (ej: FIRM:sm, FIRM:pm) |
| `0x2B` | `0xFFF03928` | `0x1FF83928` | GetProcessInfo | Usado por 39 mód. (ej: am, camera, cfg, codec) |
| `0x2C` | `0xFFF039D8` | `0x1FF839D8` | GetThreadInfo | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x2D` | `0xFFF03624` | `0x1FF83624` | ConnectToPort | Usado por 62 mód. (ej: am, camera, cfg, codec) |
| `0x2E` | `0xFFF04E6C` | `0x1FF84E6C` | SendSyncRequest1 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x2F` | `0xFFF04E78` | `0x1FF84E78` | SendSyncRequest2 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x30` | `0xFFF04E84` | `0x1FF84E84` | SendSyncRequest3 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x31` | `0xFFF04E90` | `0x1FF84E90` | SendSyncRequest4 | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x32` | `0xFFF04B78` | `0x1FF84B78` | SendSyncRequest | Usado por 62 mód. (ej: am, camera, cfg, codec) |
| `0x33` | `0xFFF03A4C` | `0x1FF83A4C` | OpenProcess | Usado por 1 mód. (ej: FIRM:pm) |
| `0x34` | `0xFFF03A68` | `0x1FF83A68` | OpenThread | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x35` | `0xFFF038D4` | `0x1FF838D4` | GetProcessId | Usado por 60 mód. (ej: am, camera, cfg, codec) |
| `0x36` | `0xFFF038F0` | `0x1FF838F0` | GetProcessIdOfThread | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x37` | `0xFFF039A0` | `0x1FF839A0` | GetThreadId | Usado por 13 mód. (ej: am, dsp, gsp, http) |
| `0x38` | `0xFFF03964` | `0x1FF83964` | GetResourceLimit | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x39` | `0xFFF06090` | `0x1FF86090` | GetResourceLimitLimitValues | Usado por 1 mód. (ej: FIRM:pm) |
| `0x3A` | `0xFFF06224` | `0x1FF86224` | GetResourceLimitCurrentValues | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x3B` | `0xFFF04E54` | `0x1FF84E54` | GetThreadContext | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x3C` | `0xFFF06340` | `0x1FF86340` | Break | Comprueba `r0 <= 4`, flag `0xFFF2E00A`, err `0xD8E007ED` |
| `0x3D` | `0xFFF05178` | `0x1FF85178` | OutputDebugString | Valida rango string usuario, err `0xE0E01FFD` |
| `0x3E` | `0xFFF03664` | `0x1FF83664` | ControlPerformanceCounter | Llama a `0xFFF0AC44` (PMU CP15 `c15, c12, 0..3`) |
| `0x47` | `0xFFF0373C` | `0x1FF8373C` | CreatePort | Usado por 3 mód. (ej: am, FIRM:sm) |
| `0x48` | `0xFFF037D8` | `0x1FF837D8` | CreateSessionToPort | Usado por 3 mód. (ej: am, FIRM:sm) |
| `0x49` | `0xFFF037B4` | `0x1FF837B4` | CreateSession | Usado por 1 mód. (ej: FIRM:fs) |
| `0x4A` | `0xFFF035EC` | `0x1FF835EC` | AcceptSession | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x4B` | `0xFFF03B4C` | `0x1FF83B4C` | ReplyAndReceive1 | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x4C` | `0xFFF03B68` | `0x1FF83B68` | ReplyAndReceive2 | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x4D` | `0xFFF03B84` | `0x1FF83B84` | ReplyAndReceive3 | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x4E` | `0xFFF03BA0` | `0x1FF83BA0` | ReplyAndReceive4 | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x4F` | `0xFFF03B30` | `0x1FF83B30` | ReplyAndReceive | Usado por 63 mód. (ej: am, camera, cfg, codec) |
| `0x50` | `0xFFF0460C` | `0x1FF8460C` | BindInterrupt | Llama a `0xFFF0D544` (helper IRQ bind/unbind) |
| `0x51` | `0xFFF04C78` | `0x1FF84C78` | UnbindInterrupt | Llama a `0xFFF0D544` (helper IRQ bind/unbind) |
| `0x52` | `0xFFF06064` | `0x1FF86064` | InvalidateProcessDataCache | Llama a `0xFFF0AE48` (helper D-cache de proceso) |
| `0x53` | `0xFFF05E1C` | `0x1FF85E1C` | StoreProcessDataCache | Llama a `0xFFF0AE48` (helper D-cache de proceso) |
| `0x54` | `0xFFF05AE0` | `0x1FF85AE0` | FlushProcessDataCache | Llama a `0xFFF0AE48` (helper D-cache de proceso) |
| `0x55` | `0xFFF03C44` | `0x1FF83C44` | StartInterProcessDma | Usado por 8 mód. (ej: camera, gsp, nwm, ns) |
| `0x56` | `0xFFF0402C` | `0x1FF8402C` | StopDma | Usado por 8 mód. (ej: camera, gsp, nwm, ns) |
| `0x57` | `0xFFF03898` | `0x1FF83898` | GetDmaState | Usado por 4 mód. (ej: camera, nwm, FIRM:fs) |
| `0x58` | `0xFFF03BBC` | `0x1FF83BBC` | RestartDma | Usado por 1 mód. (ej: nwm) |
| `0x59` | `0xFFF05AD0` | `0x1FF85AD0` | SetGpuProt | Usado por 1 mód. (ej: gsp) |
| `0x5A` | `0xFFF0485C` | `0x1FF8485C` | SetWifiEnabled | Usado por 1 mód. (ej: nwm) |
| `0x60` | `0xFFF03834` | `0x1FF83834` | DebugActiveProcess | Usado por 1 mód. (ej: FIRM:pm) |
| `0x61` | `0xFFF050E4` | `0x1FF850E4` | BreakDebugProcess | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x62` | `0xFFF05E48` | `0x1FF85E48` | TerminateDebugProcess | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x63` | `0xFFF05718` | `0x1FF85718` | GetProcessDebugEvent | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x64` | `0xFFF05464` | `0x1FF85464` | ContinueDebugEvent | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x65` | `0xFFF03948` | `0x1FF83948` | GetProcessList | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x66` | `0xFFF039F8` | `0x1FF839F8` | GetThreadList | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x67` | `0xFFF05B0C` | `0x1FF85B0C` | GetDebugThreadContext | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x68` | `0xFFF05CC0` | `0x1FF85CC0` | SetDebugThreadContext | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x69` | `0xFFF03A84` | `0x1FF83A84` | QueryDebugProcessMemory | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x6A` | `0xFFF0529C` | `0x1FF8529C` | ReadProcessMemory | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x6B` | `0xFFF05508` | `0x1FF85508` | WriteProcessMemory | Llama a `0xFFF14864` (debug, err `0xD9002002`) |
| `0x6C` | `0xFFF05DAC` | `0x1FF85DAC` | SetHardwareBreakPoint | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x6D` | `0xFFF0386C` | `0x1FF8386C` | GetDebugThreadParam | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x70` | `0xFFF0368C` | `0x1FF8368C` | ControlProcessMemory | Usado por 1 mód. (ej: ro) |
| `0x71` | `0xFFF04A08` | `0x1FF84A08` | MapProcessMemory | Usado por 1 mód. (ej: ro) |
| `0x72` | `0xFFF05030` | `0x1FF85030` | UnmapProcessMemory | Usado por 1 mód. (ej: ro) |
| `0x73` | `0xFFF036C4` | `0x1FF836C4` | CreateCodeSet | Usado por 1 mód. (ej: FIRM:loader) |
| `0x74` | `0xFFF03A30` | `0x1FF83A30` | — (solo tabla kernel) | En tabla `0xFFF02328` (solo kernel/sin uso en SysModules) |
| `0x75` | `0xFFF03760` | `0x1FF83760` | CreateProcess | Usado por 1 mód. (ej: FIRM:loader) |
| `0x76` | `0xFFF04E9C` | `0x1FF84E9C` | TerminateProcess | Usado por 1 mód. (ej: FIRM:pm) |
| `0x77` | `0xFFF055F8` | `0x1FF855F8` | SetProcessResourceLimits | Usado por 1 mód. (ej: FIRM:pm) |
| `0x78` | `0xFFF0377C` | `0x1FF8377C` | CreateResourceLimit | Usado por 1 mód. (ej: FIRM:pm) |
| `0x79` | `0xFFF061AC` | `0x1FF861AC` | — (usado por FIRM:pm) | Usado por 1 mód. (ej: FIRM:pm) |
| `0x7A` | `0xFFF04E60` | `0x1FF84E60` | — (stub 0xF8C007F4) | Stub -> `0xF8C007F4` (`ERR_NOT_IMPLEMENTED`) |
| `0x7C` | `0xFFF15980` | `0x1FF95980` | KernelSetState | Switch 10 casos (0..9), escribe `0xFFFEFF00` |
| `0x7D` | `0xFFF03AE4` | `0x1FF83AE4` | — (usado por ro) | Usado por 1 mód. (ej: ro) |

---

## 4. Kernel9 SWI Table (`0x08007938`) y Objetos `K*` `[VERIFICADO]`

- **Dispatcher SWI ARM9:** `0x08007878` (misma estructura de bitmap de permisos que Kernel11).
- **Tabla de punteros SWI:** `0x08007938` — contiene **40 entradas no nulas** en `0x08..0x7C`:
  `0x08` (`0x08007C64`), `0x09` (`0x08008910`), `0x0A` (`0x08008B0C`), `0x0B` (`0x08007D58`), `0x0C` (`0x08008EA0`), `0x13` (`0x08007C2C`), `0x14` (`0x08008B50`), `0x15` (`0x08007C48`), `0x16` (`0x08007D74`), `0x17` (`0x08007C10`), `0x18` (`0x08008A34`), `0x19` (`0x08008760`), `0x1A` (`0x08007C88`), `0x1B` (`0x08007DA8`), `0x1C` (`0x0800892C`), `0x1D` (`0x08008838`), `0x21` (`0x08007BF4`), `0x22` (`0x08007BD8`), `0x23` (`0x08008A04`), `0x24` (`0x08008F64`), `0x25` (`0x08007DEC`), `0x27` (`0x08007CA4`), `0x28` (`0x08008D50`), `0x2A` (`0x08007CFC`), `0x2B` (`0x08007CDC`), `0x2C` (`0x08007D38`), `0x37` (`0x08007D1C`), `0x3C` (`0x080091FC`), `0x3D` (`0x08008E50`), `0x50` (`0x08008C30`), `0x51` (`0x08008D5C`), `0x52` (`0x08009180`), `0x53` (`0x08009104`), `0x54` (`0x08009088`), `0x55` (`0x08007DC4`), `0x56` (`0x08008670`), `0x57` (`0x08007CC0`), `0x58` (`0x08007D90`), `0x7B` (`0x08007B30`), `0x7C` (`0x0800A06C`).
- **Objetos `K*` en Kernel11 (`0x1FFB0910..0x1FFB09EA`):** `KDebug`, `KAddressArbiter`, `KAutoObject`, `KClientPort`, `KClientSession`, `KCodeSet`, `KDmaObject`, `KEvent`, `KMutex`, `KPort`, `KProcess`, `KResourceLimit`, `KSemaphore`, `KServerPort`, `KServerSession`, `KSession`, `KSharedMemory`, `KSynchronizationObject`, `KThread`, `KTimer`.
- **Objetos `K*` en Kernel9 (`0x080193E4..0x08019455`, tabla en `0x08018F28..0x08018F5C`):** `KAddressArbiter`, `KAutoObject`, `KCodeSet`, `KDmaObject`, `KEvent`, `KMutex`, `KProcess`, `KSemaphore`, `KSynchronizationObject`, `KThread`, `KTimer`.

---

## 5. CP15 y PMU en ARM11 (629 instrucciones) vs ARM9 (117 instrucciones) `[VERIFICADO]`

### 5.1 Hallazgo crítico del PMU en ARM11 MPCore

En la documentación anterior se asumía el mapeo ARMv7 (`c9, c12` / `c9, c13`). **Verificación directa en `arm11_section1.bin`:** hay **0 accesos** a `c9, c12/c13`. El ARM11 MPCore (ARMv6K) implementa su PMU en **`CP15 c15, c12, 0..3`**, y Kernel11 lo utiliza extensamente entre `0xFFF11074` y `0xFFF11768` (`0x1FF91074..0x1FF91768`):

| Registro CP15 | CRn | CRm | Opcode2 | Conteo (`mrc` / `mcr`) | Direcciones Ejemplo (Sec1) | Función Verificada |
|---------------|-----|-----|---------|--------------------------|----------------------------|--------------------|
| **PMNC** (Control) | `c15` | `c12` | `0` | 9 `mrc` / 6 `mcr` | `0x1FF91074`, `0x1FF911BC`, `0x1FF9145C`, `0x1FF9165C` | Habilitar/resetear contadores y seleccionar eventos |
| **CCNT** (Cycle Counter) | `c15` | `c12` | `1` | 1 `mrc` / 1 `mcr` | `0x1FF91510`, `0x1FF91734` | Leer/escribir contador de ciclos |
| **PMN0** (Event Counter 0) | `c15` | `c12` | `2` | 1 `mrc` / 2 `mcr` | `0x1FF911A0`, `0x1FF91538`, `0x1FF91768` | Leer/escribir contador de eventos 0 |
| **PMN1** (Event Counter 1) | `c15` | `c12` | `3` | 1 `mrc` / 2 `mcr` | `0x1FF911B0`, `0x1FF9155C`, `0x1FF916BC` | Leer/escribir contador de eventos 1 |

**Exposición vía SVC:**
- **`SVC 0x3E` (`0xFFF03664` → `0xFFF0AC44`)** expone un dispatcher de 9 casos (`0..8`) hacia las funciones PMU `0xFFF11070..0xFFF11668`, incluyendo lectura de `PMN0` (`r1=0`), `PMN1` (`r1=1`) y `CCNT` (`r1=2`) en `0xFFF11498`.
- **Permiso en Exheaders:** Ninguno de los 58 SysModules ni de los 5 módulos FIRM tiene el bit `0x3E` habilitado en su bitmap de syscalls de Exheader `[VERIFICADO]`; solo procesos que declaren `0x3E` en su Exheader pueden invocarlo.

### 5.2 Otros registros CP15 verificados en Kernel11 (`arm11_section1.bin`)

| Grupo CP15 | Conteo | Propósito Verificado |
|------------|--------|----------------------|
| `c0, c0, 5` (`mrc`) | 59 | MPIDR — ID de núcleo (`and rX, rX, 3`), usado también en `SVC 0x11` (`0xFFF06058`) |
| `c1, c0, 0..2` | 9 | SCTLR, ACTLR, CPACR (control del sistema y VFP) |
| `c2, c0, 0..2` / `c3, c0, 0` | 12 | TTBR0, TTBR1, TTBCR, DACR (tablas de páginas MMU) |
| `c5, c0, 0..1` / `c6, c0, 0` | 6 | DFSR, IFSR, FAR (diagnóstico de aborts en `0xFFF02084`/`0xFFF020CC`/`0xFFF184xx`) |
| `c7` (`c7, c4..c14`) | 491 | Limpieza/invalidación I-cache/D-cache y barreras (`c7,c10,5` DMB: 371 ocurrencias; `c7,c10,4` DSB: 43) |
| `c8, c7, 0/2/3` | 11 | Invalidación de TLB |
| `c13, c0, 1/3` | 9 | CONTEXTIDR / ASID y TPIDR (TLS usuario `0xFFFF9000`) |

En **ARM9 (`arm9.bin`)**, se verificaron 117 instrucciones CP15, incluyendo `c5, c0, 3` y `c6, c2/c5/c7, 0` (`0x0800A118..0x0800A134`) para configurar regiones del **MPU** (Memory Protection Unit) de ARM946E-S (no usa MMU con TTBR).

---

## 6. Comunicación PXI Verificada (ARM11 ↔ ARM9) `[VERIFICADO]`

Al extraer el SysModule **`pxi`** (`0004013000001402`, embebido en `arm11.bin` en `0x32200`, código `15,180 B`), se verificaron directamente sus registros MMIO, IRQs y servicios:

- **Dirección física PXI ARM11:** `0x10163000`, mapeada en Exheader mediante descriptor `0xFFE1EC63` a la dirección virtual **`0x1EC63000`** (referenciada en `pxi/code.bin` en `0x00101188`, `0x00101FC0`, `0x00101FDC`, `0x00101FF4`, `0x00102094`, etc.).
- **Registros verificados en `pxi/code.bin`:**
  - `+0x00` (`PXI_SYNC`, 32-bit): limpiado a `0` durante init/reset (`0x00101158`).
  - `+0x04` (`PXI_CNT`, 16-bit `ldrh`/`strh`):
    - Bit 1 (`0x0002`, `0x00101FCC`): **SEND FIFO Full** (polling antes de escribir `+0x08`).
    - Bit 3 (`0x0008`, `0x0010115C`): **Flush Send FIFO**; luego escribe `0xC008` (`0x00101180`) para habilitar FIFOs.
    - Bit 8 (`0x0100`, `0x00101FB0`): **RECV FIFO Empty** (polling antes de leer `+0x0C`).
    - Bits `0x0004` / `0x0400` (`0x00102014..0x00102044`): máscaras de interrupción TX/RX.
  - `+0x08` (`PXI_SEND`, 32-bit `str`): escritura a FIFO TX (`0x00101FD4`).
  - `+0x0C` (`PXI_RECV`, 32-bit `ldr`): lectura de FIFO RX (`0x00101FB8`, drenado 8× en init `0x00101164..0x00101174`).
- **IRQs PXI en Exheader y `pxi/code.bin`:** `80, 81, 82, 83` (`0x50..0x53`), enlazadas mediante `svcBindInterrupt` (`SVC 0x50` en `0x00102BD4`): **`0x52` (82)** para recepción (`0x0010204C`) y **`0x53` (83)** para envío (`0x00102020`).
- **Servicios registrados por `pxi`:** `pxi:am9`, `pxi:dev`, `pxi:mc`, `pxi:ps9` (strings en `0x00103866..0x0010387D`).
- **Lado ARM9 (`arm9.bin`):** El literal **`0x10008000`** (base MMIO PXI del ARM9) está verificado en Kernel9 (`0x0800A148`) y en 12 ubicaciones de Process9 (`0x0801D4F0..0x0804D28C`).

---

## 7. Análisis Profundo con Pseudocódigo C (REA + Ghidra 12.2) `[VERIFICADO]`

Utilizando **REA `6.10.1` + Ghidra `12.2`** se descompilaron a C **654 funciones de `arm11_section1.bin`** (`pseudocodigo_k11/`, 0 fallos) y **2,673 funciones de `arm9.bin`** (`pseudocodigo_arm9/`, 14 fallos por instrucciones solapadas ARM/Thumb).

### 7.1 Criterio Estricto de Confianza (`CONFIRMED` vs `EVIDENCE_BASED`)
- **`CONFIRMED`:** Anclaje determinista en contrato hardware/formato o semántica 100% auto-contenida verificada línea por línea en ASM/C (header FIRM, vectores ARM, los 109 SVCs de `0xFFF02328`, los 40 SWIs de `0x08007938`, vtables C++ + `destructor` + `GetTypeObj`, accesos CP15/MMIO literales exactos, primitivas atómicas `ldrex`/`strex`/`dmb`, rutinas CRT/EABI completas en C, y XREFs directos a strings reales).
- **`EVIDENCE_BASED`:** Pertenencia demostrada a un subsistema/clase mediante C, códigos `Result`, slots de vtable compartidos o callgraph directo sin contaminación CRT, pero cuyo contrato completo o nombre fuente original requiere seguir cruzando callers/estructuras.
- **`HYPOTHESIS`: 0** (todos los falsos positivos no-código fueron depurados).

### 7.2 Hallazgos Verificados en Pseudocódigo C de Kernel11 (`arm11_section1.bin`)
- **Arranque de módulos integrados (`kernel11_launch_firm_sysmodules` @ `0xFFF00EAC`):** Itera directamente la región virtual **`[0xDFF00000..0xDFF355FC)`** (exactamente `0x35600` bytes = los 5 NCCH embebidos en FIRM Section 0 `arm11.bin`), valida ExHeader (`0xFFF025C4`), crea `KCodeSet` y lanza los procesos iniciales (`fs`, `loader`, `pm`, `sm`, `pxi`).
- **Herencia de prioridad (`KMutex_acquire_and_inherit_priority` @ `0xFFF2917C` / `KMutex_release_and_restore_priority` @ `0xFFF290DC`):** Manipulan la lista de mutexes poseídos del hilo (`KThread+0x60/0x64` vía `0xFFF2A9C0`/`0xFFF2AA20`), recorren la cola buscando la menor prioridad (`< 0x3f` en `thread+0x6c`) y actualizan la prioridad dinámica del propietario (`0xFFF1B4BC`/`0xFFF1B56C`).
- **Compilador de microcódigo CDMA PL330 (`0xFFF2B48C` 392L, `0xFFF285D8`, `0xFFF286F8`, `0xFFF287E0`):** Emite dinámicamente instrucciones del motor ARM PL330 (`0xBC` CCR de 6 bytes en `0xFFF285D8`, `DMALP` `0x20 | lc<<1` en `0xFFF286F8`, `DMALPEND` `0x38 | lc<<2` en `0xFFF287E0`) para transferencias 1D/2D.
- **Códigos `Result` más frecuentes en C de Kernel11:** `0xE0E01BF5` / `0xE0A01BF5` (30+11 funcs, `InvalidAddress`), `0xD8E007FD` (21 funcs, `InvalidState/Busy`), `0xD86007F3` (18 funcs, `OutOfMemory`), `0xD8E007F7` (18 funcs, `InvalidHandle`), `0xD8E007F6` (14 funcs, `InvalidEnum/Cmd`), `0xF8C007F4` (13 funcs, fatal `NotImplemented`), `0xC8601801` (8 funcs, `ResourceLimitReached`), `0xD920060D` (3 funcs, `Timeout`).

### 7.3 Hallazgos Verificados en Pseudocódigo C de ARM9 (`arm9.bin`)
- **Separación real de CRT vs Subsistemas:** Se identificaron en C `p9_memcpy` (`0x08056CBC`, 121 callers), `p9_memcpy32_aligned` (`0x08056B28`), `p9_memset_byte` (`0x08056014`), `p9_memzero32_aligned` (`0x08056C68`), `p9_memcmp` (`0x08056C38`), `p9_aeabi_uidivmod` (`0x08056D90`), `p9_aeabi_lmul` (`0x08055B6C`), `p9_utf16_strlen` (`0x08055AF0`), `k9_critical_section_enter/leave` (`0x080124F4`/`0x08012628`) y `k9_slab_alloc/free` (`0x080122AC`/`0x08011738`), evitando que sus llamadores hereden dominios falsos.
- **Tablas de dispatch e interfaces en `.rodata` de Process9 (`0x08083214..0x08089000`):** Se identificaron **252 tablas de punteros**, incluyendo 35 tablas con el stub común **`0x0807CE35`** (`a9=0x08071D34`, `movs r0, 0; push {r4, lr}; ...`) para métodos/comandos no implementados y 39 tablas asociadas a subsistemas concretos (`dbs` 15 slots, `ctx` 23 slots, `quota` 14 slots, `sha` 4 slots, `aes`, `sysdata`, `spi9`, `firm`).
- **Payload relocalizable de `FIRMLaunch` en `.rodata` de Process9 (`0x08089074..0x08089B8C`):** Aunque el ExHeader fija `.text` en `0x08028000..0x0808E314` (`a9_va 0x0801CF00..0x08083214`) y `.rodata` en `0x0808E314..0x08094C8C` (`a9_va 0x08083214..0x08089B8C`), el tramo `0x08089074..0x08089B8C` (referenciado por `0x0807A470` como runtime `0x08094174`) contiene **código Thumb + ARM32 ejecutable** que Ghidra detectó (`0x080892A0..0x08089678`) y que reconfigura el MPU (`c6, c4, 0 = 0x18000035` Región 4 VRAM/RAM y Región 5) mientras accede a `SHA` (`0x1000A000`), `AES` (`0x10009000`) y `NDMA` (`0x10002000`).
