# Protocolo PXI (ARM11 ↔ ARM9) — Análisis Verificado ARM11 (`FIRM:pxi`) y ARM9 (`Process9`)

> `[VERIFICADO]` Toda la información marcada como `[VERIFICADO]` proviene directamente del análisis estático (Ghidra `12.2` vía REA + desensamblado `radare2 5.9.8` + ExHeaders decodificados) sobre los binarios descifrados de este repositorio:
> - Módulo FIRM ARM11 `pxi`: [`code.bin`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/pxi/code.bin), [`exheader.bin`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/pxi/exheader.bin), tabla [`pxi_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/pxi/pxi_friendly.sym) (`111` símbolos, `0 HYPOTHESIS`)
> - Kernel9 + Process9 ARM9: [`arm9.bin`](file:///home/skels/3ds-reversing/binarios_descifrados/kernel/arm9.bin), tabla [`arm9_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/kernel/arm9_friendly.sym) (`4,849` símbolos, `0 HYPOTHESIS`)
> - Clientes ARM11 verificados: `FIRM:fs`, `FIRM:loader`, `SysModule ptm` (`0004013000002202`)

---

## 1. Visión General

El controlador hardware **PXI** (*Processor eXchange Interface*) es el único canal bidireccional directo de mensajería y sincronización entre el procesador de aplicaciones (**ARM11 MPCore**) y el procesador de seguridad (**ARM946E-S**). En el firmware de 3DS:

- **Lado ARM11 (`FIRM:pxi`, TitleID `0x0004013000001402`)**: ejecuta en userland privilegio kernel-mapeado (ExHeader sin ACLs de `srv:`, `.text=0x00100000+0x3844`, `.rodata=0x00104000+0x2BC`, `.data=0x00105000+0x4C`, `.bss=0x196D8`). Expone **9 servicios IPC** hacia userland/sysmodules mediante `srv:RegisterService` (`0x00100994`) y traduce cada petición IPC de ARM11 al FIFO hardware PXI hacia ARM9 (`0x001013FC`).
- **Lado ARM9 (`Kernel9 + Process9` en `arm9.bin`)**: Kernel9 maneja la interrupción física PXI (IRQ `12`, controlador `0x10008000`) y Process9 (`0x08081DBC` en vista de carga `0x08006800`, relocalizado a `+0xB100` en tiempo de ejecución) inicializa las colas PXI, atiende cada canal en sus tablas de salto ARM y devuelve la respuesta por el FIFO inverso.

---

## 2. Registros MMIO Hardware e Interrupciones `[VERIFICADO]`

### 2.1 Capacidades ExHeader ARM11 (`pxi/exheader.bin`)

- **Descriptores Kernel11**: mapa IO estático `0xFFE1EC63` → página `0x1EC63000..0x1EC63FFF`.
- **Interrupciones concedidas en ExHeader**: IRQs `[80, 81, 82, 83]` (`0x50..0x53`).
- **Interrupciones realmente enlazadas** en `pxi_hw_bind_irqs_80_82_83` (`0x001021A8`, vía `SVC 0x50 BindInterrupt`):
  - **IRQ `80` (`0x50`)**: PXI Remote SYNC IRQ (`param_1`). Activa el bit `0x80` en `PXI_SYNC + 3` (`*(byte*)(base + 3) |= 0x80`).
  - **IRQ `82` (`0x52`)**: PXI SEND FIFO Empty IRQ (`param_3`). Activa el bit `0x0004` en `PXI_CNT` (`*(ushort*)(base + 4) = (*(ushort*)(base + 4) & 0x8404) | 4`).
  - **IRQ `83` (`0x53`)**: PXI RECV FIFO Not-Empty IRQ (`param_2`). Activa el bit `0x0400` en `PXI_CNT` (`*(ushort*)(base + 4) = (*(ushort*)(base + 4) & 0x8404) | 0x400`).
  - *(IRQ `81` aparece concedida en ExHeader pero `0x001021A8` y `0x00101FF8` no la enlazan.)*

### 2.2 Mapa de Registros PXI (`0x1EC63000` ARM11 ↔ `0x10008000` ARM9)

Verificado en `pxi` (`0x0010114C`, `0x00101190`, `0x00101C48`, `0x00101FA8`, `0x00101FC4`, `0x001021A8`, `0x00102E14`) y ARM9 (`0x0801DE10`, `0x08020034`, `0x08023B68`, `0x08026AD4`):

| Offset | Ancho | Nombre hardware `[CONOCIMIENTO PÚBLICO 3DS]` | Comportamiento observado en binario `[VERIFICADO]` |
|---|---|---|---|
| `+0x00` | `u32` / byte `+3` | `PXI_SYNC` | `pxi_hw_map_mmio` (`0x0010114C`) escribe `0` en `+0x00`. En `+0x03`: bit `0x80` habilita IRQ SYNC local (`0x001021A8` / `0x00101FF8`); escribir máscara en `+0x03` (`0x08023B68`: `*(byte*)(base+3) \|= val`, ARM11 `0x00101C48` / `0x00101C7C`) dispara señal SYNC al núcleo remoto (`0x40`) o controla handshake. |
| `+0x04` | `u16` | `PXI_CNT` | • **Bit 1 (`0x0002`)**: `SEND_FIFO_FULL` — `pxi 0x00101C48`/`0x00101FC4` esperan mientras `(*(u16*)(base+4) & 2) != 0`; ARM9 `0x08026AD4` espera `lsls r3, r3, 0x1e; bmi`.<br>• **Bit 2 (`0x0004`)**: `SEND_FIFO_EMPTY_IRQ_EN` — activado en `0x001021A8`.<br>• **Bit 3 (`0x0008`)**: `SEND_FIFO_CLEAR` / reset — `0x0010114C` y `0x001011A8` escriben `8`, iteran retardo (`i < 0x10`, paso `2`) y escriben `0` y luego `uVar2` (bit `0x8000` enable en máscaras `0x8404`/`0x8004`/`0x8400`).<br>• **Bit 8 (`0x0100`)**: `RECV_FIFO_EMPTY` — ARM11 `0x00101FA8`/`0x00102E14` esperan `(*(u16*)(base+4) & 0x100) != 0`; ARM9 `0x0801DE10` devuelve `((u16)PXI_CNT & 0x1ff) >> 8` y `0x08020034` sondea `lsls r3, r3, 0x17; bmi`.<br>• **Bit 10 (`0x0400`)**: `RECV_FIFO_NOT_EMPTY_IRQ_EN` — activado en `0x001021A8`. |
| `+0x08` | `u32` (WO) | `PXI_SEND` FIFO | Escritura de palabras de 32 bits (`pxi 0x00101FC4`/`0x00101C48`, ARM9 `0x08026AD4`). |
| `+0x0C` | `u32` (RO) | `PXI_RECV` FIFO | Lectura de palabras de 32 bits (`pxi 0x00101FA8`/`0x00102E14`, ARM9 `0x08020034`). |

En ARM9 (`kernel9`), la gestión física usa la base `0x10008000` (`k9_pxi9_drv_01_0x0800A0D0` e helpers `p9_pxi9_*` entre `0x0801D4D4` y `0x0804D280`) atendiendo la IRQ `12` en `k9_irq_dispatch` (`0x08012248`).

---

## 3. Los 9 Canales PXI y Tabla de Registro (`0x00104044`) `[VERIFICADO]`

En ARM11 `pxi/code.bin` (`.rodata` @ `0x00104044`, 9 entradas de `12` bytes), cada descriptor contiene `[u32 str_ptr, u8 ch_id, u8 buf_start_slot, u8 max_sessions, u8 pad, u32 unk_init]`. El bucle principal `pxi_server_main_loop` (`0x001000AC`) los registra en `srv:` e indexa los slots internos por **`ch_id` (`0..8`)** (`0x11BCE4 + ch_id * 0x14`):

| `ch_id` (wire) | Índice tabla `0x104044` | Servicio ARM11 | `byte+5` (primer slot libre) | Máx. búferes estáticos 4KB permitidos | `max_sessions` (`byte+6`) | Dispatcher ARM9 Process9 (`0x08081DBC`, vista carga / `+0xB100` runtime) |
|---:|---:|---|---:|---:|---:|---|
| **`0`** | 7 | `pxi:mc` | `0` | **0** (`4 - 0` slots liberados) | `1` | `0x0807F0F4` (runtime `0x0808A1F4`), `13` casos (`0x00..0x0C`) |
| **`1`** | 0 | `PxiFS0` | `2` | **2** (`4 - 2` slots liberados) | `1` | `0x0807C61C` (runtime `0x0808771C`), `87` casos (`0x00..0x56`) |
| **`2`** | 1 | `PxiFS1` | `2` | **2** | `1` | Comparte `0x0807C61C` |
| **`3`** | 2 | `PxiFSB` | `2` | **2** | `1` | Comparte `0x0807C61C` |
| **`4`** | 3 | `PxiFSR` | `2` | **2** | `1` | Comparte `0x0807C61C` |
| **`5`** | 4 | `PxiPM` | `1` | **1** (`4 - 1` slots liberados) | `1` | `0x0807F2B0` (runtime `0x0808A3B0`), `4` casos (`0x00..0x03`) |
| **`6`** | 6 | `pxi:dev` | `4` | **4** (`0` liberados anticip.) | `2` | `0x0807AE24` (runtime `0x08085F24`), `16` casos (`0x00..0x0F`) |
| **`7`** | 5 | `pxi:am9` | `4` | **4** | `1` | `0x0807F8FC` (runtime `0x0808A9FC`), `110` casos (`0x00..0x6D`) |
| **`8`** | 8 | `pxi:ps9` | `4` | **4** | `1` | `0x0807F4B0` (runtime `0x0808A5B0`), `14` casos (`0x00..0x0D`) |
| *(slot 9 ARM9)* | — | *(interno)* | — | — | — | Stub `0x08081C30` (`SVC 0x18 SignalEvent`) inicializado en bucle `10` de `0x08081DBC` (`0x08065BDA`) |

> **Nota sobre `byte +5` en `pxi 0x001013FC` (líneas 551–565):** tras recibir una petición IPC, `pxi` asigna siempre hasta `4` páginas compartidas de `4 KB` para la respuesta en `TLS+0x180`, pero inmediatamente libera de la máscara `local_5c` los slots desde `uVar8 = *(byte*)(local_4c + 0x0F)` (copiado desde `table_entry + 5`) hasta `3`. Si una petición trae descriptores de búfer que ya no tienen slot retenido, quedan descartados por política del canal (`pxi:mc` = `0` búferes estáticos, `PxiPM` = `1`, `PxiFS*` = `2`, `pxi:dev/am9/ps9` = `4`).

---

## 4. Formato de Trama en el Cable FIFO y Traducción de Búferes `[VERIFICADO]`

### 4.1 Encapsulación de mensajes (`pxi_send_command_body` `0x00101CC8` ↔ `pxi_rx_dispatch_from_fifo` `0x00102A04`)

1. **Adquisición de exclusión mutua TX** (`0x00101CC8`): espera el mutex PXI (`SVC 0x24` o `0x00102B20`).
2. **Palabra 0 (`ch_id`)**: se escribe el byte identificador del canal (`0..8`) en `PXI_SEND` (`0x00101FC4`).
3. **Verificación/disparo SYNC**: consulta `0x00101C7C` (`*(u16*)(base+4) >> 1 & 1`) y entra a `0x00101C48`.
4. **Cálculo estricto de longitud de trama IPC**:
   ```c
   uint32_t total_words = (cmd_hdr & 0x3F) + ((cmd_hdr & 0xFC0) >> 6) + 1;
   ```
   - `cmd_hdr & 0x3F`: número de parámetros normales (`N`, bits `0..5`).
   - `(cmd_hdr & 0xFC0) >> 6`: número de palabras de traducción (`T`, bits `6..11`).
   - `+ 1`: incluye la propia cabecera `cmd_hdr`.
   - **Límite duro verificado** en ambos sentidos: tanto el emisor IPC (`0x001013FC`, `if (0x100 < uVar8) Break()`) como el receptor FIFO (`0x00102A04`, `if (0x40 < iVar4 + 1U) Break()`) fuerzan **`total_words <= 0x40` (`<= 64` palabras = `256` bytes máximo)**.
5. **Envío de palabras**: `0x00101C48` escribe `total_words` de 32 bits en `PXI_SEND` (`+0x08`) sondeando `SEND_FIFO_FULL` (`+0x04 & 2`), y libera el mutex (`SVC 0x14`).
6. **Recepción y encolado en ARM11 (`0x00102A04` y `0x00102F08`)**:
   - Lee `ch_id` con `0x00101FA8`, valida `0 <= ch_id < param_1[1]` (`9`).
   - Verifica que el canal no tenga una recepción activa (`puVar6[4] == 0`), lee `cmd_hdr`, valida `total_words <= 0x40` y lee `total_words - 1` palabras vía `0x00102E14` en `puVar6[3]`.
   - Ejecuta el callback `(**puVar6)(puVar6, puVar6[3])`; si devuelve `0`, enlaza la respuesta en la lista del hilo IPC y despierta por `ArbitrateAddress` (`0x00101EF0`) al servidor `0x001013FC` (`SVC 0x4F ReplyAndReceive`), que copia `total_words * 4` bytes al `TLS + 0x80` mediante `0x00102830`.
   - Si el callback devuelve distinto de `0` (ej. `0x00102F08`), decrementa el semáforo por `ArbitrateAddress` (`0x00101BD0`), marca respuesta recibida y llama a `ReleaseSemaphore` (`0x00101BB8`) y `SVC 0x18 SignalEvent` cuando `byte+0x34 > 1`.

### 4.2 Traducción de Búferes Estáticos con Páginas de `4 KB` (`0x001013FC`)

Porque el núcleo ARM9 no ve el espacio virtual paginado por la MMU del ARM11 de cada proceso userland:
- `pxi` mantiene un mapa de bits de páginas libres de **`4 KB` (`0x1000` bytes)** en `local_28[7]` sobre una región lineal base `local_28[6]`.
- En `0x001013FC` (líneas 326–345 y 577–599), antes de ejecutar `SVC 0x4F ReplyAndReceive`, asigna hasta `4` índices usando **`LZCOUNT(local_28[7])`** (`slot = 31 - clz`):
  - Si hay slot disponible: escribe en `TLS + 0x180 + i*8` el descriptor de búfer estático de recepción kernel **`0x04000002`** y la dirección **`local_28[6] + slot * 0x1000`**.
  - Si no hay slots: escribe `2` (búfer vacío).
- Durante la ida hacia ARM9 (`pxi` → Process9), los búferes estáticos ya aterrizaron en memoria física/compartida contigua; al finalizar y responder al cliente ARM11 (líneas 488–502), los bits correspondientes vuelven a activarse en `local_28[7]` (`*puVar13 |= 1 << (slot & 0x1F)`).

---

## 5. Detalle Verificado de Cada Canal y Handlers en Process9

### 5.1 Canal 0 — `pxi:mc` (Control de energía, Sleep/Wake y CFG9) `[VERIFICADO]`

- **Bloqueo de sueño en ARM11 (`pxi 0x001013FC`, líneas 532–549)**:
  - `pxi` intercepta explícitamente toda petición dirigida al **canal `0` (`pxi:mc`) con comando `5` (`cmd_hdr >> 16 == 5`)**:
  - Si `[TLS + 0x84] != 0`: si el bloqueo global `*(puVar6 + 0x68)` ya estaba activo lanza `Break()`, en caso contrario activa **`*(puVar6 + 0x68) = 1`** y marca `local_40 = 1`. Mientras este bloqueo esté activo, `0x001013FC` solo envía hacia ARM9 mensajes marcados urgentes y detiene nuevas transmisiones normales (`local_40 == 0` queda retenido si `*(puVar6 + 0x68) != 0`).
  - Si `[TLS + 0x84] == 0` (`cmd 5` con argumento `0`): exige que el bloqueo estuviera activo y marca `local_40 = 2`. Al completarse la respuesta (`cVar4 == 2`, líneas 482–487), verifica `in_flight == 0` y limpia `*(puVar6 + 0x68) = 0`.
- **Cliente `SysModule ptm` (`0x001010F8`)**: conecta al servicio `"pxi:mc"` (`DAT_00101200 -> 0x0010D31A`), crea un evento con `SVC 0x17` (`0x0010BC00`) y lanza el hilo `0x0010268F` (`0x0010268E` Thumb → `0x00103184`), que coordina transición de estado/sleep (`0x00103F6C` / `0x00104378` / `0x001043BC` y `SVC 0x7C KernelSetState` en `0x001053F0`). Además, `pxi_server_main_loop` (`0x001000AC`) envía `pxi:mc cmd 1` (`0x00010000`) durante su secuencia de apagado/notificación `srv:`.
- **Handlers ARM9 (`0x0807F0F4`, vista carga; `13` entradas `0..0xC`)**:
  - `cmd 0x00` (`0x0807F268`): inválido (`hdr=0x40`, devuelve `0xD900182F`).
  - `cmd 0x01` (`0x0807F14C`): llama `0x0807B954(r1)` — dispara `SVC 0x18 SignalEvent` sobre dos handles (`[r0]` y `[r4+4]`) y escribe **`*(u32*)0x10010000 = 1`** (`CFG9_EXT` en `0x0807B980`), devuelve `hdr=0x00010040`, `[4]=res`.
  - `cmd 0x02` (`0x0807F168`): stub `hdr=0x00020040`, `[4]=0`.
  - `cmd 0x03` (`0x0807F17C`): escribe `hdr=0x000300C0`, `[4]=0`, `[8]=r1`, `[12]=r0`.
  - `cmd 0x04` (`0x0807F198`): stub `hdr=0x00040040`, `[4]=0`.
  - `cmd 0x05` (`0x0807F1AC`): lee byte con signo `[r4+4]` y llama `0x0807B9D4(r2, s8)` — si `param_2 != 0` marca `*(param_1+8) = 3` y ejecuta `SVC 0x18 SignalEvent`; si `param_2 == 0` llama `0x0807ADD0`. Al despertar (`0x0807B9A0`), si `*(param_1+8) == 3`, ejecuta **`SVC 0x7C`** y limpia estado. Devuelve `hdr=0x00050040`.
  - `cmd 0x06` (`0x0807F1CC`): stub `hdr=0x00060040`, `[4]=0`.
  - `cmd 0x07` (`0x0807F1E0`): devuelve `hdr=0x00070080`, `[4]=0` y byte `[r4+8]=r0`.
  - `cmd 0x08` (`0x0807F1F8`) y `cmd 0x09` (`0x0807F204`): devuelven explícitamente **`0xE0C0EC03`** con cabecera `0x00080040` / `0x00090040`.
  - `cmd 0x0A` (`0x0807F210`): pasa 3 palabras `[r4+4..+12]` a Thumb `0x08033290` (invoca `0x080331F8` y `0x08055884`, rellena struct `0x08094F60+0x8..+0x14`, escribe `*(u8*)0x08094F60 = 1`), devuelve `hdr=0x000A0040`, `[4]=0`.
  - `cmd 0x0B` (`0x0807F238`): stub `hdr=0x000B0040`, `[4]=0`.
  - `cmd 0x0C` (`0x0807F24C`): copia `0x80` bytes de pila hacia `[r4+4]` vía `0x08056B28` (`p9_memcpy32_aligned`), devuelve `hdr=0x000C0040`, `[4]=0`.

### 5.2 Canales 1..4 — `PxiFS0`, `PxiFS1`, `PxiFSB`, `PxiFSR` `[VERIFICADO]`

- **Lado ARM11 (`FIRM:fs`)**: [`fs_friendly.sym`](file:///home/skels/3ds-reversing/binarios_descifrados/firm_modulos/fs/fs_friendly.sym) verifica **`83+` wrappers `swi 0x32`** entre `0x0012F410..0x00130ACC` (además de `0x00124CE4`, `0x00125450`, `0x001254F4`). Todas las cabeceras coinciden bit a bit con ARM9:
  - Ejemplo verificado contra tabla: `cmd 0x01` usa `0x000101C2` (`7` normales, `2` traducción; `fs:0x00130958` ↔ ARM9 `0x0807C7B4`), `cmd 0x02` usa `0x00020142` (`0x0012F494` ↔ `0x0807C8D4`), `cmd 0x03` usa `0x00030244` (`0x0012F5F4` ↔ `0x0807C9CC`), `cmd 0x05` usa `0x00050202` (`0x0012F410` ↔ `0x0807CC78`), `cmd 0x41` usa `0x00410000` (`0x0012F46C` ↔ `0x0807E63C` / `0x0806A894`), `cmd 0x55` usa `0x00550082` (`0x0012FA84` ↔ `0x0807EF1C`), `cmd 0x56` usa `0x00560102` (`0x00130764` ↔ `0x0807EF84`).
- **Lado ARM9 (`0x0807C61C`, `87` entradas `0x00..0x56`)**: `cmd 0x00` es inválido (`0x0807F044`), mientras todas las entradas `0x01..0x56` son activas y despachan operaciones de archivo/archivo-directo, SDMC (`0x08025F30`), NAND DB (`0x0806F15C`), ExtData (`0x0806C354`), CTRCARD/NTRCARD (`0x0804576C`, `0x0806B164`), SPICard (`0x0806B238`, `0x0807043C`) y gestión de claves (`0x0806A970`).

### 5.3 Canal 5 — `PxiPM` (Carga y Registro de Procesos) `[VERIFICADO]`

Correlación exacta verificada entre **`FIRM:loader`** y **`Process9 @ 0x0807F2B0`**:

| `cmd` | Cabecera entrada | Cliente `FIRM:loader` | Handler ARM9 (`0x0807F2B0`) + comportamiento verificado |
|---:|---|---|---|
| `0x01` | `0x00010082` (desc `(w3&0xff)==4`, `len>=0x400`) | `ldr_pxipm_GetProgramInfo_0x10082` (`0x14001B70`) | `0x0807F308`: llama Thumb **`0x0803366C`** para obtener el `ExHeader` (`0x400` B); responde `hdr=0x00010041`, `[4]=res`, `[8]=4`. |
| `0x02` | `0x00020200` (`u64 ProgramInfo` + `ProgramUpdateInfo`) | `ldr_RegisterProgram` (`0x14000F80` → `0x14002E48`) | `0x0807F378`: copia `ProgramInfo` (`[r4+4..+0x20]`), valida permisos/medio y llama Thumb **`0x08033448`**; responde `hdr=0x000200C0`, `[4]=res`, `[8..12]=out_program_handle` (`u64`). |
| `0x03` | `0x00030080` (`u64 program_handle`) | `ldr_UnregisterProgram` (`0x14001E28` → `0x14002EB0`) | `0x0807F474`: llama Thumb **`0x08033604`** (`0x08033BBC` + `0x0807684A`) para dar de baja el programa; responde `hdr=0x00030040`, `[4]=res`. |

### 5.4 Canal 6 — `pxi:dev` (Dispositivos / Cartucho / CardIO) `[VERIFICADO]`

Tabla ARM9 **`0x0807AE24`** (`16` entradas `0x00..0x0F`, `max_sessions = 2` en `pxi`):
- `0x00`: inválido (`0x0807B3E8`, `0xD9001830`).
- Comandos activos `0x01..0x0F` con cabeceras verificadas:
  - `0x01` (`0x000101C2` → `0x0807B464`), `0x02` (`0x000201C2` → `0x0807B544`), `0x03` (`0x00030102` → `0x0807B4D4`), `0x04` (`0x00040102` → `0x0807B5B4`), `0x05` (`0x00050102`), `0x06` (`0x00060102`), `0x07` (`0x00070040`), `0x08..0x0B` (llaman helpers `p9_ntrcard_caller_*` `0x0806C8C8..0x0806CB78`, headers `0x00080040`, `0x00090040`, `0x000A0080`, `0x000B0080`), `0x0C` (`0x000C0042` → `0x0806CAD4`), `0x0D` (`0x000D0688`), `0x0E` (`0x000E0284`), `0x0F` (`0x000F0080` → `0x0807B8AC`).

### 5.5 Canal 7 — `pxi:am9` (Application Manager ARM9) `[VERIFICADO]`

Tabla ARM9 **`0x0807F8FC`** (`110` entradas `0x00..0x6D`, vista carga `0x0807F920`):
- `0x00`, `0x2B..0x38`, `0x3A`, `0x66` apuntan al manejador de error por defecto `0x08081B18` (runtime `0x0808CC18`).
- Los **`93` comandos activos** son: `0x01..0x2A`, `0x39`, `0x3B..0x65`, `0x67..0x6D`, invocando funciones internas Thumb/ARM en `0x080347D0..0x0803D7DC` y `0x0807C610`.

### 5.6 Canal 8 — `pxi:ps9` (Criptografía RSA/AES y Generación Aleatoria) `[VERIFICADO]`

Tabla ARM9 **`0x0807F4B0`** (`14` entradas `0x00..0x0D`):
- `0x00`: inválido (`0x0807F894`, `0xD9001830`).
- `0x01` (`0x000100C6` → `0x0807BF54`), `0x02` (`0x00020284` → `0x0807BAD4`, firma/operación módulo hasta `0x800` bits), `0x03` (`0x00030284` → `0x0807BBF8`, verificación RSA hasta `0x800` bits `2048`-bit), `0x04` (`0x000401C4` → `0x0807BCDC`), `0x05` (`0x00050284`), `0x06` (`0x00060140` → `0x0807C528`, genera `0x10` bytes aleatorios vía `0x08042958`), `0x07` (`0x00070180` → `0x0807C568`, PRNG/DRBG `0x08042958` + `0x0804D976`), `0x08` (`0x00080080`), `0x09` (`0x00090080`), `0x0A` (`0x000A00C0`), `0x0B` (`0x000B0080`), `0x0C` (`0x000C0042`), `0x0D` (`0x000D0042` → `0x08042014`).

---

## 6. Diferencias respecto a Conocimiento Genérico `[VERIFICADO]`

1. **Orden en tabla `.rodata` vs `ch_id` de cable**: En `pxi 0x00104044`, la primera entrada es `PxiFS0` (`ch_id=1`) y la entrada `7` es `pxi:mc` (`ch_id=0`); el canal `0` no es necesariamente la entrada `0` del array estático, sino el valor `byte +4` del struct de registro.
2. **Descarte automático de descriptores estáticos (`byte +5`)**: `pxi:mc` fuerza `0` búferes estáticos retenidos, `PxiPM` retiene `1` (`ExHeader` `0x400` B), `PxiFS*` retienen `2`, y solo `pxi:dev/am9/ps9` retienen hasta `4`.
3. **Interrupción `81` no usada**: Aunque el ExHeader de `FIRM:pxi` concede `80, 81, 82, 83`, el código verificado en `0x001021A8` enlaza exclusivamente `80`, `82` y `83`.
4. **ARM11 SHA11 en `FIRM:fs`**: Las operaciones de hash de `FS` en ARM11 ya no viajan necesariamente a `pxi:ps9` — `FIRM:fs` mapea directamente el motor hardware `SHA11` (`0x1EC01000` / `0x1EE01000`, `0x00130C08..0x00131054`) en su propio ExHeader.
