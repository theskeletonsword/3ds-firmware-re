# (b) Tabla y script de símbolos recreados — Nintendo 3DS (ARM11/ARM9)

> **Estado de evidencia:** `[VERIFICADO EN ESTE REPO]` — Se descifraron los kernels FIRM (`arm11_section1.bin`, `arm9.bin`, `arm11.bin` con 5 módulos FIRM integrados) y **58 SysModules** (`binarios_descifrados/SysModule_*/`) con `ctrtool` + `aes_keys.txt` + `movable.sed`. Las tablas de §6 documentan las funciones detectadas (`binarios_descifrados/analisis/SysModule_*_funcs.txt`) y los SVCs reales de los 58 SysModules y los 5 módulos FIRM.
>
> Este documento entrega:
> 1. Un **formato/plantilla de tabla de símbolos** lista para rellenar una vez dispongamos de `arm9.bin`, `arm11.bin`, `code.decompressed.bin` y `exheader.bin` descifrados.
> 2. **Scripts concretos** (objdump, radare2, Ghidra, REA) para localizar, verificar y exportar símbolos semánticos (nombres de funciones, structs, enums, direcciones/offsets).
> 3. Una **regla de oro**: solo se registra un nombre/dirección si está confirmado por referencias cruzadas en el binario. Queda expresamente prohibido inventar nombres no confirmados.

---

## 1. Formato de la tabla de símbolos (plantilla vacía)

| # | Núcleo | Dirección (VA) | Offset en archivo | Nombre semántico | Tipo | Struct/Enum asociado | Firma de verificación | Fuente | Estado |
|---|--------|----------------|-------------------|------------------|------|----------------------|-----------------------|--------|--------|
| 1 | ARM11 | `0x0800XXXX` | `0xXXXXXX` | `kernel_svc_handler` | Función | `svc_table_t` | Referencias cruzadas desde SVC dispatcher | Ghidra + r2 | PENDIENTE (binario cifrado) |
| 2 | ARM9 | `0xFFFF0000` | `0xXXXXXX` | `firm9_reset_vector` | Función | — | Vector de reset en 0xFFFF0000 | objdump | PENDIENTE |
| 3 | ARM11 | `0x08YYYYYY` | `0xYYYYYY` | `pxi_send_command` | Función | `pxi_msg_t` | Llamada desde syscall PXI | r2 + objdump | PENDIENTE |
| … | … | … | … | … | … | … | … | … | … |

**Reglas de llenado (obligatorias):**
- `Dirección (VA)`: dirección virtual de carga (ej. `0x08000000` + offset de sección). Debe coincidir en objdump, r2 y Ghidra.
- `Offset en archivo`: offset real dentro del binario `.bin` (para poder volver a inspeccionar con `xxd` / `objdump -s`).
- `Nombre semántico`: solo si se confirma por contexto (cadenas de referencia, llamadas, structs adjacentes). Si no hay confirmación, poner `sub_0xXXXXXX` (nombre sintético de Ghidra/r2) y marcar Estado = `NO CONFIRMADO`.
- `Tipo`: `Función`, `Variable global`, `Struct`, `Enum`, `Constante`, `Vector de excepción`, `Tabla de SVC`.
- `Struct/Enum asociado`: nombre del struct/enum al que pertenece o que usa.
- `Firma de verificación`: instrucciones o datos que demuestran la identificación (ej. `stmfd sp!, {r4-lr, pc}`, `svc #0xXX`, cadena `"PXI:"` cercana).
- `Estado`: `CONFIRMADO` / `PENDIENTE` / `NO CONFIRMADO` / `HIPÓTESIS`.

> Ninguna fila de esta tabla debe rellenarse con datos inventados. Mientras no haya binarios descifrados, la tabla permanece vacía con estado `PENDIENTE`.

---

## 2. Scripts para reproducir el descubrimiento y verificación de símbolos

### 2.1 objdump — desensamblado y búsqueda de funciones/SVC

```bash
# ARM11 (ARMv6K, little-endian)
objdump -D -m arm -M force-thumb --no-show-raw-insn \
  --adjust-vma=0x08000000 \
  arm11.bin > arm11.disasm.txt

# ARM9 (ARMv5TE)
objdump -D -m armv5te --no-show-raw-insn \
  arm9.bin > arm9.disasm.txt

# Listar todas las instrucciones SVC (candidatos a tabla de syscalls)
grep -nE "\svc\b|\svcpl\b|\svcmi\b|\svcne\b" arm11.disasm.txt > arm11_svc.txt

# Dump de datos crudos en una dirección (útil para exheader/structs)
objdump -s --start-address=0x08001000 --stop-address=0x08001080 arm11.bin

# Buscar referencias a una dirección/etiqueta conocida
grep -n "0x08001234" arm11.disasm.txt
```

### 2.2 radare2 (r2) — análisis, funciones y exportación a CSV

Abrir y analizar:
```bash
r2 -a arm -b 32 -A arm11.bin
```

Dentro de r2:
```
aaa              # análisis completo
afl              # listar funciones detectadas (con direcciones)
afli @ fcn.08001000   # info de una función
pd 200 @ entry0  # desensamblar 200 instrucciones en el entry point
px 256 @ 0x08001000  # hexdump de 256 bytes en dirección
/ce svc          # buscar instrucciones SVC en el análisis
/ce 0xe12fff1e   # buscar bx lr (epílogo típico)
s 0x08000000     # desplazar cursor a base de carga
```

Exportar funciones detectadas a CSV (solo nombres que r2 asignó automáticamente; revisar a mano antes de dar por semánticos):
```r2
#!/usr/bin/env r2 -i
aagf
# JSON de funciones -> convertir a CSV externamente
aflj
```

Guion para escribir comentarios solo en direcciones verificadas:
```r2
# Ejemplo: solo si se verificó que 0x08001000 es el handler de SVC
CC kernel_svc_handler @ 0x08001000
```

### 2.3 Ghidra — importación, análisis y exportación de símbolos

**Importación (GUI):**
- Archivo → Nuevo proyecto → Importar archivo → `arm11.bin` / `arm9.bin`.
- **Language:** `ARM:LE:32:v6k` (ARM11 MPCore) / `ARM:LE:32:v5te` (ARM946E-S).
- **Compiler:** `gcc` (o `default`).
- **Image base:** `0x08000000` (ajustar según el header del FIRM/CXI descifrado).
- Ejecutar "Analyze" → "Analyze All".

**Headless (exportar símbolos a CSV):**
```bash
/opt/ghidra_12.1.4_PUBLIC/ghidraRun \
  -import arm11.bin \
  -postscript ExportSymbols.java arm11_symbols.csv
```

Esqueleto de `ExportSymbols.java` (exporta solo función + dirección; completar con nombres confirmados):
```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportSymbols extends GhidraScript {
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        println("VA\tOffset\tNombre\tTipo\tEstado");
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            // Long offset: convertir VA a offset de archivo requiere el memory map
            println(entry + "\t<file-offset>\t" + f.getName() + "\tFuncion\tPENDIENTE");
        }
    }
}
```

> **Regla de nombres:** en Ghidra, las funciones sin nombre aparecen como `FUN_0800XXXX`. Esos nombres son sintéticos y NO deben copiarse a la tabla de símbolos como si fueran semánticos. Solo se registra un nombre semántico si hay evidencia (cadenas, referencias cruzadas, uso de structs conocidos).

### 2.4 REA — capacidades y mapeo dirección↔offset

```bash
# Listar capacidades del proveedor (útil para decidir qué puede automatizar REA)
rea capabilities

# Análisis general de un artefacto descifrado
rea analyze --path arm11.bin

# Mapear una dirección de análisis a offset de archivo (cruzar r2 ↔ Ghidra ↔ objdump)
rea address-to-file-offset --path arm11.bin --address 0x08001234
```

> REA no es un desensamblador de firmware embebido por defecto; úsalo para auditoría de exposición y reconstrucción de obligaciones de evidencia. El desensamblado de instrucciones ARM y la recuperación de símbolos semánticos se hace con objdump/r2/Ghidra.

---

## 3. ctrtool / makerom — descifrado de CXI/CFA (cuando se disponga de claves)

> **Nota:** ctrtool y makerom están instalados en `/usr/local/bin/`. Requieren las claves de consola (`movable.sed` + `otp.bin` o `keyX/keyY`) para descifrar los CXI/CFA de los SysModules y FIRM.

```bash
# Extraer exefs/code.bin de un CXI descifrado (ejemplo; ajustar flags según versión)
ctrtool --exefsdir=exefs/ title.cxi

# Exheader (metadatos de control de acceso y capacidades del proceso)
ctrtool --exheader=exheader.bin title.cxi

# code.bin del exefs (código ARM del título/sysmodule)
ctrtool --exefsdir=exefs/ --cd=code.decompressed.bin title.cxi
```

> Solo tras el descifrado se podrán aplicar los scripts de §2 para recuperar símbolos reales.

---

## 4. Reglamento de nombres (evidencia)

| Situación | Qué poner en la tabla |
|-----------|----------------------|
| Función confirmada por cadena/referencia cruzada | Nombre semántico real, Estado `CONFIRMADO` |
| Función detectada por r2/Ghidra sin evidencia semántica | `FUN_0800XXXX` / `sub_0800XXXX`, Estado `NO CONFIRMADO` |
| Dirección sin certeza de qué hace | `0x0800XXXX`, Nombre vacío, Estado `PENDIENTE` |
| Hipótesis sin verificar en binario | Prefijar comentario con `[HIPÓTESIS]`, Estado `HIPÓTESIS`, no incluir en tabla final |

---

## 4. Símbolos REALES encontrados en SysModule descifrado (VERIFICADO)

> Fuente: `extraidos/SysModule_0004013000002102/raw/content.0000.00000005` descifrado con `ctrtool` + `aes_keys.txt`.
> Título: `0004013000002102` ("0430builder"), formato NCCH/CXI. Código ARM32/Thumb (interworking).
> Este es un **sysmodule de nivel usuario/kernel de aplicaciones ARM11**, NO el kernel `arm11.bin`/`arm9.bin` del FIRM (esos aún requieren `movable.sed` para descifrarse).

### 4.1 Funciones detectadas por radare2 (direcciones relativas al inicio de .code)

| Dirección (VA rel.) | Bloques | Tamaño (bytes) | Nombre r2 (sintético) | Estado | Nota |
|---------------------|---------|----------------|-----------------------|--------|------|
| `0x00000000` | 2 | 44 | `fcn.00000000` | CONFIRMADO | Punto de entrada / init (llama a fcn.00000024, 0000055c, 0000120c, 00000110, 00000528, 00000164) |
| `0x00000024` | 3 | 28 | `fcn.00000024` | CONFIRMADO | `ldr r0,[0x40]`; `ldr r1,[0x44]`; `mov r2,#0`; `bx lr` |
| `0x00000070` | 1 | 8 | `fcn.00000070` | CONFIRMADO | `add ip,pc,#1`; `bx ip` (Thumb interworking stub) |
| `0x00000110` | 4 | 26 | `fcn.00000110` | CONFIRMADO | `push {r4,r5,r6,lr}`; tabla de saltos (jump table) Thumb |
| `0x00000164` | 37 | 912 | `fcn.00000164` | CONFIRMADO | Función grande (912 B), candidato a servicio principal |
| `0x00000ec0` | 24 | 504 | `fcn.00000ec0` | CONFIRMADO | Función mediana (504 B) |
| `0x00001e68` | 35 | 756 | `fcn.00001e68` | CONFIRMADO | Función más grande (756 B), xref desde fcn.00000110 |
| `0x0000160c` | 17 | 328 | `fcn.0000160c` | CONFIRMADO | (328 B) |
| `0x0000120c` | 10 | 280 | `fcn.0000120c` | CONFIRMADO | (280 B) |
| `0x000009a8` | 11 | 184 | `fcn.000009a8` | CONFIRMADO | (184 B) |
| `0x000014b8` | 18 | 224 | `fcn.000014b8` | CONFIRMADO | (224 B) |
| … | … | … | … | … | (ver `binarios_descifrados/SysModule_0004013000002102/r2_functions_clean.txt` para las 60 funciones) |

> Los nombres `fcn.XXXXXX` son sintéticos (asignados por radare2). **No son nombres semánticos confirmados.** Para convertirlos en nombres semánticos se requiere evidencia adicional (cadenas de referencia, uso de structs conocidos, cross-references). Hasta entonces se mantienen como `NO CONFIRMADO` en el sentido semántico, aunque la **dirección y el código están verificados**.

### 4.2 Instrucciones SVC verificadas (syscalls ARM11)

| Dirección | Instrucción | Número SVC (inmediato) | Función contenedora | Estado |
|-----------|-------------|------------------------|---------------------|--------|
| `0x0000006c` | `svc 0x9ef000` | `0x9e` | (dentro del flujo de init) | CONFIRMADO |
| `0x000000bc` | `svc 0x76f000` | `0x76` | (flujo de servicio) | CONFIRMADO |

> **Corrección tras análisis ARM/Thumb:** Los opcodes `00f09eef` (`0x6c`) y `00f076ef` (`0xbc`) corresponden en realidad a instrucciones **Thumb-2 `blx`** (`0xF000 0xEF9E` / `0xF000 0xEF76`) decodificadas erróneamente como ARM32. Los **14 SVCs ARM reales** (`0xEF0000XX`, verificados contra su bitmap de Exheader) en `pdn` (`0004013000002102`) son: `0x03, 0x0A, 0x21, 0x22, 0x23, 0x24, 0x27, 0x2B, 0x2D, 0x32, 0x35, 0x3C, 0x4A, 0x4F` (ver §6 y `KERNEL_ANALISIS.md`).

### 4.3 Exheader (`exheader.bin`) — campos verificados

| Offset | Campo | Valor | Estado |
|--------|-------|-------|--------|
| `0x00` | Magic | `pdn\0` (`70646e00`) | CONFIRMADO |
| `0x0C` | Version/flags | `0x00010200` | CONFIRMADO |
| `0x14` | Contador | `0x00000003` | CONFIRMADO |
| `0x38` | Campo | `0x00000090` (144) | CONFIRMADO |
| `0x3C` | Campo | `0x0000067c` (1660) | CONFIRMADO |
| `0x1C0` | NCCH flags | `0x30010400` | CONFIRMADO |
| `0x20C` | Campo | `0x00000914` (2324) | CONFIRMADO |
| `0x360` | Campo | `0x00000003` | CONFIRMADO |
| `0x364`+`` | Bitmap de syscalls permitidos | `4e9ffaf0…` (bits = syscalls permitidos) | CONFIRMADO |

> ctrtool reportó los syscalls permitidos: `01,02,03,06,08,09,0A,0B,0C,0F,11,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,20,21,22,23,24,25,27,28,29,2A,2B,2C,2D,2E,2F,30,31,32,35,36,37,38,39,3A,3B,3C,3D,47,48,4A,4B,4C,4D,4E,4F,50,51,52,53,54,55,56,57`; `Arm9Capability: none`.

### 4.4 Modo de ejecución verificado

- El código mezcla instrucciones **ARM (32-bit)** y **Thumb (16-bit)** (interworking típico de GCC para 3DS). Ejemplo: `fcn.00000110` usa `push {r4,r5,r6,lr}` / `ldr r4,[pc]` (Thumb), mientras que el entry `0x0` usa `bl` (ARM).
- Endianness: little-endian.
- Punto de entrada: `0x00000000` (relativo a la base de carga del .code).

---

## 5. Archivos de símbolos generados (separados del binario crudo)

Todos los archivos de esta sección residen en:
`binarios_descifrados/SysModule_0004013000002102/` y están **separados del binario crudo** `code.bin`. Se generaron a partir del análisis verificado con radare2 sobre el `.code` descifrado.

### 5.1 `code.sym` — tabla de símbolos simple

Formato: `Address Size Type Name Verified Notes`

```
0x00000000  0x002C  FUNC    fcn.00000000                    YES         entry_point
0x00000024  0x001C  FUNC    fcn.00000024                    NO          
0x00000070  0x0008  FUNC    fcn.00000070                    NO          stub/thunk
...
0x0000006c  0x0004  INSN    svc_0x9e                        YES         svc_instruction
0x000000bc  0x0004  INSN    svc_0x76                        YES         svc_instruction
```

- **Verified=YES**: entrada/salida confirmada (punto de entrada o instrucción SVC).
- **Verified=NO**: dirección y tamaño verificados, pero el nombre `fcn.*` es sintético (radare2), no semánticamente confirmado.
- 91 entradas de funciones + 2 instrucciones SVC.

### 5.2 `code.map` — mapa estilo linker

Formato de archivo `.map` tradicional (sección + símbolos con direcciones/tamaños). Útil para importar en herramientas que esperen este formato.

### 5.3 `symbols.r2` — script de radare2

Crea flags (`f nombre @ dirección`) y comentarios (`CC`) para las 91 funciones y 2 SVCs verificadas.

```bash
# Cargar símbolos en radare2 sobre el binario crudo:
r2 -i symbols.r2 code.bin
# O dentro de r2:
#   . symbols.r2
#   afl               ; lista funciones con flags
#   pd @ fcn_00000164 ; desensamblar función grande verificada
```

### 5.4 `symbols_ghidra.py` — script para Ghidra

Crea funciones y símbolos en el programa abierto en Ghidra. Ajustar el image base al cargar `code.bin`.

```bash
/opt/ghidra_12.1.4_PUBLIC/ghidraRun \
  -import code.bin \
  -postscript symbols_ghidra.py
```

### 5.5 `symbols_gdb.txt` — comandos para GDB

Definiciones de símbolos para cargar manualmente en GDB (requiere un ELF o add-symbol-file sobre el binario crudo).

```bash
gdb -x symbols_gdb.txt
# luego: add-symbol-file code.bin 0x0
```

### 5.6 Nota sobre `.dwo` / `.dwp` (split DWARF)

No se generaron archivos `.dwo`/`.dwp` porque requieren un contenedor ELF con información de depuración DWARF real (secciones `.debug_info`, `.debug_abbrev`, etc.), que los binarios crudos de 3DS no tienen. Los archivos `.sym`, `.map` y los scripts de radare2/Ghidra/GDB son el equivalente práctico para este entorno sin debug info.

---

## 6. Análisis Completo de los 58 SysModules Descifrados + 5 Módulos FIRM `[VERIFICADO]`

### 6.1 Identificación del Cargador de Filesystem y Módulos Base en FIRM (\`arm11.bin\`)

Al inspeccionar \`binarios_descifrados/FIRM_0002/arm11.bin\` (Sección 0 de FIRM, carga \`0x1FF00000\`, \`218,624 B\`), se verificó que contiene **5 contenedores NCCH descifrados** (\`flags[7]=0x07\`):

| Módulo FIRM | TitleID | Offset en \`arm11.bin\` | Tamaño NCCH | Tamaño \`.code\` | Servicios en Exheader / Strings | SVCs ARM Reales Usados |
|-------------|---------|-------------------------|-------------|----------------|---------------------------------|------------------------|
| **\`fs\`** | \`0004013000001102\` | \`0x00000\` (\`0x1FF00000\`) | 157,184 B | 220,384 B | Registra \`fs:LDR\`, \`fs:REG\`, \`fs:USER\`; mapea \`0xFFE1EC01\`, \`0xFFE1EE01\`; strings \`/Quota.dat\`, \`/SEEDDB\`, \`/TITLETAG\` | \`0x01..0x03, 0x08..0x0C, 0x17, 0x18, 0x21..0x25, 0x27, 0x28, 0x2B, 0x2D, 0x32, 0x37, 0x3C, 0x49, 0x4A, 0x4F, 0x53..0x57\` |
| **\`loader\`** | \`0004013000001302\` | \`0x26600\` (\`0x1FF26600\`) | 13,312 B | 16,188 B | Consume **\`fs:LDR\`** (cargador de filesystem/programas), strings \`fs:REG\`, \`fs:USER\`, \`srv:\`, \`srv:pm\` | \`0x01..0x03, 0x0A, 0x21..0x24, 0x27, 0x28, 0x2B, 0x2D, 0x32, 0x3C, 0x4A, 0x4F, 0x73, 0x75\` |
| **\`pm\`** | \`0004013000001202\` | \`0x29A00\` (\`0x1FF29A00\`) | 19,968 B | 25,764 B | Consume \`fs:REG\`; strings \`pm:app\`, \`pm:dbg\`, \`http:C\`, \`soc:U\` | \`0x02, 0x03, 0x05, 0x07..0x0A, 0x12, 0x17..0x19, 0x21..0x25, 0x27, 0x28, 0x2A, 0x2B, 0x2D, 0x32, 0x33, 0x35, 0x39, 0x3C, 0x4A, 0x4F, 0x60, 0x76..0x79, 0x7C\` |
| **\`sm\`** | \`0004013000001002\` | \`0x2E800\` (\`0x1FF2E800\`) | 14,848 B | 17,448 B | Service Manager (\`srv:\`, \`srv:pm\`) | \`0x01..0x03, 0x15, 0x16, 0x21..0x24, 0x27, 0x2A, 0x2B, 0x35, 0x3C, 0x47, 0x48, 0x4A, 0x4F\` |
| **\`pxi\`** | \`0004013000001402\` | \`0x32200\` (\`0x1FF32200\`) | 13,312 B | 15,180 B | Mapea MMIO \`0x10163000\` (\`0xFFE1EC63\` → \`0x1EC63000\`); IRQs \`80, 81, 82, 83\`; strings \`pxi:am9\`, \`pxi:dev\`, \`pxi:mc\`, \`pxi:ps9\` | \`0x02, 0x03, 0x08..0x0A, 0x13..0x18, 0x21..0x25, 0x27, 0x2B, 0x2D, 0x32, 0x3C, 0x4A, 0x4F, 0x50, 0x51\` |

- **Cargador de filesystem identificado:** **\`fs\` (\`0004013000001102\`)** implementa el servidor de archivos (\`fs:LDR\`, \`fs:REG\`, \`fs:USER\`) en la primera partición NCCH de \`arm11.bin\`, mientras que **\`loader\` (\`0004013000001302\`, en \`0x1FF26600\`, zona donde se observó la string \`"fs:LDR"\` @ \`0x1FF26A50\`)** consume \`fs:LDR\` y crea procesos vía \`SVC 0x73\` (\`CreateCodeSet\`) y \`SVC 0x75\` (\`CreateProcess\`).
- **SysModules con \`fs:USER\` en Exheader (25 módulos):** `am` (`0004013000001502`), `cfg` (`0004013000001702`), `cfg` (`0004013000001703`), `ptm` (`0004013000002202`), `ptm` (`0004013000002203`), `ac` (`0004013000002402`), `ac` (`0004013000002403`), `cecd` (`0004013000002602`), `dlp` (`0004013000002802`), `nim` (`0004013000002C02`), `nim` (`0004013000002C03`), `nwm` (`0004013000002D03`), `ssl` (`0004013000002F02`), `ssl` (`0004013000002F03`), `ps` (`0004013000003102`), `ps` (`0004013000003103`), `friends` (`0004013000003202`), `friends` (`0004013000003203`), `boss` (`0004013000003402`), `news` (`0004013000003502`), `ro` (`0004013000003702`), `act` (`0004013000003802`), `nfc` (`0004013000004002`), `ns` (`0004013000008002`), `ns` (`0004013000008003`).

### 6.2 Tabla Completa de los 58 SysModules Descifrados

> Las listas completas de funciones por módulo residen en \`binarios_descifrados/analisis/SysModule_<TitleID>_funcs.txt\` (58 archivos). Los SVCs listados son exclusivamente instrucciones ARM \`0xEF0000XX\` verificadas contra el bitmap de syscalls permitido en \`exheader.bin\`.

| TitleID | Nombre (Exheader) | \`text_addr\` | Tamaño \`.code\` | Funciones (r2) | SVCs Usados (verificados) | Servicios Permitidos (Exheader) | Top 3 Funciones por Tamaño |
|---------|-------------------|---------------|------------------|----------------|---------------------------|---------------------------------|----------------------------|
| `0004013000001502` | `am` | `0x00100000` | 81,920 B | 830 | 24 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x47`, `0x48`, `0x4A`, `0x4F`) | `pxi:am9`, `fs:USER` | `fcn.00005540` (1794B), `fcn.0000a078` (1286B), `fcn.0000aa54` (1032B) |
| `0004013000001503` | `am` | `0x00100000` | 45,056 B | 489 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x47`, `0x48`, `0x4A`, `0x4F`) | `pxi:am9` | `fcn.00001d8c` (2816B), `fcn.00006de0` (800B), `fcn.00008528` (688B) |
| `0004013000001602` | `camera` | `0x00100000` | 98,304 B | 805 | 33 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x55`, `0x56`, `0x57`) | `i2c::CAM`, `pdn:c`, `cfg:s`, `mcu::CAM`, `csnd:SND`, `ptm:s` | `fcn.00002b3c` (890B), `fcn.0000bedc` (694B), `fcn.00000dc8` (688B) |
| `0004013000001702` | `cfg` | `0x00100000` | 57,344 B | 632 | 16 (`0x02`, `0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `SPI::NOR`, `ps:ps`, `i2c::EEP` | `fcn.000008c4` (1442B), `fcn.00001b0c` (978B), `fcn.0000a024` (904B) |
| `0004013000001703` | `cfg` | `0x00100000` | 45,056 B | 353 | 13 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `SPI::NOR`, `ps:ps`, `i2c::EEP` | `fcn.000060c0` (846B), `fcn.0000643c` (582B), `fcn.0000388c` (478B) |
| `0004013000001802` | `codec` | `0x00100000` | 40,960 B | 190 | 23 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pdn:i`, `SPI::CD2`, `gpio:CDC`, `mcu::CDC`, `cfg:s`, `ptm:s` | `fcn.0000146c` (2612B), `fcn.00000194` (1332B), `fcn.00005bf0` (1328B) |
| `0004013000001803` | `codec` | `0x00100000` | 40,960 B | 182 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pdn:i`, `SPI::CD1`, `SPI::CD2`, `SPI::PMC`, `gpio:CDC`, `mcu::CDC`, `cfg:s`, `ptm:s` | `fcn.00005ec4` (2488B), `fcn.00001c88` (1284B), `fcn.000032dc` (1260B) |
| `0004013000001A02` | `dsp` | `0x00100000` | 40,960 B | 124 | 26 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x54`) | `pdn:d`, `cdc:DSP`, `ptm:s`, `cfg:s`, `ps:ps` | `fcn.0000735c` (1384B), `fcn.000001a8` (1140B), `fcn.0000321c` (524B) |
| `0004013000001A03` | `dsp` | `0x00100000` | 40,960 B | 221 | 22 (`0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x54`) | `pdn:d`, `cdc:DSP`, `ptm:s`, `cfg:s`, `ps:ps` | `fcn.000012fc` (1500B), `fcn.000054f4` (1468B), `fcn.00006b48` (664B) |
| `0004013000001B02` | `gpio` | `0x00100000` | 20,480 B | 88 | 16 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | *(ninguno)* | `fcn.0000016c` (936B), `fcn.000028d8` (840B), `fcn.000014f8` (504B) |
| `0004013000001B03` | `gpio` | `0x00100000` | 20,480 B | 83 | 14 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | *(ninguno)* | `fcn.00001b34` (916B), `fcn.00000da4` (812B), `fcn.000019c0` (436B) |
| `0004013000001C02` | `gsp` | `0x00100000` | 61,440 B | 373 | 36 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x54`, `0x55`, `0x56`, `0x59`) | `pdn:g`, `i2c::LCD`, `mcu::GPU`, `cfg:s`, `ptm:s` | `fcn.00000550` (1228B), `fcn.00006f7c` (988B), `fcn.000024a0` (852B) |
| `0004013000001C03` | `gsp` | `0x00100000` | 61,440 B | 337 | 30 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x54`, `0x55`, `0x56`) | `pdn:g`, `gpio:GXS`, `i2c::LCD`, `mcu::GPU`, `cfg:s`, `ptm:s` | `fcn.00000e68` (1428B), `fcn.000075ac` (1096B), `fcn.000033a4` (872B) |
| `0004013000001D02` | `hid` | `0x00100000` | 53,248 B | 256 | 29 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:HID`, `cdc:HID`, `mcu::HID`, `i2c::HID`, `cfg:s`, `ptm:s` | `fcn.00002834` (1152B), `fcn.00000180` (1100B), `fcn.000037d0` (872B) |
| `0004013000001D03` | `hid` | `0x00100000` | 45,056 B | 245 | 27 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:HID`, `cdc:HID`, `mcu::HID`, `i2c::HID`, `cfg:s`, `ptm:s` | `fcn.000062d0` (1132B), `fcn.00002168` (776B), `fcn.00003308` (696B) |
| `0004013000001E02` | `i2c` | `0x00100000` | 28,672 B | 103 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x19`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`) | *(ninguno)* | `fcn.000037f4` (1644B), `fcn.0000013c` (900B), `fcn.00003034` (588B) |
| `0004013000001E03` | `i2c` | `0x00100000` | 28,672 B | 125 | 20 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x19`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`) | *(ninguno)* | `fcn.00001868` (1084B), `fcn.00003894` (1024B), `fcn.00002db0` (792B) |
| `0004013000001F02` | `mcu` | `0x00100000` | 61,440 B | 191 | 21 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:MCU`, `i2c::MCU`, `ptm:s` | `fcn.000000e8` (1464B), `fcn.0000086c` (852B), `fcn.00003eb0` (708B) |
| `0004013000001F03` | `mcu` | `0x00100000` | 61,440 B | 241 | 19 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:MCU`, `i2c::MCU`, `ptm:s` | `fcn.00006908` (1592B), `fcn.00007108` (948B), `fcn.0000493c` (940B) |
| `0004013000002002` | `mic` | `0x00100000` | 28,672 B | 153 | 27 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | `cdc:MIC`, `ptm:s` | `fcn.0000034c` (1428B), `fcn.00004240` (892B), `fcn.0000267c` (508B) |
| `0004013000002102` | `pdn` | `0x00100000` | 20,480 B | 91 | 14 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(ninguno)* | `fcn.00000164` (912B), `fcn.00001e68` (756B), `fcn.00000ec0` (504B) |
| `0004013000002103` | `pdn` | `0x00100000` | 16,384 B | 77 | 12 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(ninguno)* | `fcn.00000b14` (904B), `fcn.00000660` (752B), `fcn.00001250` (436B) |
| `0004013000002202` | `ptm` | `0x00100000` | 61,440 B | 705 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x7C`) | `mcu::RTC`, `fs:USER`, `cfg:s`, `pxi:mc`, `pm:app`, `pdn:s` | `fcn.00003f6c` (1016B), `fcn.00005af0` (926B), `fcn.0000b0fc` (880B) |
| `0004013000002203` | `ptm` | `0x00100000` | 53,248 B | 591 | 24 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x7C`) | `mcu::RTC`, `fs:USER`, `cfg:s`, `pxi:mc`, `pm:app`, `pdn:s` | `fcn.00008610` (942B), `fcn.00003100` (904B), `fcn.00006c4c` (848B) |
| `0004013000002302` | `spi` | `0x00100000` | 24,576 B | 120 | 19 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(ninguno)* | `fcn.00000160` (832B), `fcn.00003384` (456B), `fcn.000028a8` (356B) |
| `0004013000002303` | `spi` | `0x00100000` | 24,576 B | 106 | 17 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | *(ninguno)* | `fcn.00000c8c` (832B), `fcn.00000830` (704B), `fcn.00000654` (452B) |
| `0004013000002402` | `ac` | `0x00100000` | 155,648 B | 1249 | 24 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `ptm:s`, `ps:ps`, `nwm::INF`, `soc:P`, `soc:U`, `cfg:s`, `cfg:nor`, `http:C`, `fs:USER` | `fcn.00003330` (2478B), `fcn.00001878` (1776B), `fcn.00007190` (1456B) |
| `0004013000002403` | `ac` | `0x00100000` | 139,264 B | 1208 | 27 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `ptm:s`, `ps:ps`, `nwm::INF`, `soc:P`, `soc:U`, `cfg:s`, `cfg:nor`, `http:C`, `fs:USER` | `fcn.000089c8` (1744B), `fcn.0000df68` (1354B), `fcn.00017856` (1244B) |
| `0004013000002602` | `cecd` | `0x00100000` | 155,648 B | 1507 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `nwm::CEC`, `fs:USER`, `ptm:s`, `ps:ps`, `cfg:s`, `frd:u` | `fcn.0000aed0` (1280B), `fcn.0000bf94` (1248B), `fcn.00009c3c` (956B) |
| `0004013000002702` | `csnd` | `0x00100000` | 36,864 B | 407 | 31 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x52`, `0x53`, `0x54`) | `cdc:CSN`, `ptm:s` | `fcn.000052fc` (2236B), `fcn.0000105c` (842B), `fcn.000026f4` (556B) |
| `0004013000002703` | `csnd` | `0x00100000` | 32,768 B | 324 | 29 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x52`, `0x53`, `0x54`) | `cdc:CSN`, `ptm:s` | `fcn.00005098` (2124B), `fcn.000023f4` (862B), `fcn.000012e8` (646B) |
| `0004013000002802` | `dlp` | `0x00100000` | 86,016 B | 951 | 30 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x14`, `0x17`, `0x18`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x29`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `am:u`, `cfg:u`, `nwm::UDS`, `ptm:s`, `ps:ps` | `fcn.00010494` (1280B), `fcn.00004f5c` (754B), `fcn.000114b8` (688B) |
| `0004013000002902` | `http` | `0x00100000` | 118,784 B | 658 | 29 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x15`, `0x16`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ptm:s`, `soc:U`, `ssl:C` | `fcn.00009484` (1176B), `fcn.00010eec` (1176B), `fcn.00011544` (1176B) |
| `0004013000002903` | `http` | `0x00100000` | 110,592 B | 597 | 23 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `soc:U`, `ssl:C` | `fcn.0000f29c` (1680B), `fcn.00014e14` (1652B), `fcn.00013360` (1244B) |
| `0004013000002A02` | `mp` | `0x00100000` | 139,264 B | 680 | 34 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | `nwm::EXT`, `cfg:nor`, `ptm:s` | `fcn.000103ac` (4916B), `fcn.00017488` (3708B), `fcn.000149fc` (1540B) |
| `0004013000002A03` | `mp` | `0x00100000` | 139,264 B | 676 | 32 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`) | `nwm::EXT`, `cfg:nor`, `ptm:s` | `fcn.0000bd5c` (4604B), `fcn.00014550` (3724B), `fcn.00009d14` (1528B) |
| `0004013000002B02` | `ndm` | `0x00100000` | 49,152 B | 703 | 26 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x15`, `0x16`, `0x17`, `0x18`, `0x19`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `ptm:s`, `nwm::EXT`, `nim:ndm`, `ndm:u`, `cecd:ndm`, `frd:n`, `boss:M` | `fcn.000097cc` (688B), `fcn.00001598` (514B), `fcn.00000ca8` (364B) |
| `0004013000002C02` | `nim` | `0x00100000` | 356,352 B | 3143 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `am:net`, `ac:u`, `http:C`, `cfg:s`, `ptm:s`, `ptm:gets` | `fcn.000374dc` (1694B), `fcn.00007038` (1372B), `fcn.0002a5e4` (1356B) |
| `0004013000002C03` | `nim` | `0x00100000` | 225,280 B | 833 | 22 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `fs:USER`, `am:net`, `ac:u`, `http:C`, `ssl:C`, `cfg:s`, `ptm:s` | `fcn.0002d5bc` (3780B), `fcn.00029984` (3544B), `fcn.0002050c` (3224B) |
| `0004013000002D02` | `nwm` | `0x00100000` | 348,160 B | 2421 | 39 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x55`, `0x56`, `0x57`, `0x58`, `0x5A`) | `cfg:u`, `mcu::NWM`, `ps:ps`, `ptm:s` | `fcn.000024a0` (5830B), `fcn.000539f4` (2196B), `fcn.0001aefc` (1556B) |
| `0004013000002D03` | `nwm` | `0x00100000` | 327,680 B | 1875 | 34 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x50`, `0x51`, `0x52`, `0x53`, `0x55`, `0x56`, `0x57`) | `mcu::NWM`, `ptm:s`, `ps:ps`, `fs:USER` | `fcn.00026950` (4112B), `fcn.00034c3c` (1244B), `fcn.00015c8c` (956B) |
| `0004013000002E02` | `socket` | `0x00100000` | 212,992 B | 644 | 29 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0B`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `nwm::SOC`, `ptm:s` | `fcn.00030518` (2924B), `fcn.0002a800` (2484B), `fcn.0002a050` (2200B) |
| `0004013000002E03` | `socket` | `0x00100000` | 217,088 B | 782 | 25 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0B`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `nwm::SOC`, `ptm:s` | `fcn.0002aa58` (3200B), `fcn.0000eb50` (3108B), `fcn.0002e3e0` (2784B) |
| `0004013000002F02` | `ssl` | `0x00100000` | 356,352 B | 1911 | 25 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x15`, `0x16`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `soc:U`, `ps:ps`, `fs:USER` | `fcn.00022ad4` (6412B), `fcn.0004ce50` (5952B), `fcn.000243e0` (4908B) |
| `0004013000002F03` | `ssl` | `0x00100000` | 356,352 B | 1121 | 22 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `soc:U`, `soc:P`, `ps:ps`, `fs:USER` | `fcn.000255e4` (2396B), `fcn.0005176c` (2064B), `fcn.00053eac` (1848B) |
| `0004013000003102` | `ps` | `0x00100000` | 28,672 B | 159 | 15 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pxi:ps9`, `mcu::PLS`, `fs:USER` | `fcn.00000164` (920B), `fcn.00003bc0` (756B), `fcn.00001d84` (416B) |
| `0004013000003103` | `ps` | `0x00100000` | 24,576 B | 137 | 13 (`0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `pxi:ps9`, `mcu::PLS`, `fs:USER` | `fcn.00002aa4` (940B), `fcn.00001730` (752B), `fcn.00002444` (436B) |
| `0004013000003202` | `friends` | `0x00100000` | 413,696 B | 3690 | 27 (`0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `soc:U`, `http:C`, `fs:USER`, `cfg:s`, `ptm:s`, `ps:ps`, `ptm:sets`, `APT:U`, `nwm::EXT` | `fcn.00048a88` (1528B), `fcn.00029028` (1490B), `fcn.00007122` (1308B) |
| `0004013000003203` | `friends` | `0x00100000` | 376,832 B | 3718 | 26 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `ac:u`, `soc:U`, `http:C`, `fs:USER`, `cfg:s`, `ptm:s`, `ps:ps`, `ptm:sets`, `APT:U`, `nwm::EXT` | `fcn.00050ef6` (1982B), `fcn.00051b5c` (1338B), `fcn.0004908a` (1268B) |
| `0004013000003302` | `ir` | `0x00100000` | 81,920 B | 388 | 27 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `cfg:s`, `gpio:IR`, `i2c::IR`, `ptm:s` | `fcn.000003ec` (1536B), `fcn.000029f0` (924B), `fcn.0000f7ec` (852B) |
| `0004013000003303` | `ir` | `0x00100000` | 32,768 B | 172 | 22 (`0x01`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `gpio:IR`, `i2c::IR`, `ptm:s` | `fcn.00000a7c` (1116B), `fcn.00004008` (1092B), `fcn.00003994` (752B) |
| `0004013000003402` | `boss` | `0x00100000` | 311,296 B | 2949 | 31 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x0C`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1D`, `0x1E`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x37`, `0x3C`, `0x4A`, `0x4F`) | `http:C`, `ac:u`, `ptm:s`, `ptm:play`, `cfg:s`, `fs:USER`, `ps:ps`, `frd:u`, `cecd:s` | `fcn.000330b2` (3080B), `fcn.00031c30` (1820B), `fcn.0003fb26` (1308B) |
| `0004013000003502` | `news` | `0x00100000` | 49,152 B | 603 | 19 (`0x01`, `0x02`, `0x03`, `0x0A`, `0x17`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `boss:P`, `cecd:s`, `frd:u`, `fs:USER`, `ndm:u`, `nim:u`, `ptm:sysm` | `fcn.0000909c` (688B), `fcn.00008384` (476B), `fcn.00005cd8` (388B) |
| `0004013000003702` | `ro` | `0x14000000` | 45,056 B | 143 | 19 (`0x02`, `0x03`, `0x0A`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x70`, `0x71`, `0x72`, `0x7D`) | `ps:ps`, `fs:USER` | `fcn.000041c0` (2088B), `fcn.00006e80` (1560B), `fcn.00000174` (1124B) |
| `0004013000003802` | `act` | `0x00100000` | 167,936 B | 1430 | 22 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x18`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `am:net`, `cfg:s`, `fs:USER`, `http:C`, `ptm:s`, `frd:u` | `fcn.00011874` (1940B), `fcn.0001c77c` (1346B), `fcn.00005e1e` (1308B) |
| `0004013000004002` | `nfc` | `0x00100000` | 110,592 B | 776 | 26 (`0x01`, `0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x17`, `0x18`, `0x19`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`) | `cfg:u`, `fs:USER`, `ir:USER`, `nwm::EXT`, `ps:ps`, `ptm:s` | `fcn.00015ab8` (904B), `fcn.00010fc0` (842B), `fcn.00000160` (688B) |
| `0004013000008002` | `ns` | `0x00100000` | 151,552 B | 854 | 35 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x14`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1C`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x24`, `0x25`, `0x27`, `0x28`, `0x2B`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x54`, `0x55`, `0x56`, `0x7C`) | `APT:U`, `am:u`, `cam:s`, `cfg:s`, `fs:USER`, `nwm::EXT`, `pm:app`, `ps:ps`, `ptm:sysm`, `qtm:sp` | `fcn.0001e8d4` (2924B), `fcn.00000318` (1728B), `fcn.0000b730` (1356B) |
| `0004013000008003` | `ns` | `0x00100000` | 110,592 B | 579 | 31 (`0x02`, `0x03`, `0x08`, `0x09`, `0x0A`, `0x13`, `0x17`, `0x18`, `0x19`, `0x1A`, `0x1B`, `0x1D`, `0x1E`, `0x1F`, `0x20`, `0x21`, `0x22`, `0x23`, `0x25`, `0x27`, `0x28`, `0x2D`, `0x32`, `0x35`, `0x3C`, `0x4A`, `0x4F`, `0x54`, `0x55`, `0x56`, `0x7C`) | `pm:app`, `APT:U`, `cfg:s`, `ps:ps`, `fs:USER`, `nwm::EXT`, `am:u`, `ptm:sysm` | `fcn.000069c8` (3108B), `fcn.000076e8` (1608B), `fcn.00015d88` (1320B) |
