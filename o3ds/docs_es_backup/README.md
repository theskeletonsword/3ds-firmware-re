# 3DS FIRM/ARM Reversing — Análisis de kernel ARM11 y ARM9

Repositorio de análisis y reversing de los binarios de firmware de Nintendo 3DS (FIRM, `arm11.bin`, `arm9.bin`, sysmodules, `code.decompressed.bin`, `exheader.bin`).

> ⚠️ **ADVERTENCIA CRÍTICA:** Antes de probar drivers críticos, modificar `FIRM` o escribir en el almacenamiento de una consola 3DS, **siempre realice un respaldo completo de la NAND y de los archivos críticos de recuperación** (`movable.sed`, `otp.bin`, `seeds`, y copias de `FIRM`/`arm9.bin`/`arm11.bin`). Sin respaldo y sin un método de recuperación (hardmod/NAND programmer), un error puede provocar un **hard brick** irreversible. Ver `MANUAL_DRIVERS_3DS.md` y `GUIA_DRIVERS_CRITICOS.md`.

---

## Estado Actual (VERIFICADO EN ESTE REPO)

Gracias al archivo `movable.sed` encontrado en el repositorio + `aes_keys.txt` + `ctrtool`, logré **descifrar los kernels reales** de los títulos FIRM:

| Binario | Ruta | Arquitectura | Carga / Runtime | Entry Point | Tamaño | Contenido |
|---------|------|--------------|-----------------|-------------|--------|-----------|
| **arm11_section1.bin** (Kernel11 real) | `binarios_descifrados/FIRM_0002/arm11_section1.bin` | ARMv6K MPCore | `0x1FF80000` / `0xFFF00000` | `0x1FFAE034` | 204,800 B | Kernel11 (SVCs, vectores `0xFFFF0000`, PMU CP15 `c15,c12`) |
| **arm11.bin** (FIRM Sec 0) | `binarios_descifrados/FIRM_0002/arm11.bin` | ARMv6K MPCore | `0x1FF00000` | — | 218,624 B | 5 NCCHs integrados (`fs`, `loader`, `pm`, `sm`, `pxi`) |
| **arm9.bin** (Kernel9 + Process9) | `binarios_descifrados/FIRM_0002/arm9.bin` | ARMv5TE ARM946E-S | `0x08006800` (Process9 `0x08028000`) | `0x0801B01C` | 541,184 B | Kernel9 (vectores `0x0800E7E0`, SWIs `0x08007938`) + Process9 |

También se descifraron y documentaron **58 SysModules** (`SIMBOLOS_RECREADOS.md`) + los 5 módulos integrados en FIRM.

### Hallazgos Verificados en Binario

| Hallazgo | ARM9 (`arm9.bin`) | ARM11 Kernel11 (`arm11_section1.bin`) |
|----------|-------------------|---------------------------------------|
| Funciones detectadas | 4,455 `r2` / 2,673 C Ghidra (**4,849** símbolos tras filtrar 32 falsos positivos) | 415 `r2` / 654 C Ghidra (**838** símbolos con tabla SVC, RTTI `K*` y C) |
| Tabla de syscalls | 40 SWIs activos (`0x08007938`, dispatcher `0x08007878`) | 109 SVCs activos (`0xFFF02328`, dispatcher `0xFFF0220C`) |
| Vectores de excepción | `0x0800E7E0` (copiados a `0x08000000`) | `0x1FFAD000` (mapeados a `0xFFFF0000`) |
| Entry point (FIRM header) | `0x0801B01C` | `0x1FFAE034` |
| PMU / CP15 | MPU `c5/c6` (`0x0800A118..0x0800A134`) | PMU **`c15, c12, 0..3`** (`0xFFF11074..0xFFF11768`) + `SVC 0x3E` |
| PXI MMIO | `0x10008000` | `0x1EC63000` (`0x10163000`, IRQs `80..83`, en `FIRM:pxi`) |

### Nombres Amigables Basados en Evidencia (Strings, RTTI `K*`, MMIO y Callgraph)

| Kernel | Entradas `CONFIRMED`/`EVIDENCE_BASED` | Ejemplos Verificados |
|--------|----------------------------------------|----------------------|
| ARM9 | **4,849** (**311** `CONFIRMED`, **4,538** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `arm9_firm_entry_point`, `k9_swi_0x7B_Backdoor`, `k9_critical_section_enter`, `p9_memcpy`, `p9_sdmmc_get_reg_ptr`, `p9_movable_sed_path_handler`, `p9_ertfs_init_error` |
| ARM11 Kernel11 | **838** (**287** `CONFIRMED`, **551** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `arm11_firm_entry_point`, `kernel11_launch_firm_sysmodules`, `svc_0x3E_ControlPerformanceCounter`, `k11_critical_section_enter`, `KMutex_acquire_and_inherit_priority`, `k11_gic_irq_dispatch`, `k11_mmu_map_virtual_range` |

> Se limpiaron los falsos positivos previos y se enriquecieron ambas tablas con pseudocódigos C generados por REA + Ghidra `12.2` (`binarios_descifrados/FIRM_0002/pseudocodigo_k11/` y `pseudocodigo_arm9/`).

---

## Estructura del Repositorio

```
00_ESTADO_Y_METODOLOGIA.md     # Qué se encontró, qué está cifrado, herramientas y comandos
ARQ_ARM11_vs_ARM9.md           # (a) Arquitectura ARM11 vs ARM9 y flujo del kernel
KERNEL_ANALISIS.md             # Análisis completo de kernels ARM11 y ARM9 (EL1)
SIMBOLOS_RECREADOS.md          # (b) Tabla y scripts de símbolos (SysModules)
SIMBOLOS_KERNEL.md             # (b-ext) Tabla y archivos de símbolos (kernels ARM11/ARM9)
GUIA_DRIVERS_CRITICOS.md       # (c) Guía de diseño y hardening para drivers críticos
MANUAL_DRIVERS_3DS.md          # (c-ext) Manual completo de programación de drivers 3DS
README.md                      # Este archivo
extraidos/                     # Binarios extraídos (títulos FIRM, SysModules, etc.) — todos cifrados
binarios_descifrados/          # Binarios descifrados con ctrtool + aes_keys.txt + movable.sed
   FIRM_0002/
      arm11_section1.bin        # Kernel11 ARM11 real descifrado (verificado)
      arm11.bin                 # Sección 0 FIRM (5 NCCHs: fs, loader, pm, sm, pxi)
      arm9.bin                  # Kernel9 + Process9 descifrado (verificado)
      arm11_kernel11_friendly.sym / arm9_friendly.sym  # Tablas con nombres verificados y evidence-based
      arm9.map                  # Mapa estilo linker ARM9
      symbols_arm11_kernel11_friendly.r2 / symbols_arm9_friendly.r2  # Scripts radare2
      symbols_arm11_kernel11_friendly_ghidra.py / symbols_arm9_friendly_ghidra.py  # Scripts Ghidra
      symbols_arm9_gdb.txt      # Comandos GDB ARM9
      arm9_all_funcs.txt        # Lista de funciones ARM9 detectadas por r2
   SysModule_XXXXXXXXXXXXXX/    # 58 SysModules descifrados con code.bin, exheader.bin
updates/                        # .cia de actualización
aes_keys.txt                    # Claves AES de consola (encontrado en el repositorio)
movable.sed                     # Clave movable de consola (encontrado en el repositorio)
```

---

## Entregables

| # | Entregable | Archivo | Contenido |
|---|------------|---------|-----------|
| (a) | Arquitectura ARM11 vs ARM9 y flujo del kernel | `ARQ_ARM11_vs_ARM9.md` | Procesadores, PXI, memoria, excepciones, SVC, PMU/CP15, arranque |
| (a-ext) | Análisis completo de kernels (EL1) | `KERNEL_ANALISIS.md` | arm9.bin y arm11.bin descifrados, funciones, SVCs/SWIs, entry points |
| (b) | Tabla y script de símbolos (SysModules) | `SIMBOLOS_RECREADOS.md` | Formato de tabla, scripts objdump/r2/Ghidra/REA, reglas de evidencia |
| (b-ext) | Archivos de símbolos separados (kernels) | `SIMBOLOS_KERNEL.md` | .sym, .map, .r2, .py, .txt para arm9.bin y arm11.bin |
| (c) | Guía de diseño y hardening para drivers críticos | `GUIA_DRIVERS_CRITICOS.md` | PMU CP15, FS exóticos, governors, PXI, almacenamiento |
| (c-ext) | Manual de programación de drivers 3DS | `MANUAL_DRIVERS_3DS.md` | Manual completo con advertencia NAND, ejemplos de código, checklist |
| (d) | Borrador de README para el repositorio | `README.md` | Este archivo |

---

## Comandos Rápidos de Reproducción

### Descifrar FIRM y extraer kernels (requiere `movable.sed`)

```bash
# Descifrar título FIRM como NCCH
ctrtool -v --intype=ncch --exheader=exh.bin --exefs=exefs.bin title_firm.cxi

# Extraer sección .firm
ctrtool -v --exefsdir=exefs_dir title_firm.cxi

# Separar FIRM en arm9.bin y arm11.bin
ctrtool -v --intype=firm --firmdir=firm_out --firmtype=nand exefs_dir/firm.bin
```

### Analizar kernel con radare2

```bash
# ARM11 Kernel11 real (arm11_section1.bin, base runtime 0xFFF00000)
r2 -a arm -b 32 -m 0xFFF00000 -A binarios_descifrados/FIRM_0002/arm11_section1.bin
# Dentro de r2:
#   afl                        ; listar 415 funciones
#   pd 100 @ 0xFFF0220C        ; desensamblar SVC dispatcher
#   pd 100 @ 0x1FFAE034        ; entry point (con -m 0x1FF80000)

# ARM9 (base 0x08006800)
r2 -a arm -b 32 -B 0x08006800 -A binarios_descifrados/FIRM_0002/arm9.bin
# Dentro de r2:
#   afl                        ; listar funciones
#   pd 100 @ 0x0801B01C        ; desensamblar entry point
#   pd 100 @ 0x08007878        ; desensamblar SWI dispatcher
```

### Cargar símbolos amigables en radare2

```bash
# ARM9 con nombres verificados
r2 -a arm -b 32 -B 0x08006800 -i binarios_descifrados/FIRM_0002/symbols_arm9_friendly.r2 binarios_descifrados/FIRM_0002/arm9.bin

# ARM11 Kernel11 con nombres verificados
r2 -a arm -b 32 -m 0xFFF00000 -i binarios_descifrados/FIRM_0002/symbols_arm11_kernel11_friendly.r2 binarios_descifrados/FIRM_0002/arm11_section1.bin
```

### Cargar símbolos en Ghidra

1. Nuevo proyecto → Importar `arm11_section1.bin` o `arm9.bin`
2. **Language:** `ARM:LE:32:v6k` (ARM11) / `ARM:LE:32:v5te` (ARM9)
3. **Image base:** `0xFFF00000` (Kernel11 runtime) / `0x08006800` (ARM9)
4. Ejecutar script: `symbols_arm11_kernel11_friendly_ghidra.py` / `symbols_arm9_friendly_ghidra.py`

---

## Reglas de Evidencia

1. **Hechos verificados en el binario/desensamblado:** solo lo que se puede demostrar directamente en los archivos descifrados (direcciones, instrucciones, referencias cruzadas).
2. **Conocimiento público 3DS:** documentado en 3dbrew/GBATEK, correlacionado explícitamente cuando aplica sin sustituir la verificación binaria.
3. **Hipótesis / por comprobar:** inferencias que requieren validación en hardware real o análisis adicional. Nunca darse por hechas.
4. **No inventar nombres:** los símbolos solo se registran con nombres semánticos confirmados o `EVIDENCE_BASED` (strings/XREFs reales); de lo contrario usan nombres sintéticos y se marcan como `HYPOTHESIS`.

---

## Estado de Análisis Completado

1. Kernels `arm11_section1.bin`, `arm9.bin` y `arm11.bin` descifrados y mapeados en `binarios_descifrados/FIRM_0002/` y `KERNEL_ANALISIS.md`.
2. Dispatcher SVC (`0xFFF0220C`), tabla de 109 SVCs (`0xFFF02328`), dispatcher SWI ARM9 (`0x08007878`), tabla de 40 SWIs (`0x08007938`) y vectores de excepción (`0xFFFF0000` / `0x0800E7E0`) documentados.
3. Los 58 SysModules + 5 módulos FIRM (`sm`, `pm`, `loader`, `fs`, `pxi`) documentados con funciones y SVCs en `SIMBOLOS_RECREADOS.md`.
4. Accesos PMU CP15 (`c15, c12, 0..3` + `SVC 0x3E`) y MMIO PXI (`0x1EC63000`/`0x10163000`, `0x10008000`, IRQs `80..83`) verificados.
