# Manual de Programación de Drivers Críticos — Nintendo 3DS (ARM11/ARM9 EL1)

> **ADVERTENCIA OBLIGATORIA — LÉASE ANTES DE NINGUNA PRUEBA EN HARDWARE REAL**
>
> **SIEMPRE realice un respaldo completo de la NAND (y de todos los archivos críticos de recuperación: `movable.sed`, `otp.bin`, `seeds`, y copias de `FIRM`/`arm9.bin`/`arm11.bin`) ANTES de probar drivers críticos, modificar `FIRM` o escribir en el almacenamiento de la consola.**
>
> **¿Qué provoca un hard brick o fallo de arranque?**
> - Escribir un `FIRM` corrupto, mal firmado o con claves incorrectas en la partición FIRM impide que el bootROM de ARM9 valide el firmware: la consola no arranca ni siquiera hasta el menú (hard brick de nivel de firmware).
> - Corromper `arm9.bin` (firm9) rompe el núcleo de seguridad: sin él no hay descifrado de títulos, no hay acceso a claves de consola y el sistema no puede completar el arranque seguro.
> - Corromper `arm11.bin` impide que el kernel de aplicaciones inicialice: pantalla negra tras el logo o bucle de reinicio.
> - Escribir en bloques críticos de NAND (FIRM, FIRM backup, SecureZone, SD/MMC FAT de boot) sin respaldo hace imposible la recuperación por medios de software si no se tiene hardmod / NAND programmer.
> - Un driver de kernel con fallo (puntero nulo, acceso a memoria inválida, desbordamiento de búfer, corrupción de tablas de página) puede provocar un *kernel panic* del ARM11 y, si afecta a rutas de arranque o a la comunicación PXI con ARM9, dejar el sistema no arrancable.
>
> **Cómo mitigar el riesgo:**
> 1. **Backup completo de NAND** antes de tocar nada (usar hardmod o Boot9strap/GodMode9 según el estado de la consola). Guardar el backup en sitio seguro, fuera de la consola.
> 2. **Backup de `movable.sed`, `otp.bin`, `seeds` y copias de `FIRM`/`arm9.bin`/`arm11.bin`** — sin ellos no se puede volver a firmar/descifrar nada específico de esa consola.
> 3. **Probar drivers primero en emulador (Citra) o en un dump de NAND en PC**, nunca directamente en el hardware si existe alternativa.
> 4. **Mantener un método de recuperación** (hardmod, NAND programmer, o una consola de respaldo con bootROM explotable) antes de escribir en FIRM.
> 5. **Nunca escribir código de kernel no firmado** en una partición de arranque sin poder revertir con un FIRM conocido bueno.
> 6. **Validar checksums y firmas** de cualquier binario antes de flashear.
>
> Si no dispone de respaldo de NAND y de un método de recuperación, **NO pruebe drivers críticos ni modifique FIRM/almacenamiento en hardware real**.

---

## 1. Introducción y Alcance

Este manual describe cómo programar **drivers críticos de kernel (EL1)** para Nintendo 3DS, abarcando ambos procesadores:

- **ARM11 MPCore (ARMv6K):** Kernel de aplicaciones (`arm11.bin`), ejecuta en EL1, gestiona procesos, hilos, memoria virtual (FCRAM), syscalls SVC, sysmodules, y comunicación PXI con ARM9.
- **ARM946E-S (ARMv5TE):** Núcleo de seguridad (`arm9.bin`), ejecuta en EL1/secure mode, gestiona claves de consola, criptografía, PMIC, SD/MMC seguro, y arranque seguro.

> **Estado de verificación:** Los kernels `arm11_section1.bin` (Kernel11 real), `arm9.bin` (Kernel9 + Process9) y `arm11.bin` (5 módulos FIRM NCCH) fueron descifrados y analizados en este repositorio (ver `KERNEL_ANALISIS.md`). Las direcciones de carga, entry points, vectores de excepción, la tabla de 109 SVCs de Kernel11 (`0xFFF02328`), la tabla de 40 SWIs de Kernel9 (`0x08007938`), el PMU CP15 (`c15, c12, 0..3`) + `SVC 0x3E`, y el MMIO PXI (`0x1EC63000` / `0x10163000` y `0x10008000`) están **`[VERIFICADO]`** directamente en los binarios.

---

## 2. Arquitectura del Sistema (Verificada en Binario)

### 2.1 Kernels Descifrados y Analizados

| Elemento | ARM11 Kernel11 (`arm11_section1.bin`) | ARM9 Kernel9 + Process9 (`arm9.bin`) |
|----------|---------------------------------------|--------------------------------------|
| Archivo | `binarios_descifrados/FIRM_0002/arm11_section1.bin` | `binarios_descifrados/FIRM_0002/arm9.bin` |
| Arquitectura | ARMv6K MPCore | ARMv5TE ARM946E-S |
| Dirección de carga (FIRM) | `0x1FF80000` (MMU runtime `0xFFF00000`, vectores `0xFFFF0000`) | `0x08006800` (Process9 `.code` en `0x08028000`) |
| Entry point (header FIRM) | `0x1FFAE034` | `0x0801B01C` |
| Tamaño | 204,800 bytes (`0x32000`) | 541,184 bytes (`0x84200`) |
| Funciones | 415 `r2` / 654 C Ghidra (**838** símbolos con tabla SVC, RTTI `K*` y C, **0 `HYPOTHESIS`**) | 4,455 `r2` / 2,673 C Ghidra (**4,849** símbolos depurados con C Ghidra, **0 `HYPOTHESIS`**) |
| Tabla de Syscalls | 109 SVCs activos en `0xFFF02328` (dispatcher `0xFFF0220C`) | 40 SWIs activos en `0x08007938` (dispatcher `0x08007878`) |
| Modo | ARM + Thumb | ARM + Thumb |

> **Nota sobre `arm11.bin` (`0x1FF00000`, 218,624 B):** Es la Sección 0 de FIRM y contiene 5 módulos NCCH embebidos (`fs`, `loader`, `pm`, `sm`, `pxi`).

### 2.2 Archivos de Símbolos Separados (no modifican los binarios crudos)

| Archivo | Descripción |
|---------|-------------|
| `arm11_kernel11_friendly.sym` / `arm9_friendly.sym` | Tablas de símbolos (`0 HYPOTHESIS`) reconstruidas con C Ghidra |
| `pseudocodigo_k11/` / `pseudocodigo_arm9/` | Pseudocódigos C exportados por REA + Ghidra 12.2 (`decompile-index.json`) |
| `symbols_arm11_kernel11_friendly.r2` / `symbols_arm9_friendly.r2` | Scripts de flags para radare2 |
| `symbols_arm11_ghidra.py` / `symbols_arm9_ghidra.py` | Script de importación para Ghidra |
| `symbols_arm11_gdb.txt` / `symbols_arm9_gdb.txt` | Comandos para GDB |

---

## 3. Desarrollo de Drivers para ARM11 (EL1 - Kernel de Aplicaciones)

### 3.1 Entorno de Ejecución

El driver ARM11 ejecuta en **modo SVC (Supervisor)** del procesador ARM11 MPCore. Tiene acceso completo a:
- Memoria virtual (FCRAM) a través del MMU
- Registros CP15 (PMU, caché, MMU)
- Periféricos mediante MMIO (Memory Mapped I/O)
- Syscalls SVC del kernel11
- Comunicación PXI con ARM9

### 3.2 Registro de un Driver como Syscall

Para exponer funcionalidad a userland, un driver ARM11 debe registrarse en la tabla de SVCs del kernel11:

```c
/* ESTRUCTURA TÍPICA DE UN DRIVER ARM11 (pseudocódigo, verificar offsets) */

struct driver_entry {
    uint32_t svc_number;      /* Número de SVC asignado por el kernel */
    void* handler;            /* Puntero a la función handler del driver */
    uint32_t permissions;     /* Qué procesos pueden llamar (capabilities) */
};

/* Registro conceptual - requiere acceso al kernel11 */
int register_driver(uint32_t svc_num, void* handler, uint32_t perms);
```

> `[POR VERIFICAR]` El mecanismo exacto de registro de SVCs en el kernel11 requiere análisis del SVC handler en `arm11.bin`.

### 3.3 Acceso a Registros CP15 (PMU `c15,c12`, Caché, MMU) `[VERIFICADO]`

El ARM11 MPCore expone su PMU mediante **CP15 `c15, c12, 0..3`** (verificado en `arm11_section1.bin` @ `0xFFF11074..0xFFF11768`, no `c9, c12` de ARMv7) y además lo expone a procesos autorizados vía **`SVC 0x3E`** (`0xFFF03664` → `0xFFF0AC44`, deshabilitado en Exheaders de SysModules retail):

```c
/* Registros PMU reales en ARM11 MPCore (CP15 c15, c12) - solo modo kernel */
static inline uint32_t arm11_pmu_read_pmnc(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 0" : "=r" (val));
    return val;
}

static inline void arm11_pmu_write_pmnc(uint32_t val) {
    __asm__ volatile ("mcr p15, 0, %0, c15, c12, 0" :: "r" (val));
}

static inline uint32_t arm11_pmu_read_ccnt(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 1" : "=r" (val));
    return val;
}

static inline uint32_t arm11_pmu_read_pmn0(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 2" : "=r" (val));
    return val;
}

static inline uint32_t arm11_pmu_read_pmn1(void) {
    uint32_t val;
    __asm__ volatile ("mrc p15, 0, %0, c15, c12, 3" : "=r" (val));
    return val;
}
```

> `[ADVERTENCIA]` Acceder a CP15 desde modo usuario genera `Undefined Instruction`. Solo código de kernel (SVC mode) puede ejecutar `mrc`/`mcr` a CP15.

### 3.4 Gestión de Memoria y Caché

Para drivers que comparten memoria con ARM9 (buffers PXI):

```c
/* Limpiar caché de datos para una dirección (dc clean) */
static inline void arm11_cache_clean(void* addr, size_t size) {
    /* Iterar por líneas de caché y hacer dc clean */
    __asm__ volatile ("dmb" ::: "memory");
    /* ... implementación específica de línea por línea ... */
    __asm__ volatile ("dsb" ::: "memory");
}

/* Invalidar caché de instrucciones (ic invalidate) */
static inline void arm11_cache_invalidate_ic(void) {
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r" (0));
    __asm__ volatile ("dsb" ::: "memory");
    __asm__ volatile ("isb");
}
```

### 3.5 Ejemplo: Driver PMU (Contadores de Rendimiento)

Un driver de gobernador de rendimiento puede leer el CCNT para estimar carga de CPU:

```c
/* Pseudocódigo - gobernador simplificado */
struct pmu_driver_state {
    uint32_t last_ccnt;
    uint32_t last_time;
    uint32_t cpu_usage_pct;
};

void pmu_driver_tick(struct pmu_driver_state* state) {
    uint32_t current_ccnt = arm11_pmu_read_ccnt();
    uint32_t delta_ccnt = current_ccnt - state->last_ccnt;
    /* Calcular uso y decidir DVFS */
    state->last_ccnt = current_ccnt;
}
```

---

## 4. Desarrollo de Drivers para ARM9 (EL1 - Núcleo de Seguridad)

### 4.1 Entorno de Ejecución

El driver ARM9 ejecuta en **modo Supervisor** del ARM946E-S. Tiene acceso a:
- Claves de consola (keyX/keyY, movable.sed derivadas)
- Criptografía hardware (AES, RSA, SHA)
- PMIC (power management)
- SD/MMC en modo seguro
- SecureZone de NAND

### 4.2 Dispatcher y Tabla de SWIs de Kernel9 `[VERIFICADO]`

El ARM9 usa `SWI` (`SVC` en ARM11). En `arm9.bin`, el dispatcher SWI reside en **`0x08007878`** y despacha a través de la tabla de punteros **`0x08007938`** (**40 entradas activas** en el rango `0x08..0x7C`, verificando el bitmap de permisos del proceso igual que Kernel11).

> **Nota:** Las constantes previas `0xFF8000`/`0xFF8001` en `0x08018F64` correspondían a datos/constantes junto a la tabla RTTI `K*` de Kernel9, no a instrucciones SWI. Ver `KERNEL_ANALISIS.md` §4 para la lista completa de las 40 direcciones SWI verificadas.

### 4.3 Acceso a Claves y Criptografía

Un driver ARM9 que necesite criptografía debe usar los servicios del kernel ARM9, no acceder directamente a las claves:

```c
/* Conceptual - acceso a servicios criptográficos ARM9 */
int arm9_crypto_aes_encrypt(const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, uint8_t* out, size_t len);

/* Los drivers ARM11 NO pueden llamar esto directamente - deben ir vía PXI */
```

> `[ADVERTENCIA]` Las claves de consola nunca deben exponerse a ARM11. Todo acceso criptográfico desde ARM11 debe ir a través de PXI → ARM9.

---

## 5. Comunicación PXI (ARM11 ↔ ARM9)

El PXI es el canal principal de comunicación interprocesador. Un driver ARM11 que necesite servicios de ARM9 (criptografía, PMIC, SD seguro) debe usar PXI.

### 5.1 Registros MMIO e IRQs PXI Verificados `[VERIFICADO]`

Extraídos directamente de `FIRM:pxi` (`0004013000001402`, embebido en `arm11.bin` @ `0x32200`) y `arm9.bin`:
- **ARM11 PXI MMIO:** física `0x10163000`, mapeada por Exheader (`0xFFE1EC63`) a **`0x1EC63000`**:
  - `+0x00`: `PXI_SYNC` (32-bit)
  - `+0x04`: `PXI_CNT` (16-bit — bit 1 `0x0002` SEND Full, bit 3 `0x0008` Flush, bit 8 `0x0100` RECV Empty, `0xC008` Enable)
  - `+0x08`: `PXI_SEND` (32-bit TX FIFO)
  - `+0x0C`: `PXI_RECV` (32-bit RX FIFO)
- **IRQs PXI (ARM11):** `80..83` (`0x50..0x53`), enlazadas con `SVC 0x50` (`BindInterrupt` @ `0x00102BD4`): `0x52` (82) RECV y `0x53` (83) SEND.
- **ARM9 PXI MMIO:** **`0x10008000`** (verificado en Kernel9 @ `0x0800A148` y Process9 @ `0x0801D4F0..0x0804D28C`).

### 5.2 Flujo PXI para Drivers

```
Driver ARM11                          PXI                              Kernel ARM9
--------                              ---                            -----------
1. Preparar payload en buffer         ---------------->                4. Recibir IRQ PXI
   compartido (limpiar caché)                                              5. Leer comando PXI RX
2. Escribir comando en registro       <---------------                 6. Procesar solicitud
   PXI TX + generar IRQ                                                 7. Escribir respuesta PXI RX
3. Esperar con timeout                ---------------->                8. Generar IRQ PXI
                                                    <---------------   9. Driver ARM11 lee respuesta
```

### 5.2 Requisitos de Hardening PXI

- **Timeout obligatorio:** Toda operación PXI debe tener un timeout para evitar bloqueo infinito si ARM9 no responde.
- **Limpieza de caché:** Limpiar (clean) y invalidar (invalidate) las líneas de caché del buffer compartido antes y después de cada operación PXI.
- **Validación de entrada:** Validar todos los parámetros recibidos de ARM9 antes de usarlos en ARM11, y viceversa.
- **No compartir claves:** Nunca colocar claves de consola o material criptográfico en buffers PXI sin cifrar.

---

## 6. Acceso a Hardware y MMIO

### 6.1 Mapas de Memoria (Referencia)

| Región | Uso | Acceso |
|--------|-----|--------|
| 0x1FF00000 | ARM11 kernel (arm11.bin) | Solo ARM11 EL1 |
| 0x08006800 | ARM9 kernel (arm9.bin) | Solo ARM9 EL1 |
| 0x1F000000-0x1F5FFFFF | StaticMapping (ej. ns module) | ARM11 (ver exheader) |
| FCRAM | Memoria principal aplicaciones | ARM11 EL0/EL1 |
| AXI WRAM | Memoria de trabajo ARM9 | ARM9 principalmente |

> `[POR VERIFICAR]` Las direcciones MMIO exactas de periféricos (PMIC, GPU PICA, controlador SD, etc.) requieren análisis adicional de `arm11.bin` y `arm9.bin`.

### 6.2 Lectura/Escritura de Registros MMIO

```c
/* Lectura de registro MMIO (volatile, sin optimización) */
static inline uint32_t mmio_read(uint32_t addr) {
    return *(volatile uint32_t*)addr;
}

/* Escritura de registro MMIO */
static inline void mmio_write(uint32_t addr, uint32_t val) {
    *(volatile uint32_t*)addr = val;
    __asm__ volatile ("dsb" ::: "memory");  /* Barrera de memoria */
}

/* Ejemplo: escribir a un registro hipotético a 0x10140000 */
#define REG_PMU_CTRL 0x10140000  /* EJEMPLO - verificar dirección real */
mmio_write(REG_PMU_CTRL, 0x1);
```

> `[ADVERTENCIA]` Las direcciones MMIO en este manual son EJEMPLOS. Usar direcciones incorrectas puede causar corrupción de memoria o hard brick.

---

## 7. Sistemas de Archivos y Almacenamiento

### 7.1 Particiones de NAND

| Partición | Uso | Acceso |
|-----------|-----|--------|
| FIRM | Firmware ARM9 + ARM11 | Solo ARM9 durante arranque |
| SecureZone | Claves, seeds, datos seguros | Solo ARM9 |
| SD/MMC | Títulos, saves, contenido | ARM9 (modo seguro) + ARM11 (vía sysmodule) |

### 7.2 Requisitos para Drivers de Almacenamiento

- **Validar firmas:** Todo bloque escrito en NAND debe tener checksum/firma válida.
- **Escritura atómica:** Usar doble buffer o journaling mínimo para evitar corrupción por apagado brusco.
- **No cachear claves:** Nunca guardar claves de consola en caché de escritura sin cifrar.
- **ARM9 para SecureZone:** Los drivers ARM11 no pueden acceder directamente a SecureZone; deben ir vía PXI.

---

## 8. Optimización y Governors (Rendimiento Extremo)

### 8.1 Governor de CPU basado en PMU

Un governor puede leer el CCNT del PMU para decidir cambios de frecuencia (DVFS):

```c
struct governor_config {
    uint32_t target_freq_khz;
    uint32_t min_freq_khz;
    uint32_t max_freq_khz;
    uint32_t up_threshold_pct;
    uint32_t down_threshold_pct;
    uint32_t sampling_interval_ms;
};

void governor_run(struct governor_config* cfg) {
    uint32_t ccnt_before = arm11_pmu_read_ccnt();
    /* ... esperar sampling_interval ... */
    uint32_t ccnt_after = arm11_pmu_read_ccnt();
    uint32_t cycles = ccnt_after - ccnt_before;
    /* Calcular uso y ajustar frecuencia vía PMIC (PXI a ARM9) */
}
```

### 8.2 Habilitación/Deshabilitación de Cores MPCore

El ARM11 MPCore tiene múltiples cores (2 en old3DS, 4 en new3DS). Un driver que gestione cores debe:

1. Sincronizar con el scheduler del kernel11 antes de apagar un core.
2. Verificar que el core esté inactivo antes de hacer clock gating.
3. Usar barreras de caché (`dmb`, `dsb`) para coherencia entre cores.
4. No apagar el core que ejecuta el driver mismo.

---

## 9. Checklist de Hardening para Drivers Críticos

Antes de desplegar cualquier driver en hardware real:

- [ ] Respaldo completo de NAND + `movable.sed` + `otp.bin` + `seeds`
- [ ] Driver probado en emulador (Citra) o dump de NAND en PC
- [ ] Todos los punteros de userland validados antes de dereferenciar en kernel
- [ ] Límites de tamaño verificados en todas las lecturas/escrituras
- [ ] Acceso a CP15/PMU restringido a modo kernel, mediado por SVC
- [ ] Barreras de memoria (`dmb`/`dsb`) en buffers compartidos PXI
- [ ] Limpieza/invalidación de caché en buffers compartidos con ARM9
- [ ] Spinlocks/semáforos protegiendo estructuras compartidas entre cores MPCore
- [ ] Timeouts en todas las comunicaciones PXI con ARM9
- [ ] Validación de firmas/checksums antes de escribir en NAND/FIRM
- [ ] Método de recuperación disponible (hardmod / NAND programmer / consola de respaldo)
- [ ] Direcciones MMIO verificadas contra `arm11.bin`/`arm9.bin` descifrados
- [ ] Números de SVC verificados contra la tabla de syscalls del kernel11

---

## 10. Comandos de Herramientas para Análisis y Desarrollo

### 10.1 Descifrar FIRM y extraer kernels

```bash
# Descifrar título FIRM como NCCH
ctrtool -v --intype=ncch --exheader=exh.bin --exefs=exefs.bin title_firm.cxi

# Extraer sección .firm del ExeFS
ctrtool -v --exefsdir=exefs_dir title_firm.cxi

# Separar FIRM en secciones (arm9.bin, arm11.bin)
ctrtool -v --intype=firm --firmdir=firm_out --firmtype=nand exefs_dir/firm.bin
```

### 10.2 Analizar kernel con radare2

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

### 10.3 Cargar símbolos en radare2

```bash
# ARM11 Kernel11 (nombres verificados + SVC/PMU)
r2 -a arm -b 32 -m 0xFFF00000 -i binarios_descifrados/FIRM_0002/symbols_arm11_kernel11_friendly.r2 binarios_descifrados/FIRM_0002/arm11_section1.bin

# ARM9 (nombres verificados Kernel9 + Process9)
r2 -a arm -b 32 -B 0x08006800 -i binarios_descifrados/FIRM_0002/symbols_arm9_friendly.r2 binarios_descifrados/FIRM_0002/arm9.bin
```

### 10.4 Cargar símbolos en Ghidra

1. Nuevo proyecto → Importar `arm11_section1.bin` (`0xFFF00000`) o `arm9.bin` (`0x08006800`)
2. **Language:** `ARM:LE:32:v6k` (ARM11) / `ARM:LE:32:v5te` (ARM9)
3. **Image base:** `0xFFF00000` (Kernel11 runtime) / `0x08006800` (ARM9)
4. Ejecutar script: `symbols_arm11_kernel11_friendly_ghidra.py` / `symbols_arm9_friendly_ghidra.py`

---

## 11. Referencias y Archivos del Repositorio

| Archivo | Contenido |
|---------|-----------|
| `KERNEL_ANALISIS.md` | Análisis completo de kernels ARM11/ARM9 (SVCs, vectores, PMU, PXI) |
| `SIMBOLOS_KERNEL.md` | Tabla y archivos de símbolos separados del binario crudo |
| `SIMBOLOS_RECREADOS.md` | Tabla completa de los 58 SysModules + 5 módulos FIRM |
| `ARQ_ARM11_vs_ARM9.md` | Arquitectura ARM11 vs ARM9 y flujo del kernel |
| `GUIA_DRIVERS_CRITICOS.md` | Guía de diseño y hardening (versión anterior) |
| `README.md` | README principal del repositorio |
| `binarios_descifrados/FIRM_0002/arm11_section1.bin` | Kernel ARM11 real (204,800 B) |
| `binarios_descifrados/FIRM_0002/arm11.bin` | Sección 0 FIRM con 5 NCCHs (`fs`, `loader`, `pm`, `sm`, `pxi`) |
| `binarios_descifrados/FIRM_0002/arm9.bin` | Kernel ARM9 + Process9 descifrado (541,184 B) |

---

## 12. Tabla de Resumen de Evidencia

| Elemento | Estado | Ubicación |
|----------|--------|-----------|
| Kernels `arm11_section1.bin` / `arm9.bin` / `arm11.bin` descifrados | `[VERIFICADO]` | `binarios_descifrados/FIRM_0002/` |
| 654 funciones C Kernel11 (**838** totales: **287** `CONFIRMED`, **551** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) / 2,673 funciones C ARM9 (**4,849** totales: **311** `CONFIRMED`, **4,538** `EVIDENCE_BASED`, **0** `HYPOTHESIS`) | `[VERIFICADO]` | `arm11_kernel11_friendly.sym`, `arm9_friendly.sym`, `pseudocodigo_k11/`, `pseudocodigo_arm9/` |
| Entry points `0x1FFAE034` (ARM11) y `0x0801B01C` (ARM9) | `[VERIFICADO]` | Header `firm.bin` |
| Tabla de 109 SVCs Kernel11 (`0xFFF02328`) y dispatcher (`0xFFF0220C`) | `[VERIFICADO]` | `KERNEL_ANALISIS.md` §3 |
| Tabla de 40 SWIs Kernel9 (`0x08007938`) y dispatcher (`0x08007878`) | `[VERIFICADO]` | `KERNEL_ANALISIS.md` §4 |
| Vectores de excepción ARM11 (`0x1FFAD000`/`0xFFFF0000`) y ARM9 (`0x0800E7E0`) | `[VERIFICADO]` | `KERNEL_ANALISIS.md` §2 |
| PMU CP15 `c15, c12, 0..3` + `SVC 0x3E` (`0xFFF03664`) | `[VERIFICADO]` | `KERNEL_ANALISIS.md` §5 |
| Registros PXI `0x1EC63000` (`0x10163000`), IRQs `80..83` y ARM9 `0x10008000` | `[VERIFICADO]` | `KERNEL_ANALISIS.md` §6 |
| 58 SysModules + 5 módulos FIRM (funciones y SVCs) | `[VERIFICADO]` | `SIMBOLOS_RECREADOS.md` §6 |
| Advertencia de respaldo NAND | `[VERIFICADO]` | Inicio de este manual |
