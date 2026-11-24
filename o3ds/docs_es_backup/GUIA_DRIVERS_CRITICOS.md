# (c) Guía de diseño y hardening para drivers críticos en Nintendo 3DS

> **ADVERTENCIA OBLIGATORIA — LÉASE ANTES DE NINGUNA PRUEBA**
>
> **SIEMPRE realice un respaldo completo de la NAND (y de todos los archivos críticos de recuperación: bootROM dumps, `movable.sed`, `otp.bin`, `seeds`, `movable.sed`, NAND bin, y cualquier backup de `FIRM`/`arm9.bin`/`arm11.bin`) ANTES de probar drivers críticos, modificar `FIRM` o escribir en el almacenamiento de la consola.**
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
> 2. **Backup de `movable.sed`, `otp.bin`, `seeds` y `movable.sed`** — sin ellos no se puede volver a firmar/descifrar nada específico de esa consola.
> 3. **Probar drivers primero en emulador (Citra) o en un dump de NAND en PC**, nunca directamente en el hardware si existe alternativa.
> 4. **Mantener un método de recuperación** (hardmod, NAND programmer, o una consola de respaldo con bootROM explotable) antes de escribir en FIRM.
> 5. **Nunca escribir código de kernel no firmado** en una partición de arranque sin poder revertir con un FIRM conocido bueno.
> 6. **Validar checksums y firmas** de cualquier binario antes de flashear.
>
> Si no dispone de respaldo de NAND y de un método de recuperación, **NO pruebe drivers críticos ni modifique FIRM/almacenamiento en hardware real**.

---

## 1. Alcance y modelo de amenazas

Esta guía está dirigida al desarrollo de **drivers críticos de kernel** para Nintendo 3DS (ARM11 ARMv6K MPCore y ARM9 ARMv5TE ARM946E-S), específicamente:

- Contadores de rendimiento PMU en ARM11 vía registros CP15.
- Acceso a sistemas de archivos exóticos (particiones de NAND, SD/MMC en modo seguro de ARM9, FIRM, SecureZone).
- Optimizadores extremos de rendimiento / governors (DVFS, scalado de frecuencia, habilitación/deshabilitación de cores del MPCore).
- Comunicación con app nativa (userland ↔ kernel vía SVC/PXI) y almacenamiento.

**Suposiciones del modelo de amenazas:**
- El atacante tiene código de usuario (ARM11 userland) y puede intentar elevar privilegios vía SVC o PXI.
- El driver de kernel corre en modo privilegiado (SVC mode ARM11 / Supervisor ARM9).
- Un bug en el driver puede comprometer todo el sistema (kernel panic, corrupción de memoria, exposición de claves de ARM9).
- El almacenamiento (NAND/SD) puede ser apagado bruscamente; el driver debe ser robusto ante escritura parcial y corrupción.

---

## 2. Contexto arquitectónico (referencia, pendiente de verificar contra binarios descifrados)

> Esta sección resume el modelo de referencia de 3DS. **No está verificada contra los binarios cifrados de este repo** (ver `00_ESTADO_Y_METODOLOGIA.md`). Validar direcciones, números de SVC y registros antes de escribir código.

| Componente | Núcleo | Arquitectura | Rol relevante para drivers |
|------------|--------|--------------|---------------------------|
| Kernel de aplicaciones | ARM11 | ARMv6K MPCore | SVC, memoria virtual (FCRAM), PMU/CP15, sysmodules, PXI cliente |
| Núcleo de seguridad | ARM9 | ARMv5TE ARM946E-S | Claves de consola, cripto, PMIC, SD seguro, PXI servidor, arranque seguro |
| Comunicación IPC | ARM11↔ARM9 | PXI | FIFO/mailbox, IRQ bidireccional, buffers compartidos |
| Contadores de rendimiento | ARM11 | CP15 (PMU) | CCNT, PMNC, PMXEVTYPER, PMXEVCNTR, PMCEID |

---

## 3. Diseño de drivers críticos — principios

### 3.1 Principio de mínimo privilegio
- Un driver debe ejecutarse con el **mínimo nivel de privilegio necesario**. Si solo necesita leer un contador PMU, no requiere acceso directo a registros de PMIC ni a claves de ARM9.
- Separar la lógica de usuario (app nativa) de la lógica de kernel: la app envía solicitudes vía SVC o PXI; el kernel las valida antes de actuar.

### 3.2 Validación estricta de entradas (SVC / PXI)
- **Todo parámetro proveniente de userland** (punteros, tamaños, handles, IDs de comando PXI) debe validarse antes de usarse:
  - Verificar que los punteros apunten a memoria de usuario mapeada y con los permisos correctos (lectura/escritura según corresponda).
  - Verificar tamaños contra límites máximos (evitar desbordamientos de búfer en el kernel).
  - Verificar que los handles sean válidos y pertenezcan al proceso llamante.
- Usar `copy_from_user` / `copy_to_user` equivalentes con verificación de límites; nunca dereferenciar punteros de usuario directamente en contexto de kernel sin validación.

### 3.3 Gestión de memoria segura
- Las tablas de página (MMU del ARM11) y los atributos de memoria (AP bits, dominio, XN) deben configurarse para que el kernel no ejecute datos ni writable-executable simultáneamente.
- Al asignar memoria para buffers compartidos PXI, usar páginas dedicadas, limpiar/invalidar caché CP15 (`dc clean`, `dc invalidate`, `ic invalidate`) y usar barreras de memoria (`dmb`, `dsb`) para coherencia entre ARM11 y ARM9.
- Nunca compartir páginas que contengan claves, credenciales o estructuras internas del kernel con userland o con ARM9 sin cifrado/acotamiento.

### 3.4 Concurrencia y sincronización
- El ARM11 MPCore tiene múltiples cores. Un driver crítico debe usar spinlocks o semáforos del kernel para proteger estructuras compartidas.
- Deshabilitar interrupciones solo por el tiempo estrictamente necesario; evitar bloqueos largos con interrupciones deshabilitadas.
- Al acceder a registros de hardware compartidos (PMU, PMIC, PXI), usar acceso atómico y barreras de memoria.

---

## 4. Contadores PMU en ARM11 (CP15) — guía específica

El ARM11 MPCore expone un PMU mediante registros CP15 (p15). Un driver de gobernador o profiling puede leerlos desde modo kernel.

### 4.1 Registros CP15 de interés (ARMv6K)

| Registro | Propósito |
|----------|-----------|
| `PMNC` | Control del PMU (habilitar, reset, contar ciclos) |
| `CCNT` | Contador de ciclos (cycle counter) |
| `PMXEVTYPER` | Tipo de evento del contador seleccionado |
| `PMXEVCNTR` | Valor del contador de eventos seleccionado |
| `PMCEID0/1` | Eventos implementados (capacidad del PMU) |

> **Advertencia:** acceder a CP15 desde modo usuario genera `Undefined Instruction`. Solo código de kernel (SVC mode) puede leer/escribir estos registros.

### 4.2 Ejemplo de uso (referencia, pseudocódigo)

```c
/* SOLO ILUSTRATIVO — verificar registros exactos en TRM ARM11 MPCore y binario descifrado */
static inline unsigned int pmccntr_read(void) {
    unsigned int val;
    asm volatile ("mrc p15, 0, %0, c9, c13, 0" : "=r" (val)); /* PMCCNTR */
    return val;
}

static inline void pmnc_enable(void) {
    asm volatile ("mcr p15, 0, %0, c9, c12, 0" :: "r" (1)); /* habilitar PMU */
}
```

### 4.3 Hardening del driver PMU
- El driver debe **mediar el acceso** al PMU: userland no lee CP15 directamente; solicita lecturas al driver vía SVC.
- Validar que el proceso llamante tenga permiso para profiling (capacidad en exheader).
- Limitar la frecuencia de lectura para no introducir overhead medible ni alterar el comportamiento del sistema (efecto observador).
- No exponer el valor bruto del ciclo como fuente de entropía ni de generación de claves (puede ser predecible).

---

## 5. Sistemas de archivos exóticos y almacenamiento

La 3DS usa particiones de NAND (FIRM, SecureZone, SD/MMC) con formatos específicos. Un driver de almacenamiento crítico debe:

### 5.1 Principios para NAND / SecureZone / FIRM
- **Solo ARM9** debe tocar directamente las claves de SecureZone y el descifrado de FIRM. El ARM11 solicita operaciones vía PXI.
- Validar firmas y checksums de cualquier bloque antes de escribir en NAND.
- Implementar escritura atómica (doble buffer o journaling mínimo) para evitar corrupción por apagado brusco.
- Nunca cachear claves o material criptográfico en memoria compartida PXI sin cifrar.

### 5.2 SD/MMC en modo seguro (ARM9)
- El acceso a SD para títulos cifrados pasa por ARM9. Un driver ARM11 que necesite leer archivos debe usar los syscalls de filesystem del kernel11 o pedir vía PXI, no acceder al controlador SD directamente.
- Verificar integridad de archivos leídos (hash) antes de ejecutarlos o usarlos como datos de configuración.

---

## 6. Governors y optimizadores extremos de rendimiento

Un governor decide frecuencias de CPU y estados de los cores del MPCore basándose en lecturas del PMU (CCNT) y en la carga del sistema.

### 6.1 Requisitos de seguridad
- **Validar límites de frecuencia y voltaje** antes de programar el PMIC (vía PXI a ARM9). Valores fuera de rango pueden dañar el hardware o causar inestabilidad.
- **No permitir que userland escriba directamente registros de frecuencia/voltaje.** Toda solicitud de DVFS pasa por el governor del kernel, que valida contra una tabla de frecuencias permitidas.
- **Evitar cambios demasiado frecuentes** (throttling del governor): establecer un intervalo mínimo entre reajustes para no saturar el PXI ni el PMIC.
- **Fallback seguro:** ante cualquier error del governor, volver a frecuencias por defecto seguras (no sobrecalentar, no sobrevoltaje).

### 6.2 Habilitación/deshabilitación de cores (MPCore)
- El ARM11 MPCore tiene cores secundarios. Un driver que los active/desactive debe:
  - Sincronizar con el scheduler del kernel11 para no migrar hilos a un core que se va a apagar.
  - Verificar que el core esté inactivo antes de hacer clock gating.
  - Usar barreras de caché y memoria para coherencia entre cores.

---

## 7. Comunicación con app nativa (userland) y almacenamiento

### 7.1 SVC y PXI
- Las apps nativas invocan SVC para pedir servicios al kernel11. Un driver crítico expone su funcionalidad mediante un número de SVC registrado y validado.
- Para operaciones que requieren ARM9, el driver ARM11 envía un mensaje PXI y espera la respuesta con timeout (evitar bloqueo infinito si ARM9 no responde).
- Implementar timeouts y reintentos acotados en toda comunicación PXI.

### 7.2 Almacenamiento desde userland
- El acceso a archivos desde userland usa los syscalls de filesystem del kernel11 (abrir, leer, escribir, cerrar). El driver de almacenamiento debe:
  - Validar permisos de archivo (lectura/escritura) del proceso llamante.
  - Sanitizar rutas (evitar traversal `../` fuera de sandbox).
  - Limitar tamaño de lecturas/escrituras para no agotar memoria del kernel.

---

## 8. Checklist de hardening antes de desplegar en hardware real

- [ ] Respaldo completo de NAND + `movable.sed` + `otp.bin` + `seeds` + backups de `FIRM`/`arm9.bin`/`arm11.bin`.
- [ ] Driver probado en emulador (Citra) o dump de NAND en PC antes del hardware.
- [ ] Todos los punteros de userland validados antes de dereferenciar en kernel.
- [ ] Límites de tamaño verificados en todas las lecturas/escrituras.
- [ ] Acceso a CP15/PMU restringido a modo kernel, mediado por SVC.
- [ ] Barreras de memoria (`dmb`/`dsb`) y operaciones de caché (clean/invalidate) en buffers compartidos PXI.
- [ ] Spinlocks/semáforos protegiendo estructuras compartidas entre cores MPCore.
- [ ] Timeouts en todas las comunicaciones PXI con ARM9.
- [ ] Validación de firmas/checksums antes de escribir en NAND/FIRM.
- [ ] Método de recuperación disponible (hardmod / NAND programmer / consola de respaldo).
- [ ] Direcciones, números de SVC y registros verificados contra binarios descifrados (no usar valores inventados).

---

## 9. Tabla de estados de evidencia

| Elemento | Estado | Observación |
|----------|--------|-------------|
| Advertencia de respaldo NAND | `[VERIFICADO EN ESTE REPO]` | Requisito del objetivo; incluido al inicio de esta guía |
| Arquitectura ARM11/ARM9 | `[CONOCIMIENTO PÚBLICO 3DS]` | Ver `ARQ_ARM11_vs_ARM9.md`; pendiente de verificar en binarios descifrados |
| Registros CP15/PMU | `[POR VERIFICAR]` | Según TRM ARM11 MPCore; no confirmado en `arm11.bin` de este repo (cifrado) |
| Números de SVC y tabla syscall | `[POR VERIFICAR]` | Pendiente de `arm11.bin` descifrado |
| Registros PXI y direcciones MMIO | `[POR VERIFICAR]` | Pendiente de binarios descifrados y reference del SoC |
| Formatos de NAND/SecureZone/FIRM | `[CONOCIMIENTO PÚBLICO 3DS]` | Pendiente de verificación en binarios descifrados |
