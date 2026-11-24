# (a) Arquitectura ARM11 vs ARM9 y flujo del kernel — Nintendo 3DS

> **Estado de evidencia:** Actualizado con hallazgos **`[VERIFICADO EN ESTE REPO]`** tras el descifrado de `FIRM_0002` (`arm11_section1.bin`, `arm11.bin`, `arm9.bin`) y los 58 SysModules (ver `KERNEL_ANALISIS.md` y `SIMBOLOS_RECREADOS.md`). Las secciones descriptivas generales conservan etiquetas explícitas de `[CONOCIMIENTO PÚBLICO 3DS]` o `[VERIFICADO]`.

---

## 1. Resumen de los dos procesadores

| Característica | ARM11 MPCore | ARM946E-S |
|----------------|--------------|-----------|
| Arquitectura | ARMv6K | ARMv5TE |
| Núcleo | MPCore (multinúcleo; 2 cores en old3DS, 4 en new3DS; uno ejecuta kernel/app) | Unicore |
| Rol en 3DS | Ejecuta userland, procesos de aplicación, sysmodules y el kernel ARM11 ("srv"/kernel11) | Núcleo de seguridad ("firm9"/arm9.bin), arranque seguro, claves, criptografía, PMIC, SD/MMC |
| Reloj típico | ~268 MHz (old3DS), ~804 MHz (new3DS) | ~134 MHz (old3DS) |
| Endianness | Little-endian | Little-endian |
| Modos de ejecución | ARM + Thumb | ARM + Thumb |

### 1.1 Partición de responsabilidades (modelo de referencia)

- **ARM9 (firm9/arm9.bin):** arranca primero tras el bootROM. Es el "secure core". Posee acceso directo a claves de consola (keyX/keyY), realiza el descifrado/validación del FIRM y de los títulos, gestiona el PMIC, la tarjeta SD (en modo seguro) y actúa como ancla de confianza. El ARM11 no puede leer estas claves directamente.
- **ARM11 (arm11.bin):** kernel de aplicaciones. Gestiona procesos, hilos, memoria virtual (FCRAM), syscalls (SVC), servicios PXI y la comunicación con el ARM9 a través del bus PXI y memoria compartida.

> [POR VERIFICAR] La división exacta de qué syscalls residen en ARM9 vs ARM11 y los números de SVC específicos deben leerse del `arm9.bin` y `arm11.bin` descifrados.

---

## 2. Comunicación entre ARM11 y ARM9: PXI

El **PXI (Processor eXchange Interface)** es el canal principal de interprocesador ARM11↔ARM9.

| Elemento | Descripción |
|----------|-------------|
| Naturaleza | FIFO/mailbox basado en registros, con interrupciones por cada lado |
| Uso típico | ARM11 envía solicitudes (syscalls cruzados) y el ARM9 responde; también notificaciones de eventos |
| Sincronización | Polling de registros de estado + IRQ; handshake para evitar sobrescritura de mensajes pendientes |
| Memoria compartida | Regiones acordadas en la tabla de memoria (ver §3) para payloads grandes que no caben en los registros PXI |

### 2.1 Flujo PXI típico (referencia)

```
ARM11 (kernel)                    PXI bus                     ARM9 (firm9)
-------                           -------                     ---------
1. Escribe comando en registro    ---------------->           4. Recibe interrupción PXI
   PXI TX + parámetros                                      5. Lee comando, procesa
2. Genera IRQ PXI hacia ARM9      <---------------            6. Escribe respuesta en PXI RX
3. Espera (bloqueo o callback)    ---------------->           7. Genera IRQ PXI hacia ARM11
                                                <--------------- 8. ARM11 lee respuesta y despierta hilo
```

> `[VERIFICADO]` Los registros exactos de PXI se confirmaron en `FIRM:pxi` (`0004013000001402`, embebido en `arm11.bin` @ `0x32200`) y `arm9.bin`: MMIO ARM11 en `0x1EC63000` (física `0x10163000`, offsets `+0x00` SYNC, `+0x04` CNT, `+0x08` SEND, `+0x0C` RECV), IRQs `80..83` (`0x50..0x53`), y MMIO ARM9 en `0x10008000`. Ver `KERNEL_ANALISIS.md` §6.

### 2.2 Alternativa: llamadas cruzadas vía SVC

Algunas operaciones ARM11→ARM9 se implementan como SVC del ARM11 que el kernel11 traduce en un mensaje PXI al ARM9, en lugar de que el ARM11 llame directamente al ARM9.

> [POR VERIFICAR] Qué SVCs de ARM11 son "puente PXI" vs cuáles se resuelven enteramente en el kernel11.

---

## 3. Manejo de memoria (mapa de referencia)

La 3DS tiene una memoria compartida físicamente, pero cada núcleo ve regiones distintas con distintas atribuciones.

| Región (referencia) | Uso típico | Acceso |
|---------------------|------------|--------|
| FCRAM | Memoria principal de aplicaciones (256 MB old3DS / 512 MB new3DS) | ARM11 (usuario+kernel) |
| AXI WRAM | Memoria de trabajo de bajo latency | ARM9 principalmente; compartida con ARM11 en algunas zonas |
| VRAM / PICA mem | Gráficos (GPU PICA) | ARM11 (a través de comandos GPU) |
| Región segura / keys | Claves de consola, seed | Solo ARM9 (hardware-enforced) |
| PXI shared buffers | Payloads interprocesador | ARM11 + ARM9 (acuerdo de cache coherencia manual) |

### 3.1 Notas de coherencia de caché

El ARM11 MPCore tiene cachés L1/L2 por núcleo. Al compartir memoria con ARM9 (buffers PXI), el software debe:
- Limpiar (clean) y invalidar (invalidate) líneas de caché explícitamente mediante instrucciones CP15 antes de ceder el buffer al otro núcleo.
- Usar barreras de memoria (`dmb`, `dsb`) para ordenar escrituras.

> [POR VERIFICAR] Rangos de dirección exactos, tamaño de FCRAM por modelo y política de caché del kernel11.

---

## 4. Excepciones y vectores

| Núcleo | Vector table base (verificada) | Modo de excepción |
|--------|--------------------------------|-------------------|
| ARM9 | `0x0800E7E0` (copiada a `0x08000000` / `0xFFFF0000`) | Reset, Undef (`0x08007B58`), SWI (`0x08007878`), Prefetch (`0x08007700`), Data (`0x080076FC`), IRQ (`0x08007704`), FIQ |
| ARM11 | `0x1FFAD000` (mapeada por MMU en `0xFFFF0000`) | Reset (`0xFFFF0058`), Undef (`0xFFF02520`), SVC (`0xFFF0220C`), Prefetch (`0xFFF02084`), Data (`0xFFF020CC`), IRQ (`0xFFF02144`), FIQ (`0xFFF005D0`) |

- **ARM9:** Arranca en `0x0801B01C` (`arm9_entry`), inicializa MPU (`c5/c6`), configura vectores y salta a `kernel9_main` (`0x08006830`).
- **ARM11:** Arranca en `0x1FFAE034` (`arm11_entry`), configura stacks por modo, MMU (`TTBR0`/`TTBR1`) y salta a `kernel11_main_init` (`0xFFF00030`). Ver `KERNEL_ANALISIS.md` §2.

---

## 5. SVC y privilegios

### 5.1 ARM11 (kernel11)
- Las aplicaciones de usuario invocan **SVC** (número en `r0` o como inmediato, según la convención del kernel11) para pedir servicios al kernel: creación de hilos, memoria, servicios PXI, eventos, etc.
- El kernel valida los argumentos (punteros, handles, derechos) antes de ejecutar.
- Existen niveles de privilegio: **user** (aplicaciones), **kernel** (kernel11 y sysmodules privilegiados). Algunos sysmodules corren en kernel mode con acceso directo a registros de hardware.

### 5.2 ARM9 (firm9)
- Tiene su propio conjunto de SVC/SWI internos para criptografía, gestión de claves, acceso a SD y PMIC.
- El ARM11 no ejecuta SVC del ARM9 directamente; los pide vía PXI.

> [POR VERIFICAR] Números de SVC, convenciones de registro (qué va en r0-r3, valor de retorno en r0) y tabla de servicios del kernel11.

---

## 6. Acceso a hardware y periféricos (referencia)

| Periférico | Núcleo principal | Notas |
|------------|------------------|-------|
| PMIC (power) | ARM9 | Encendido/apagado, voltajes; ARM11 solicita vía PXI |
| SD/MMC | ARM9 (modo seguro) | Lectura de títulos/FIRM; ARM11 accede a archivos vía sysmodule |
| Cripto (AES, RSA, SHA) | ARM9 | Claves de consola no expuestas a ARM11 |
| GPU PICA | ARM11 | Comandos de renderizado por DMA/command buffer |
| Teclado / pantalla táctil | ARM11 (vía sysmodule) | |
| PMU / contadores de rendimiento | ARM11 (CP15) | Ver §7 |

> [POR VERIFICAR] Mapas de registros (MMIO) de cada periférico; no se incluyen direcciones para no inventar.

---

## 7. Contadores de rendimiento PMU en ARM11 (CP15) — relevante para drivers/governors

El ARM11 MPCore implementa su **Performance Monitoring Unit (PMU)** mediante **CP15 `c15, c12, 0..3`** `[VERIFICADO]` en `arm11_section1.bin` (`0xFFF11074..0xFFF11768`):

| Registro CP15 | CRn/CRm/Opc2 | Uso |
|---------------|--------------|-----|
| `PMNC` (PMN Control Register) | `c15, c12, 0` | Habilitar/deshabilitar contadores, reset, eventos |
| `CCNT` (Cycle Counter) | `c15, c12, 1` | Ciclos de reloj |
| `PMN0` (Event Counter 0) | `c15, c12, 2` | Contador de eventos 0 |
| `PMN1` (Event Counter 1) | `c15, c12, 3` | Contador de eventos 1 |

> `[VERIFICADO]` Kernel11 expone el control del PMU mediante **`SVC 0x3E`** (`0xFFF03664` → `0xFFF0AC44`), aunque ninguno de los 58 SysModules retail ni los 5 módulos FIRM tiene el bit `0x3E` habilitado en su Exheader. Usar CP15 desde modo usuario genera Undefined Instruction. Ver `KERNEL_ANALISIS.md` §5.

---

## 8. Flujo de arranque (referencia de alto nivel)

1. **bootROM (ARM9):** verifica firma del FIRM, descifra `arm9.bin` (firm9) con claves de consola, lo carga en RAM y salta a él.
2. **ARM9 (firm9):** inicializa PMIC, claves, valida y carga el FIRM del ARM11 (`arm11.bin`) en RAM; inicia el ARM11.
3. **ARM11 (arm11.bin):** inicializa MMU, vectores, kernel11, monta sysmodules, inicia servicios PXI y lanza el primer proceso de userland.

> [POR VERIFICAR] Secuencia exacta, direcciones de carga y puntos de entrada de `arm9.bin`/`arm11.bin`.

---

## 8. Hallazgos VERIFICADOS en binario descifrado (este repositorio)

> Fuente: `extraidos/SysModule_0004013000002102/raw/content.0000.00000005` descifrado con `ctrtool` + `aes_keys.txt`.
> Título: `0004013000002102` ("0430builder"), formato NCCH/CXI. Es un sysmodule de nivel usuario/kernel de aplicaciones **ARM11**.

| Hallazgo | Valor verificado | Dirección | Estado |
|----------|------------------|-----------|--------|
| Punto de entrada (.code) | `0x00000000` (relativo a base de carga) | `code.bin` offset 0 | CONFIRMADO |
| Modo de ejecución | ARM32 + Thumb (interworking GCC 3DS) | todo `code.bin` | CONFIRMADO |
| Endianness | Little-endian | todo `code.bin` | CONFIRMADO |
| Instrucción SVC #1 | `svc 0x9e` (encodificado `00f09eef`) | `0x0000006c` | CONFIRMADO |
| Instrucción SVC #2 | `svc 0x76` (encodificado `00f076ef`) | `0x000000bc` | CONFIRMADO |
| Función entry/init | `fcn.00000000` (44 B, 2 bloques) | `0x00000000` | CONFIRMADO |
| Función grande (servicio?) | `fcn.00000164` (912 B, 37 bloques) | `0x00000164` | CONFIRMADO |
| Función más grande | `fcn.00001e68` (756 B, 35 bloques) | `0x00001e68` | CONFIRMADO |
| Exheader magic | `pdn\0` (`70646e00`) | `exheader.bin` 0x00 | CONFIRMADO |
| Syscalls permitidos (exheader) | 01,02,03,06,08,09,0A,0B,0C,0F,11,13…57 | `exheader.bin` 0x364+ | CONFIRMADO |
| Arm9Capability | `none` | `exheader.bin` | CONFIRMADO |

> Estas direcciones son **relativas al inicio de la sección .code**. Para usarlas en el binario completo hay que sumar el offset de carga del ExeFS (ver `ctrtool` output: ExeFS offset `0x00000c00` en el NCCH).

> Total de funciones detectadas por radare2: **60** (lista completa en `binarios_descifrados/SysModule_0004013000002102/r2_functions_clean.txt`).

### 8.1 Ejemplo de comando de reproducción (radare2, verificado)

```bash
r2 -q -a arm -b 32 -i analyze.r2 SysModule_0004013000002102/code.bin
# dentro del script analyze.r2:
#   aaa
#   afl        -> lista las 60 funciones
#   pd 120 @ 0 -> desensambla el entry point
#   /ce svc    -> busca instrucciones SVC (halladas en 0x6c y 0xbc)
```

---

## 9. Tabla de resumen de verificación

| Tema | Estado | Dónde verificar |
|------|--------|-----------------|
| Binarios presentes están cifrados | `[VERIFICADO EN ESTE REPO]` | `00_ESTADO_Y_METODOLOGIA.md` |
| SVCs `0x9e` y `0x76` en un SysModule ARM11 | `[VERIFICADO EN ESTE REPO]` | §8 + `binarios_descifrados/…` |
| 60 funciones detectadas en SysModule ARM11 | `[VERIFICADO EN ESTE REPO]` | §8 + `r2_functions_clean.txt` |
| Exheader `pdn\0` + syscall bitmap | `[VERIFICADO EN ESTE REPO]` | §8 + `exheader.bin` |
| Existencia de ARM11 + ARM9 separados | `[CONOCIMIENTO PÚBLICO 3DS]` | Re-leer de `arm9.bin`/`arm11.bin` descifrados |
| PXI como canal ARM11↔ARM9 | `[CONOCIMIENTO PÚBLICO 3DS]` | `arm11.bin` + traces PXI |
| Mapa de memoria (FCRAM/AXI WRAM) | `[CONOCIMIENTO PÚBLICO 3DS]` | Binarios descifrados + MMU |
| Números de SVC y privilegios (kernel11) | `[POR VERIFICAR]` | `arm11.bin` (SVC handler) — requiere `movable.sed` |
| PMU/CP15 y governors | `[HIPÓTESIS]` | `arm11.bin` + TRM ARM11 MPCore — requiere `movable.sed` |
