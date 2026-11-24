# 00. Estado del repositorio y metodología de análisis (3DS FIRM/ARM)

> **Propósito:** registrar qué se encontró, qué se pudo verificar realmente en los binarios presentes, qué está cifrado (por tanto no analysable sin claves de consola) y los comandos concretos para reproducir el análisis una vez dispongamos de binarios **descifrados** (`arm9.bin`, `arm11.bin`, `code.decompressed.bin`, `exheader.bin`).

---

## 1. Inventario de lo presente en el repositorio

| Ruta | Tamaño | Tipo detectado | Estado | Notas |
|------|--------|----------------|--------|-------|
| `extraidos/FIRM_0004013800000202/raw/content.0000.0000000b` | 891 904 b | alta entropía (no código ARM) | **CIFRADO** | Título FIRM (arm11/arm9 envuelto). `file` lo etiqueta erróneamente como CXI; cabecera no es NCCH. |
| `extraidos/FIRM_0004013800000102/raw/content.0000.00000018` | 1 711 104 b | alta entropía | **CIFRADO** | Título FIRM. |
| `extraidos/FIRM_0004013800000002/raw/content.0000.0000006c` | 969 728 b | alta entropía | **CIFRADO** | Título FIRM. |
| `extraidos/FIRM_0004013800000003/raw/content.0000.00000001` | 846 848 b | alta entropía | **CIFRADO** | Título FIRM. |
| `extraidos/SysModule_000401300000XXXXXX/raw/content.0000.000000NN` | varios | `NCCH` / CXI (contenedor) | **CONTENEDOR CIBI; código interno cifrado** | Cabecera `NCCH` visible en offset `0x100`, pero las secciones (code.bin) muestran alta entropía y **cero opcodes ARM** (ver sección 3). |

Titulares de SysModules identificados (ejemplo): `0710pseg-ciuser`, `0812builder`, `0215builder`, `1105builder`, etc. Son módulos de sistema del lado ARM11 (servicios, filesystem, PM, etc.).

> **Ninguno** de los archivos solicitados por el usuario existe como tal suelto: **no hay `arm9.bin`, `arm11.bin`, `code.decompressed.bin` ni `exheader.bin`** como archivos independientes. Deben extraerse/descifrarse de los títulos FIRM y de los exefs de los CXI.

---

## 2. Hallazgo verificado: cifrado de consola (VERIFICADO EN ESTE REPO)

Se inspeccionaron los primeros bytes de cada `content.*` y se buscaron firmas de instrucciones ARM (`e3a0` `mov`, `ea00` `b`, `e59f` `ldr literal`, `e28f` `add`, `e12f` `bx`).

**Resultado:** alta entropía en todos los offsets probados (`0x0`, `0x200`, `0x4000`, `0x8000`, `0x10000`) y **0 coincidencias de patrones de opcode ARM** en cualquiera de los FIRM. En un SysModule de 11 264 B se lee la magia `NCCH` (`4e434348`) en `0x100`, confirmando contenedor CXI, pero su payload no contiene código ARM descifrado.

**Conclusión:** los binarios están cifrados con claves derivadas del hardware de consola (KeyX/KeyY derivadas de `movable.sed` + OTP / console-unique ID). **Sin esas claves no es posible desensamblar, recuperar símbolos ni verificar direcciones en estos archivos específicos.**

### Qué se necesita para continuar
- `movable.sed` (y/o `otp.bin`) de la consola origen.
- Herramientas de descifrado 3DS (por ejemplo `ctrtool`, `makerom`, scripts de `3dbrew`/`LibreTS`).
- Una vez descifrados: `arm9.bin` (ARM9 kernel/firm9), `arm11.bin` (ARM11 kernel), `code.decompressed.bin` (código descomprimido de exefs) y `exheader.bin` (metadatos de control de acceso y capacidades del proceso).

---

## 3. Comandos de reproducción (objdump / radare2 / Ghidra / REA)

> Estos comandos están listos para ejecutar **contra binarios descifrados**. Marcados con `[PENDIENTE: binario descifrado]` donde aplique.

### 3.1 objdump (desensamblado ARM)

```bash
# ARM11 (ARMv6K, little-endian, ARM mode)
objdump -D -m arm -M force-thumb --no-show-raw-insn \
  --adjust-vma=0x08000000 \
  arm11.bin > arm11.disasm.txt

# ARM9 (ARMv5TE)
objdump -D -m armv5te --no-show-raw-insn \
  arm9.bin > arm9.disasm.txt

# Buscar vectores de excepción y SVC en el disassembly
grep -nE "\svc\b|\svcpl\b|\svcmi\b" arm11.disasm.txt | head -50
grep -nE "\bldr\b.*pc,|\bb\b.*#0x" arm9.disasm.txt | head -30

# Dump de una región de datos (exheader / header)
objdump -s -j .rodata -j .data exheader.bin
```

### 3.2 radare2 (r2)

```bash
# Abrir en modo ARM, analizar todo
r2 -a arm -b 32 -A arm11.bin

# Dentro de r2:
aaa              # análisis completo
afl              # listar funciones detectadas
pd 200 @ entry0  # desensamblar 200 instrucciones en el punto de entrada
px @ 0x08000000  # hexdump en dirección de carga
/ce svc          # buscar instrucciones SVC
/ce 0xe12fff1e   # buscar bx lr (epílogo típico)
s 0x08000000     # desplazar a base de carga
afr              # renombrar función (manual, solo nombres verificados)
```

Guion r2 para exportar símbolos a CSV (solo nombres que se confirmen con referencias cruzadas):

```r2
#!/usr/bin/env r2 -i
aagf
aflj~{...}   # (ver plantilla en SIMBOLOS_RECREADOS.md)
```

### 3.3 Ghidra (GUI y headless)

Proyecto nuevo → Importar `arm11.bin` / `arm9.bin`:
- **Language:** `ARM:LE:32:v6k` (ARM11 MPCore) / `ARM:LE:32:v5te` (ARM946E-S)
- **Compiler:** `gcc`
- **Image base:** `0x08000000` (ajustar según el header/FIRM)

Headless (analizar + exportar símbolos):

```bash
/opt/ghidra_12.1.4_PUBLIC/ghidraRun \
  -import arm11.bin \
  -postscript "ExportSymbols.java" arm11_symbols.csv
```

Script Ghidra (Java) mínimo para exportar función + dirección solo si hay cross-reference confirmado:

```java
// ExportSymbols.java - esqueleto; rellenar solo con direcciones verificadas
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportSymbols extends GhidraScript {
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            System.out.println(entry + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses());
        }
    }
}
```

### 3.4 REA (reverse engineering agent)

```bash
# Capacidades del proveedor
rea capabilities

# Análisis general de un artefacto (sobre binario descifrado)
rea analyze --path arm11.bin

# Mapear una dirección de análisis a offset de archivo (útil para cruzar r2 ↔ Ghidra)
rea address-to-file-offset --path arm11.bin --address 0x08001234
```

> REA no es un desensamblador de firmware embebido por defecto; úsalo para auditoría de exposición y reconstrucción de obligaciones de evidencia, no para reemplazar objdump/r2/Ghidra en el análisis de instrucciones ARM.

---

## 4. Reglas de evidencia adoptadas en este análisis

| Etiqueta | Significado |
|----------|-------------|
| `[VERIFICADO EN ESTE REPO]` | Comprobado directamente sobre los archivos presentes (cifrado, contenedores NCCH/CXI, tamaños, TitleIDs). |
| `[CONOCIMIENTO PÚBLICO 3DS]` | Documentado en 3dbrew / GBATEK / reversing público de 3DS. **No re-verificado en estos blobs cifrados.** Debe confirmarse contra `arm9.bin`/`arm11.bin` descifrados. |
| `[HIPÓTESIS / POR COMPROBAR]` | Inferencia que requiere validación en hardware real o binarios descifrados. No darla por hecha. |

**Todo lo que sigue (arquitectura ARM11 vs ARM9, tabla de símbolos, guía de drivers, README) separa estas tres categorías explícitamente.**
