#!/usr/bin/env python3
"""Translate the Spanish free-text *Notes* column of the O3DS *_friendly.sym tables to English.
Source of truth for the Spanish originals: docs_es_backup/sym_notes_es/ (never modified).
Pass 1: regular templates (regex).  Pass 2: exact-string table in sym_notes_translation.tsv (hand translated).
Symbol names / addresses / confidence columns are not touched.   usage: translate_sym_notes.py [--report]"""
import glob, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
line = re.compile(r'^(0x[0-9A-Fa-f]+\s+0x[0-9A-Fa-f]+\s+\w+\s+\S+\s*)(.*)$')
T = [  # (regex, replacement)  -- order matters
 (r'^Llama \((C\+BFS|hop \d+)\) a ', r'Calls (\1) '),
 (r'^Llamado \((C\+BFS|hop \d+)\) desde ', r'Called (\1) from '),
 (r'^Implementación llamada por ', 'Implementation called by '),
 (r'^Método virtual vtable (\w+) #(\d+) slot (\d+)', r'Virtual method of \1 vtable #\2, slot \3'),
 (r'^Tabla SVC ', 'SVC table '), (r'^Tabla SWI ', 'SWI table '),
 (r'^Función hoja Thumb \((\d+)B hasta retorno\)', r'Thumb leaf function (\1 B up to return)'),
 (r'^Función hoja ARM \((\d+)B hasta retorno\)', r'ARM leaf function (\1 B up to return)'),
 (r'^Epílogo/hoja ARM \((\d+)B\)', r'ARM epilogue/leaf (\1 B)'),
 (r'^Slot (\d+) de ', r'Slot \1 of '),
 (r'^Ejecuta swi ', 'Executes swi '),
 (r'^ASM (Thumb|ARM) \(gap no decompilado\)', lambda m: f'{m.group(1)} ASM (undecompiled gap)'),
 (r'^C: inicializador/setter de campos', 'C: field initializer/setter'),
 (r'^C: rutina analizada en Ghidra', 'C: routine analysed in Ghidra'),
 (r'^C: rutina standalone analizada en Ghidra', 'C: standalone routine analysed in Ghidra'),
 (r'^C: gestor directorios/cache/IPC-async', 'C: directory/cache/async-IPC manager'),
 (r'^C: gestor archivos/montaje/rutas', 'C: file/mount/path manager'),
 (r'^C: helper dominio (\w+) desde ', r'C: \1-domain helper reached from '),
 (r'^C: método virtual vtable ', 'C: virtual method of vtable '),
 (r'^C: sección crítica/atómica ldrex/strex', 'C: critical section / atomics ldrex/strex'),
 (r'^C: accede registro MMIO ', 'C: accesses MMIO register '),
 (r'^C: planificación KThread/KScheduler', 'C: KThread/KScheduler scheduling'),
 (r'^C: gestión MMU/memoria', 'C: MMU/memory management'),
 (r'^C: invoca PxiFS ', 'C: invokes PxiFS '),
 (r'^C\+SWI (0x[0-9A-Fa-f]+): envia IPC cmd ', r'C+SWI \1: sends IPC cmd '),
 (r'^Sub-bloque dentro de ', 'Sub-block inside '),
 (r'^Retorna Result kernel', 'Returns kernel Result'),
 (r'^Accede global ', 'Accesses global '),
 (r'^C: metodo virtual tabla (\S+) ', r'C: virtual method of table \1 '),
 (r'^C: constructor/asignacion vtable ', 'C: constructor / vtable assignment '),
 (r'^C: helper dominio (\w+) (?!desde)', r'C: \1-domain helper '),
 (r'^C: bucle ReplyAndReceive para (\S+) \(despacha a ', r'C: ReplyAndReceive loop for \1 (dispatches to '),
 (r'^C: bucle/dispatcher IPC para (\S+) \((\d+) casos? inline\)', r'C: IPC loop/dispatcher for \1 (\2 inline case(s))'),
 (r'^C: bucle ReplyAndReceive generico por sesion I2C \(despacha a ', 'C: generic per-session ReplyAndReceive loop for I2C (dispatches to '),
 (r'^ASM Thumb: rutina static-buf/on-connect (\S+) \(tabla ', r'ASM Thumb: static-buffer / on-connect routine of \1 (table '),
 (r'^ASM Thumb: dispatcher IPC (\S+) \(tabla (\S+); (\d+) cmds( activos)? (\S+)', r'ASM Thumb: IPC dispatcher of \1 (table \2; \3 cmds\4 \5'),
 (r' activos', ' active'), (r'multijugador local', 'local multiplayer'), (r'WiFi infraestructura', 'infrastructure WiFi'), (r'pruebas RF/diagnostico', 'RF tests/diagnostics'),
 (r'^C: ejecuta tabla \.(\w+) de constructores C\+\+', r'C: runs the .\1 table of C++ constructors'),
 (r'^C: recorre tabla \.(\w+) PC-relativa de constructores C\+\+', r'C: walks the PC-relative .\1 table of C++ constructors'),
 (r'^C: recorre tabla \.(\w+) constructores C\+\+', r'C: walks the .\1 table of C++ constructors'),
 (r'^C: ejecuta \.(\w+) constructores C\+\+', r'C: runs .\1 C++ constructors'),
 (r'^C: bucle limpiado a cero de seccion \.bss', 'C: .bss zero-fill loop'),
 (r'^C: limpiado a cero de seccion \.bss', 'C: .bss zero-fill'),
 (r'^\.rodata: tabla ', '.rodata: table of '), (r'^\.data: ', '.data: '),
 (r'^Wrapper/stub directo ', 'Direct wrapper/stub for '),
 (r'^Slot (\d+) vtable Process9 #(\d+) \(([^,]+), subsistema (\w+)\)', r'Slot \1 of Process9 vtable #\2 (\3, \4 subsystem)'),
 (r'^ASM ARM32: hilo servidor sesion (\S+) ', r'ASM ARM32: session server thread of \1 '),
 (r'^C: dispatcher IPC principal (\S+) \((\d+) casos ', r'C: main IPC dispatcher of \1 (\2 cases '),
 (r'^C: dispatcher IPC (\S+) \((\d+) casos ', r'C: IPC dispatcher of \1 (\2 cases '),
 (r"^C: dispatcher IPC '(\S+)' cmds ", r"C: IPC dispatcher of '\1' cmds "),
 (r"^ASM r2: dispatcher IPC '(\S+)' ARM jump table (\S+) \((\d+) casos ", r"ASM r2: IPC dispatcher of '\1', ARM jump table \2 (\3 cases "),
 (r'^ASM Thumb: dispatcher IPC (\S+) ', r'ASM Thumb: IPC dispatcher of \1 '),
 (r'^ASM r2: \.(\w+) ctor ', r'ASM r2: .\1 constructor of '),
 (r'^C\+SWI (\S+): cliente IPC (\S+) cmd ', r'C+SWI \1: IPC client of \2 cmd '),
 (r'^C\+SWI (\S+): cliente IPC hacia ', r'C+SWI \1: IPC client towards '),
 (r'^\.data: punteros nombres ', '.data: name pointers, '), (r'^\.data: punteros ', '.data: pointers, '),
 (r'^\.rodata: table of (registro|dispositivos|punteros) ', lambda m: '.rodata: ' + {'registro':'registration table ','dispositivos':'device table ','punteros':'pointer table '}[m.group(1)]),
 (r' casos active ', ' active cases '), (r' casos ', ' cases '), (r'\bcmds active\b', 'active cmds'),
 (r'^C verificado: ', 'C verified: '), (r'^C \+ ldrex verificado: ', 'C + ldrex verified: '), (r'^MMIO GIC \+ C verificado: ', 'MMIO GIC + C verified: '),
 (r', llama \[', ', calls ['), (r'\(llama \[', '(calls ['),
]
TOK = re.compile(r"0x[0-9A-Fa-f]+|\b\d+L\b|\b\d+\b|\[[^\]]*\]|\b\w+_\w+\b")
def skeleton(n):
    vals = []
    def f(m): vals.append(m.group(0)); return '{%d}' % (len(vals) - 1)
    i = n.find('FUN_'); cut = max(n.rfind('(', 0, i), 0) if i >= 0 else len(n)
    return TOK.sub(f, n[:cut]) + (' \u27e8sig\u27e9' if i >= 0 else ''), vals, n[cut:] if i >= 0 else ''
def expand(tpl, vals, tail):
    res = re.sub(r'\{(\d+)\}', lambda m: vals[int(m.group(1))], tpl)
    return res + (' ' + tail if tail else '')
def translate(note, table):
    sk, vals, tail = skeleton(note)
    if sk in table: return expand(table[sk], vals, tail)          # exact Spanish skeleton known
    out = note
    for pat, rep in T: out = re.sub(pat, rep, out)
    sk, vals, tail = skeleton(out)
    if sk in table: return expand(table[sk], vals, tail)          # skeleton after the regex templates
    return out
def strip_sig(n):
    i = n.find('FUN_')
    return n if i < 0 else n[:max(n.rfind('(', 0, i), 0)]
SPAN = re.compile(r"[áéíóúñÁÉÍÓÚ¿]|\b(de|del|la|el|los|las|para|con|por|que|se|un|una|es|su|al|desde|hasta|sobre|sin|entre|y|o|llama|llamado|tabla|rutina|gestor|método|función|campos|inicializa|escribe|lee|crea|valida|busca|devuelve|retorna|accede|ejecuta|envía|envia|registra|hoja|dominio)\b", re.I)
if __name__ == '__main__':
    table = {}
    p = os.path.join(HERE, 'sym_notes_translation.tsv')
    if os.path.exists(p):
        for l in open(p, encoding='utf-8'):
            l = l.rstrip('\n')
            if '\t' in l and not l.startswith('#'): a, b = l.split('\t', 1); table[a] = b
    resid = {}
    for bk in sorted(glob.glob(HERE + '/docs_es_backup/sym_notes_es/*')):
        dst = HERE + '/decrypted_binaries/' + os.path.basename(bk).replace('__', '/')
        out = []
        for l in open(bk, encoding='utf-8', errors='surrogateescape').read().split('\n'):
            m = line.match(l)
            if m:
                n = translate(m.group(2), table)
                if SPAN.search(strip_sig(n)): resid[n] = resid.get(n, 0) + 1
                l = m.group(1) + n
            out.append(l)
        open(dst, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
    print('residual Spanish-looking distinct notes:', len(resid), 'lines:', sum(resid.values()))
    if '--report' in sys.argv:
        for k, v in sorted(resid.items(), key=lambda x: -x[1]): print(f'{v}\t{k}')
