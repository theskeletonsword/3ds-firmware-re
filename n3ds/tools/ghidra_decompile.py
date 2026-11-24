#!/usr/bin/env python3
"""Headless-Ghidra bulk decompilation of one binary (resumable).

usage: ghidra_decompile.py <binary_dir> [--lang ARM:LE:32:v6] [--base 0x100000] [--names names.tsv] [--out <dir>]
  <binary_dir> must contain code.bin (+ exheader.bin for the load address) ; output: <binary_dir>/decompiled/<addr>.c + index.tsv
  Kernel/FIRM images: pass --bin explicitly (e.g. --bin kernel_native/arm9.bin --base 0x08006800 --lang ARM:LE:32:v5t).
names.tsv is generated automatically from symbols/N3DS_SYMBOL_TABLE.csv or symbols/titles/TITLES_SYMBOL_TABLE.csv when not given.
Re-running skips functions already written. Needs ~1-2 GB heap per run; run several binaries in parallel with xargs -P.
"""
import argparse, csv, glob, os, re, shutil, subprocess, sys, tempfile
R = os.path.abspath(os.path.dirname(__file__) + '/../..')
GH = '/opt/ghidra_12.2_PUBLIC/support/analyzeHeadless'
FUNC_KINDS = {'ipc_command_handler', 'ipc_client_call', 'ipc_dispatcher', 'svc_wrapper', 'rtti_vptr_init', 'rtti_vslot', 'source_file_reference', 'string_reference', 'library_match'}
DATA_KINDS = {'service_name_string', 'pointer_table', 'rtti_typeinfo', 'rtti_vtable', 'source_path_string'}

def _add(entries, ea_s, nm, prio, kind='func'):
    if not ea_s or not nm: return
    try: v = int(ea_s, 16)
    except ValueError: return
    if v == 0: return
    nm = re.sub(r'[^A-Za-z0-9_]', '_', nm.strip())
    if not nm: return
    prev = entries.get(v)
    if prev is None or prio >= prev[0]:
        entries[v] = (prio, f'0x{v:08x}', nm, kind)

def _load_analysis(entries, d):
    specs = [
        ('library_matches.csv', 1), ('string_refs.csv', 1),
        ('derived.csv', 2), ('sources.csv', 5), ('rtti.csv', 5),
    ]
    for fn, prio in specs:
        p = f'{d}/analysis/{fn}'
        if not os.path.exists(p): continue
        with open(p, encoding='utf-8', errors='replace') as f:
            for r in csv.DictReader(f):
                k = r.get('kind', '')
                ea = r.get('ea') or r.get('ea_n3ds') or ''
                if k in FUNC_KINDS: _add(entries, ea, r['symbol_name'], prio, 'func')
                elif k in DATA_KINDS: _add(entries, ea, r['symbol_name'], prio, 'data')

def names_for(d):
    base = os.path.basename(d.rstrip('/')); m = re.search(r'([0-9A-F]{16})$', base); tid = m.group(1) if m else None
    model = 'n3ds' if '/n3ds/' in d + '/' else ('o3ds' if '/o3ds/' in d + '/' else '')
    entries = {}
    _load_analysis(entries, d)
    if '/decrypted_titles/' in d + '/' and model in ('n3ds', 'o3ds'):
        tab = f'{R}/n3ds/symbols/titles/TITLES_SYMBOL_TABLE.csv' if model == 'n3ds' else f'{R}/o3ds/symbols_titles/TITLES_SYMBOL_TABLE.csv'
        if tid and os.path.exists(tab):
            with open(tab, encoding='utf-8', errors='replace') as f:
                for r in csv.DictReader(f):
                    if r['title_id'] != tid: continue
                    k = r['kind']
                    prio = 5 if k in ('rtti_vptr_init', 'rtti_vslot', 'rtti_typeinfo', 'rtti_vtable', 'source_file_reference', 'source_path_string') else 2 if k in ('ipc_command_handler', 'ipc_client_call', 'ipc_dispatcher', 'svc_wrapper', 'service_name_string', 'pointer_table') else 1
                    if k in FUNC_KINDS: _add(entries, r['ea'], r['symbol_name'], prio, 'func')
                    elif k in DATA_KINDS: _add(entries, r['ea'], r['symbol_name'], prio, 'data')
    if model:
        dd = f'{R}/n3ds/symbols/derived_decomp/{model}__{base}.csv'
        if os.path.exists(dd):
            with open(dd, encoding='utf-8', errors='replace') as f:
                for r in csv.DictReader(f): _add(entries, r['ea'], r['symbol_name'], 4, 'func')
    if model == 'n3ds':
        is_title = '/decrypted_titles/' in d + '/'
        is_firm = '/firm_modules/' in d + '/'
        with open(f'{R}/n3ds/symbols/N3DS_SYMBOL_TABLE.csv', encoding='utf-8', errors='replace') as f:
            for r in csv.DictReader(f):
                if not r['ea_n3ds'] or r['confidence_level'] == 'unresolved': continue
                comp = r['component']
                if is_title: match = (comp == base)
                elif is_firm: match = (comp == base or comp.startswith(f'FIRM module {base} ') or (base == 'loader' and comp == 'FIRM module ldr (derived)'))
                elif tid: match = (tid in comp)
                else: match = False
                if not match: continue
                lvl = r['confidence_level']
                prio = 7 if lvl == 'manual_decompiled' else 4 if lvl == 'derived_decompiled' else 3 if lvl == 'derived_structural' else 6
                kind = 'data' if (r['role_service'].endswith(('service_name_string', 'pointer_table')) or '_ro_str_' in r['symbol_name']) else 'func'
                _add(entries, r['ea_n3ds'], r['symbol_name'], prio, kind)
    elif model == 'o3ds' and '/decrypted_binaries/' in d + '/':
        for sy in sorted(glob.glob(d + '/*_friendly.sym')):
            with open(sy, encoding='utf-8', errors='replace') as f:
                for l in f:
                    mm = re.match(r'^(0x[0-9A-Fa-f]+)\s+0x[0-9A-Fa-f]+\s+\w+\s+(\S+)', l)
                    if mm:
                        kind = 'data' if '_ro_str_' in mm.group(2) else 'func'
                        _add(entries, mm.group(1), mm.group(2), 6, kind)
    mf = f'{R}/n3ds/symbols/manual/{base}.csv'
    if os.path.exists(mf):
        with open(mf, encoding='utf-8', errors='replace') as f:
            for r in csv.DictReader(f):
                if r.get('binary', base) == base:
                    _add(entries, r['ea'], r['symbol_name'], 7, 'func')
    return [(ea, nm, kind) for _, ea, nm, kind in sorted(entries.values(), key=lambda x: int(x[1], 16))]

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('dir'); ap.add_argument('--bin'); ap.add_argument('--lang', default='ARM:LE:32:v6'); ap.add_argument('--base')
    ap.add_argument('--names'); ap.add_argument('--out'); ap.add_argument('--heap', default='3G'); ap.add_argument('--fresh', action='store_true', help='discard previous output first')
    a = ap.parse_args()
    d = os.path.abspath(a.dir.rstrip('/')); binp = a.bin or d + '/code.bin'
    out = a.out or d + '/decompiled'
    saved_names = None
    if a.fresh and os.path.isdir(out):
        if a.bin and not a.names and os.path.exists(out + '/names.tsv'):
            saved_names = open(out + '/names.tsv', 'rb').read()
        shutil.rmtree(out)
    os.makedirs(out, exist_ok=True)
    if saved_names is not None:
        open(out + '/names.tsv', 'wb').write(saved_names)
    base = a.base
    if not base:
        t = subprocess.run(['ctrtool', '-t', 'exheader', d + '/exheader.bin'], capture_output=True, text=True).stdout
        mm = re.search(r'Code text address:\s+(0x\w+)', t); base = mm.group(1) if mm else '0x100000'
    names = a.names
    if not names and os.path.exists(out + '/names.tsv') and a.bin: names = out + '/names.tsv'   # kernel jobs ship their own names
    if not names:
        names = out + '/names.tsv'
        with open(names, 'w') as f:
            for ea, nm, kind in names_for(d): f.write(f'{ea}\t{nm}\t{kind}\n')
    proj = tempfile.mkdtemp(prefix='ghproj_')
    try:
        cmd = [GH, proj, 'p', '-import', binp, '-processor', a.lang, '-loader', 'BinaryLoader', '-loader-baseAddr', base,
               '-scriptPath', R + '/n3ds/tools/ghidra', '-postScript', 'DecompileAll.java', out, names, '-deleteProject']
        env = dict(os.environ, GHIDRA_MAXMEM=a.heap)
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=6 * 3600)
        open(out + '/ghidra.log', 'w').write(r.stdout[-20000:] + '\n--- stderr ---\n' + r.stderr[-5000:])
        last = [l for l in r.stdout.splitlines() if 'decompiled=' in l or 'named functions' in l]
        print(os.path.basename(d), last[-2:] if last else 'NO RESULT (see ghidra.log)')
    finally:
        shutil.rmtree(proj, ignore_errors=True)
