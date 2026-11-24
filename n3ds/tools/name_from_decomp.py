#!/usr/bin/env python3
"""Name functions straight from the decompiled C (bulk Ghidra output) when the C itself proves the role:

  * svc wrappers          body is only `software_interrupt(0xNN)` (+ result store)           -> <bin>_svc_0xNN_<SvcName>_<addr>
  * TLS accessor          body only reads the TLS pointer (coproc_movefrom_User_R_Thread_and_Process_ID)  -> <bin>_get_tls_<addr>
  * server loops          calls a ReplyAndReceive wrapper (svc 0x4F/0x4B..0x4E) inside a loop together with a switch on cmdbuf[0] >> 16 -> <bin>_ipc_server_loop_<addr>
Writes symbols/derived_decomp/<binary dir name>.csv (merged by build_master_table.py as level derived_decompiled).
usage: name_from_decomp.py        (all binaries that have a decompiled/ folder, both models)
"""
import csv, glob, os, re, sys
R = os.path.abspath(os.path.dirname(__file__) + '/../..')
sys.path.insert(0, R + '/n3ds/tools')
import derive_ipc
SVCN = derive_ipc.SVCN
os.makedirs(R + '/n3ds/symbols/derived_decomp', exist_ok=True)
claimed = set()
with open(R + '/n3ds/symbols/N3DS_SYMBOL_TABLE.csv', encoding='utf-8', errors='replace') as f:
    for r in csv.DictReader(f):
        if r['ea_n3ds'] and r['confidence_level'] not in ('unresolved', 'derived_decompiled'):
            ea_i = int(r['ea_n3ds'], 16)
            m = re.search(r'([0-9A-F]{16})$', r['component'])
            key = m.group(1) if m else r['component'].split()[2] if r['component'].startswith('FIRM module ') else r['component']
            claimed.add(('n3ds', key, ea_i))
            if r['component'].startswith('FIRM module '):
                mod = r['component'].split()[2]
                claimed.add(('n3ds', 'loader' if mod == 'ldr' else mod, ea_i))
for model in ('n3ds', 'o3ds'):
    for p in glob.glob(f'{R}/{model}/decrypted_binaries/*/analysis/derived.csv') + glob.glob(f'{R}/{model}/decrypted_binaries/firm_modules/*/analysis/derived.csv') + glob.glob(f'{R}/{model}/decrypted_titles/*/analysis/derived.csv'):
        bn = os.path.basename(os.path.dirname(os.path.dirname(p)))
        m = re.search(r'([0-9A-F]{16})$', bn); key = m.group(1) if m else bn
        with open(p, encoding='utf-8', errors='replace') as f:
            for r in csv.DictReader(f):
                ea = r.get('ea') or r.get('ea_n3ds')
                if ea: claimed.add((model, key, int(ea, 16)))
    if model == 'o3ds':
        for sy in glob.glob(f'{R}/o3ds/decrypted_binaries/*/*_friendly.sym') + glob.glob(f'{R}/o3ds/decrypted_binaries/firm_modules/*/*_friendly.sym'):
            bn = os.path.basename(os.path.dirname(sy))
            m = re.search(r'([0-9A-F]{16})$', bn); key = m.group(1) if m else bn
            for l in open(sy, encoding='utf-8', errors='replace'):
                mm = re.match(r'^(0x[0-9A-Fa-f]+)\s+', l)
                if mm: claimed.add(('o3ds', key, int(mm.group(1), 16)))
tot = 0
for model in ('n3ds', 'o3ds'):
    for cdir in sorted(glob.glob(f'{R}/{model}/decrypted_binaries/*/decompiled') + glob.glob(f'{R}/{model}/decrypted_titles/*/decompiled') + glob.glob(f'{R}/{model}/decrypted_binaries/firm_modules/*/decompiled')):
        bdir = os.path.dirname(cdir); bn = os.path.basename(bdir)
        mt = re.search(r'([0-9A-F]{16})$', bn); key = mt.group(1) if mt else bn
        pre = re.sub(r'[^A-Za-z0-9]', '', bn.split('-')[1] if bn.startswith('Module-') else bn.split('-')[0]).lower()[:12] or 'bin'
        self_pat = re.compile(rf'^{re.escape(pre)}_(?:svc_0x[0-9A-F]{{2}}_\w+|get_tls|ipc_server_loop)_[0-9a-f]+$')
        files = {}
        for cf in glob.glob(cdir + '/*.c'):
            t = open(cf, errors='replace').read()
            m = re.match(r'// (\S+) @ (0x[0-9a-f]+)\s+size (\d+)', t)
            if m: files[int(m.group(2), 16)] = (m.group(1), int(m.group(3)), t)
        svcw = {}; rows = []
        for ea, (nm, size, t) in sorted(files.items()):
            own = (model, key, ea) not in claimed and (model, bn, ea) not in claimed
            elig = nm.startswith(('FUN_', 'func_', 'thunk_FUN')) or (bool(self_pat.match(nm)) and own)
            body = t.split('\n', 1)[1]
            sw = re.findall(r'software_interrupt\((0x[0-9a-fA-F]+|\d+)\)', body)
            lines = [l for l in body.split('\n') if l.strip() and not l.strip().startswith(('/*', '//', '*'))]
            if len(sw) == 1 and size <= 0x40 and len(lines) <= 12:
                n = int(sw[0], 0)
                if n in SVCN:
                    svcw[ea] = n
                    if elig:
                        rows.append([f'0x{ea:08X}', hex(size), f'{pre}_svc_0x{n:02X}_{SVCN[n]}_{ea:x}', 'svc_wrapper_decomp', f'decompiled body is a single software_interrupt(0x{n:02X}) ({SVCN[n]}); {len(lines)} C lines'])
            elif re.search(r'coproc_movefrom_User_R_Thread_and_Process_ID\(\)', body) and size <= 0x10 and len(lines) <= 6 and elig:
                rows.append([f'0x{ea:08X}', hex(size), f'{pre}_get_tls_{ea:x}', 'tls_accessor_decomp', 'decompiled body only reads the TLS pointer (mrc p15,0,Rd,c13,c0,3)'])
        rsv = {a for a, n in svcw.items() if n in (0x4F, 0x4B, 0x4C, 0x4D, 0x4E)}
        rsv_pat = re.compile(r'\b(' + '|'.join(re.escape(files[a][0]) for a in sorted(rsv)) + r')\s*\(') if rsv else None
        for ea, (nm, size, t) in sorted(files.items()):
            own = (model, key, ea) not in claimed and (model, bn, ea) not in claimed
            elig = nm.startswith('FUN_') or (bool(self_pat.match(nm)) and own)
            if not elig or size < 0x80 or not rsv_pat: continue
            if '>> 0x10' in t and 'coproc_movefrom_User_R_Thread_and_Process_ID' in t: continue
            hits = sorted(f'0x{a:x}' for a in rsv if re.search(r'\b' + re.escape(files[a][0]) + r'\s*\(', t))
            if hits and re.search(r'\b(while|do)\b', t) and size < 0x800:
                rows.append([f'0x{ea:08X}', hex(size), f'{pre}_ipc_server_loop_{ea:x}', 'ipc_server_loop_decomp', 'loop that calls the ReplyAndReceive SVC wrapper ' + ', '.join(hits)])
        with open(f'{R}/n3ds/symbols/derived_decomp/{model}__{bn}.csv', 'w', newline='') as f:
            w = csv.writer(f); w.writerow(['ea', 'size', 'symbol_name', 'kind', 'technical_evidence']); w.writerows(rows)
        tot += len(rows)
print('rows', tot)
