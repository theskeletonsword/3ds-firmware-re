#!/usr/bin/env python3
"""Print the job list (one shell command per binary) for tools/decompile_all.sh and pre-write names.tsv for kernel images.
Everything that is decompiled: N3DS sysmodules / FIRM modules / titles / kernels, plus the O3DS binaries that are NOT byte-identical to an N3DS one."""
import csv, glob, hashlib, os, re, sys
R = os.path.abspath(os.path.dirname(__file__) + '/../..')
FRESH = '--fresh' in sys.argv[1:]
sha = lambda p: hashlib.sha1(open(p, 'rb').read()).hexdigest()
def tid(p):
    m = re.search(r'([0-9A-F]{16})$', os.path.basename(p)); return m.group(1) if m else None
jobs = []
def add(d, extra=''):
    if FRESH: extra = (extra + ' --fresh').strip()
    jobs.append(f'python3 {R}/n3ds/tools/ghidra_decompile.py {d} {extra}'.rstrip())
n3 = {}
for kind in ('decrypted_binaries/Module-*', 'decrypted_binaries/firm_modules/*', 'decrypted_titles/*'):
    for d in sorted(glob.glob(f'{R}/n3ds/{kind}')):
        if os.path.exists(d + '/code.bin'): n3[(kind.split('/')[0], os.path.basename(d) if 'firm_modules' in kind else tid(d))] = sha(d + '/code.bin'); add(d)
for kind in ('decrypted_binaries/Module-*', 'decrypted_binaries/firm_modules/*', 'decrypted_titles/*'):
    for d in sorted(glob.glob(f'{R}/o3ds/{kind}')):
        if not os.path.exists(d + '/code.bin'): continue
        k = (kind.split('/')[0], os.path.basename(d) if 'firm_modules' in kind else tid(d))
        if n3.get(k) == sha(d + '/code.bin'): continue          # identical image already decompiled on the N3DS side
        add(d)
# kernels: names from the master CSV + manual CSVs (N3DS) / O3DS .sym
def kernel_job(model, kdir, binname, lang, base, comp_prefix=None, manual_comp=None, manual_csv=None, symfile=None, alias=None, addr_min=None, addr_max=None):
    d = f'{R}/{model}/{kdir}'; out = d + f'/decompiled_{binname.replace(".bin", "")}'
    os.makedirs(out, exist_ok=True); entries = {}
    def put(ea_s, nm, prio, kind='func'):
        try: v = int(ea_s, 16)
        except ValueError: return
        if alias and 0x1FF80000 <= v < 0x20000000: v = v - 0x1FF80000 + alias        # boot code of arm11_section1.bin maps at file offset in the alias image
        if addr_min is not None and v < addr_min: return
        if addr_max is not None and v >= addr_max: return
        nm = re.sub(r'[^A-Za-z0-9_]', '_', nm.strip())
        if not nm: return
        prev = entries.get(v)
        if prev is None or prio >= prev[0]: entries[v] = (prio, nm, kind)
    if comp_prefix or manual_comp:
        with open(f'{R}/n3ds/symbols/N3DS_SYMBOL_TABLE.csv', encoding='utf-8', errors='replace') as f:
            for r in csv.DictReader(f):
                if not r['ea_n3ds'] or r['confidence_level'] == 'unresolved': continue
                if comp_prefix and r['component'].startswith(comp_prefix):
                    prio = 7 if r['confidence_level'] == 'manual_decompiled' else 6
                    kind = 'data' if (r['role_service'].endswith(('service_name_string', 'pointer_table')) or '_ro_str_' in r['symbol_name']) else 'func'
                    put(r['ea_n3ds'], r['symbol_name'], prio, kind)
                elif manual_comp and r['component'] == manual_comp:
                    put(r['ea_n3ds'], r['symbol_name'], 7, 'func')
    if manual_csv and os.path.exists(f'{R}/n3ds/symbols/manual/{manual_csv}'):
        with open(f'{R}/n3ds/symbols/manual/{manual_csv}', encoding='utf-8', errors='replace') as f:
            for r in csv.DictReader(f): put(r['ea'], r['symbol_name'], 7, 'func')
    if symfile:
        for l in open(symfile, encoding='utf-8', errors='replace'):
            m = re.match(r'^(0x[0-9A-Fa-f]+)\s+0x[0-9A-Fa-f]+\s+\w+\s+(\S+)', l)
            if m: put(m.group(1), m.group(2), 6, 'data' if '_ro_str_' in m.group(2) else 'func')
    with open(out + '/names.tsv', 'w') as f:
        for v in sorted(entries):
            _, nm, kind = entries[v]
            f.write(f'0x{v:08x}\t{nm}\t{kind}\n')
    add(d, f'--bin {d}/{binname} --lang {lang} --base {base} --out {out}')
O = f'{R}/o3ds/decrypted_binaries/Firm-NATIVE_FIRM-0004013800000002'
kernel_job('n3ds', 'decrypted_binaries/kernel_native', 'arm9.bin', 'ARM:LE:32:v5t', '0x08006800', comp_prefix='ARM9 Kernel9+Process9 (NATIVE', manual_comp='kernel_native/arm9', manual_csv='kernel_native_arm9.csv', addr_max=0x0808A900)
kernel_job('n3ds', 'decrypted_binaries/kernel_native', 'arm11_section1.bin', 'ARM:LE:32:v6', '0xFFF00000', comp_prefix='ARM11 Kernel11 (NATIVE', manual_comp='kernel_native/arm11_section1', manual_csv='kernel_native_arm11.csv', alias=0xFFF00000)
kernel_job('n3ds', 'decrypted_binaries/kernel_safe', 'arm9.bin', 'ARM:LE:32:v5t', '0x08006800', comp_prefix='ARM9 Kernel9+Process9 (SAFE', addr_max=0x0808A900)
kernel_job('n3ds', 'decrypted_binaries/kernel_safe', 'arm11_section1.bin', 'ARM:LE:32:v6', '0xFFF00000', comp_prefix='ARM11 Kernel11 (SAFE', alias=0xFFF00000)
kernel_job('n3ds', 'decrypted_binaries/kernel_twl', 'arm9.bin', 'ARM:LE:32:v5t', '0x08006800')
kernel_job('n3ds', 'decrypted_binaries/kernel_agb', 'arm9.bin', 'ARM:LE:32:v5t', '0x08006800')
kernel_job('n3ds', 'decrypted_binaries/kernel_native', 'arm9loader_tail.bin', 'ARM:LE:32:v5t', '0x0808A900', comp_prefix='ARM9 Kernel9+Process9 (NATIVE', addr_min=0x0808A900)
kernel_job('o3ds', 'decrypted_binaries/Firm-NATIVE_FIRM-0004013800000002', 'arm9.bin', 'ARM:LE:32:v5t', '0x08006800', symfile=O + '/arm9_friendly.sym')
kernel_job('o3ds', 'decrypted_binaries/Firm-NATIVE_FIRM-0004013800000002', 'arm11_section1.bin', 'ARM:LE:32:v6', '0xFFF00000', symfile=O + '/arm11_kernel11_friendly.sym', alias=0xFFF00000)
print('\n'.join(jobs))
