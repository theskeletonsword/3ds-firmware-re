#!/usr/bin/env python3
"""Merge per-component transfer CSVs into one N3DS symbol table (symbols/N3DS_SYMBOL_TABLE.csv).
Adds role/service, rejects probable matches whose address shift is an outlier vs. neighbours,
re-labels re-addressed names as adapted_n3ds, and appends N3DS-only entries backed by direct evidence."""
import csv, glob, os, re, statistics, collections
B = os.path.dirname(os.path.abspath(__file__)) + '/../symbols/'
COMP = {  # file stem -> (component, load context, role)
 'kernel9_process9': ('ARM9 Kernel9+Process9 (NATIVE_FIRM sec2)', 'arm9.bin @0x08006800', 'ARM9 kernel / Process9'),
 'kernel9_safe': ('ARM9 Kernel9+Process9 (SAFE_MODE_FIRM sec2)', 'arm9.bin @0x08006800', 'ARM9 kernel / Process9 (safe mode build)'),
 'kernel11_safe': ('ARM11 Kernel11 (SAFE_MODE_FIRM sec1)', 'arm11_section1.bin @0x1FF80000 (runtime alias 0xFFF00000)', 'ARM11 kernel (safe mode build)'),
 'kernel11': ('ARM11 Kernel11 (NATIVE_FIRM sec1)', 'arm11_section1.bin @0x1FF80000 (runtime alias 0xFFF00000)', 'ARM11 kernel'),
 'firm_fs': ('FIRM module fs 0004013000001102', 'code.bin @0x00100000', 'service fs:* (File System, built into FIRM)'),
 'firm_loader': ('FIRM module loader 0004013000001302', 'code.bin @0x14000000', 'service ldr:ro/Loader (built into FIRM)'),
 'firm_pm': ('FIRM module pm 0004013000001202', 'code.bin', 'service pm:* (Process Manager)'),
 'firm_pxi': ('FIRM module pxi 0004013000001402', 'code.bin', 'PXI inter-processor services'),
 'firm_sm': ('FIRM module sm 0004013000001002', 'code.bin', 'srv: (Service Manager)'),
}
def role_of(name, base):
    n = name.lower()
    if re.search(r'svc_0x', n): return base + ' / SVC handler'
    if 'ipc' in n: return base + ' / IPC command handler'
    if 'vtable' in n or 'jump_table' in n or 'jumptable' in n: return base + ' / vtable-jump table'
    if 'crt0' in n or 'init_array' in n or 'fini' in n: return base + ' / CRT'
    if 'irq' in n or 'fiq' in n or 'vector' in n: return base + ' / interrupt-exception'
    return base
rows = []
for f in sorted(glob.glob(B + '*.csv')):
    stem = os.path.basename(f)[:-4]
    if stem in ('N3DS_SYMBOL_TABLE', 'N3DS_MODULE_INVENTORY', 'N3DS_IPC_COMMANDS'): continue
    if stem in COMP: comp, ctx, role = COMP[stem]
    else:
        m = re.match(r'(\w+?)_([0-9A-F]{16})$', stem); nm, tid = m.groups()
        comp, ctx, role = f'SysModule {nm} {tid}', 'code.bin @0x00100000', f'sysmodule {nm}'
    data = list(csv.DictReader(open(f)))
    pts = sorted((int(r['ea_o3ds'], 16), int(r['ea_n3ds'], 16)) for r in data if r['ea_n3ds'])
    shifts = [b - a for a, b in pts]; pos = {a: i for i, (a, b) in enumerate(pts)}
    for r in data:
        lvl = r['confidence_level']; ev = r['technical_evidence']
        if r['ea_n3ds'] and lvl in ('probable_by_transfer', 'probable_by_callgraph', 'probable_by_layout', 'probable_by_similarity', 'probable_by_table', 'probable_by_constants', 'probable_by_gap_function'):
            i = pos[int(r['ea_o3ds'], 16)]; nb = shifts[max(0, i-6):i] + shifts[i+1:i+7]
            if nb and abs(shifts[i] - statistics.median(nb)) > 0x4000:
                lvl = 'unresolved'; ev += ';rejected:address_shift_outlier_vs_neighbours'; r['ea_n3ds'] = ''
        if r['ea_n3ds'] and 'name_readdressed' in ev and lvl in ('exact', 'probable_by_transfer', 'probable_by_callgraph', 'probable_by_layout', 'probable_by_similarity', 'probable_by_table', 'probable_by_constants', 'probable_by_gap_function'):
            ev += f';match_level={lvl}'; lvl = 'adapted_n3ds'
        basis = r['confidence_level'] if lvl == 'adapted_n3ds' else ''
        rows.append([comp, r['ea_n3ds'], r['symbol_name'], r['o3ds_equivalent'], r['ea_o3ds'], r['o3ds_confidence'], lvl, role_of(r['symbol_name'], role), ctx + ' | ' + ev + (' | verification=' + r['verification'] if r.get('verification') else ''), basis])
# N3DS-only entries with direct evidence
rows += [
 ['ARM9 Kernel9+Process9 (NATIVE_FIRM sec2)', '0x0808AA3C', 'n3ds_arm9loader_entry', '(none: O3DS FIRM ARM9 entry is 0x0801B01C)', '', '', 'exact', 'N3DS arm9loader reset stub (FIRM ARM9 entrypoint)',
  'FIRM header Entrypoint ARM9=0x0808AA3C (ctrtool -t firm); code @0x0808AA3C = mrs/orr/msr cpsr + cp15 setup; sits in plain tail of section 2 (arm9loader_tail.bin) after the K9L2-encrypted ARM9 binary'],
]
for r in rows:   # header-confirmed upgrade of a transferred row
    if r[2] == 'arm11_firm_entry_point' and r[1] == '0x1FFAF064':
        r[6] = 'exact'; r[8] += ';FIRM header Entrypoint ARM11=0x1FFAF064 (ctrtool -t firm) confirms the transferred address'
# manual symbols (hand-verified from decompiled C), see symbols/manual/README.md
manual_seen = set()
for f in sorted(glob.glob(B + 'manual/*.csv')):
    for d in csv.DictReader(open(f)):
        mt = re.search(r'([0-9A-F]{16})$', d['binary']); key = mt.group(1) if mt else d['binary']
        manual_seen.add((key, int(d['ea'], 16) & ~1))
# derived structural symbols (symbols/derived/*.csv from tools/derive_ipc.py + tools/refine_with_libctru.py): new names, no O3DS equivalent
taken = collections.defaultdict(set)
for r in rows:
    if r[1]: taken[r[0].split()[-1] if r[0].startswith('SysModule') else r[0]].add(int(r[1], 16) & ~1)
for f in sorted(glob.glob(B + 'derived/*.csv')):
    stem = os.path.basename(f)[:-4]
    for d in csv.DictReader(open(f)):
        mod = d['symbol_name'].split('_')[0]
        comp = f'FIRM module {mod} (derived)' if stem.startswith('firm_') else f'SysModule {mod} {stem}'
        ea_int = int(d['ea_n3ds'], 16) & ~1
        if (stem, ea_int) in manual_seen: continue
        if d['kind'] in ('ipc_command_handler', 'ipc_client_call', 'ipc_dispatcher', 'svc_wrapper', 'thumb_switch_helper') and ea_int in taken.get(stem, set()): continue
        rows.append([comp, d['ea_n3ds'], d['symbol_name'], '', '', '', 'derived_structural', d['kind'], 'derived from N3DS bytes (tools/derive_ipc.py): ' + d['technical_evidence'], ''])
# names proven by the decompiled C itself (tools/name_from_decomp.py)
_seen = {(re.search(r'([0-9A-F]{16})', r[0]).group(1) if re.search(r'([0-9A-F]{16})', r[0]) else r[0], int(r[1], 16) & ~1) for r in rows if r[1]} | manual_seen
for f in sorted(glob.glob(B + 'derived_decomp/n3ds__*.csv')):
    bn = os.path.basename(f)[6:-4]; mt = re.search(r'([0-9A-F]{16})$', bn); key = mt.group(1) if mt else bn
    for d in csv.DictReader(open(f)):
        if (key, int(d['ea'], 16) & ~1) in _seen: continue
        rows.append([bn, d['ea'], d['symbol_name'], '', '', '', 'derived_decompiled', d['kind'], 'derived from the decompiled C: ' + d['technical_evidence'], ''])
for f in sorted(glob.glob(B + 'manual/*.csv')):
    for d in csv.DictReader(open(f)):
        rows.append([d['binary'], d['ea'], d['symbol_name'], '', '', '', 'manual_decompiled', 'manual', d['evidence'], ''])
os.makedirs(B, exist_ok=True)
with open(B + 'N3DS_SYMBOL_TABLE.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['component', 'ea_n3ds', 'symbol_name', 'o3ds_equivalent', 'ea_o3ds', 'o3ds_confidence', 'confidence_level', 'role_service', 'technical_evidence', 'match_basis'])
    w.writerows(rows)
c = collections.Counter((r[0], r[6]) for r in rows)
tot = collections.Counter(r[6] for r in rows)
print('rows', len(rows), dict(tot))
