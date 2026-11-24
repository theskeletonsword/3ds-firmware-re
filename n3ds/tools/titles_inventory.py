#!/usr/bin/env python3
"""Inventory + master symbol table for every decrypted title of a model.
usage: titles_inventory.py <model_root: n3ds|o3ds> <out_dir>
Writes <out_dir>/TITLES_INVENTORY.csv and <out_dir>/TITLES_SYMBOL_TABLE.csv"""
import csv, collections, glob, hashlib, os, re, subprocess, sys
R = os.path.abspath(os.path.dirname(__file__) + '/../..')
model, out = sys.argv[1], sys.argv[2]; os.makedirs(out, exist_ok=True)
other = 'o3ds' if model == 'n3ds' else 'n3ds'
def idx(m):
    d = {}
    for p in glob.glob(f'{R}/{m}/decrypted_titles/*'):
        mm = re.search(r'-([0-9A-F]{16})$', p)
        if mm: d[mm.group(1)] = p
    return d
mine, oth = idx(model), idx(other)
def sha(p):
    h = hashlib.sha256()
    if os.path.exists(p + '/code.bin'): return hashlib.sha256(open(p + '/code.bin', 'rb').read()).hexdigest()
    for dp, dn, fn in sorted(os.walk(p)):
        for f in sorted(fn):
            if f in ('info.txt', 'summary.txt', 'ncch_info.txt') or 'analysis' in dp: continue
            h.update(f.encode()); h.update(hashlib.sha256(open(os.path.join(dp, f), 'rb').read()).digest())
    return h.hexdigest()
def counterpart(tid):
    for t in (tid, tid[:8] + '00' + tid[10:], tid[:8] + '20' + tid[10:]):
        if t in oth and t != tid or (t == tid and t in oth): return t
    return None
inv = []; sym = []
for tid, d in sorted(mine.items()):
    name = re.sub(r'-' + tid + '$', '', os.path.basename(d))
    info = open(d + '/info.txt').read() if os.path.exists(d + '/info.txt') else ''
    ver = (re.search(r'TitleVersion:\s+(.*)', info) or [0, ''])[1]
    ex = subprocess.run(['ctrtool', '-t', 'exheader', d + '/exheader.bin'], capture_output=True, text=True).stdout if os.path.exists(d + '/exheader.bin') else ''
    g = lambda p: (m.group(1).strip() if (m := re.search(p + r'\s*(.*)', ex, re.M)) else '')
    svc = re.search(r'Service access:\s*\n((?:\s*>.*\n)+)', ex)
    services = ' '.join(x.strip()[2:].strip() for x in svc.group(1).splitlines()) if svc else ''
    ncch = [l for l in open(d + '/summary.txt').read().splitlines()] if os.path.exists(d + '/summary.txt') else []
    romfs_files = romfs_bytes = 0; exts = collections.Counter()
    for rd in glob.glob(d + '/content_*/romfs'):
        for dp, dn, fn in os.walk(rd):
            for f in fn:
                romfs_files += 1; romfs_bytes += os.path.getsize(os.path.join(dp, f)); exts[os.path.splitext(f)[1].lower() or '(none)'] += 1
    ct = counterpart(tid); rel = 'only_in_' + model
    if ct:
        a, b = sha(d), sha(oth[ct]); rel = ('identical_content_to_' if a and a == b else 'differs_from_') + other + (f'({ct})' if ct != tid else '')
    cnt = collections.Counter()
    ad = d + '/analysis'
    for f in ('rtti', 'derived', 'sources', 'string_refs', 'library_matches'):
        pth = f'{ad}/{f}.csv'
        if os.path.exists(pth):
            for r in csv.DictReader(open(pth)):
                cnt[r['kind']] += 1
                lvl = {'rtti_typeinfo': 'derived_rtti', 'rtti_vtable': 'derived_rtti', 'rtti_vslot': 'derived_rtti', 'rtti_vptr_init': 'derived_rtti', 'source_file_reference': 'derived_source_ref',
                       'source_path_string': 'derived_source_ref', 'string_reference': 'derived_string_ref', 'library_match': 'library_match'}.get(r['kind'], 'derived_structural')
                sym.append([name, tid, r.get('ea') or r.get('ea_n3ds'), r['symbol_name'], r['kind'], lvl, r['technical_evidence']])
    code = os.path.getsize(d + '/code.bin') if os.path.exists(d + '/code.bin') else 0
    inv.append([tid, name, ver, g(r'^Name:'), g(r'Product code:'), g(r'System mode:'), g(r'System mode \(New3DS\):'), g(r'CPU Speed \(New3DS\):'), code, g(r'Code text size:'), g(r'Code ro size:'), g(r'Code data size:'),
                services, len(ncch), romfs_files, romfs_bytes, ' '.join(f'{k}={v}' for k, v in exts.most_common(5)), rel,
                cnt['rtti_typeinfo'], cnt['rtti_vtable'], cnt['rtti_vptr_init'], cnt['source_file_reference'], cnt['svc_wrapper'], cnt['ipc_command_handler'] + cnt['ipc_client_call'] + cnt['ipc_dispatcher'], cnt['service_name_string'], cnt['string_reference'], cnt['library_match']])
H = ['title_id', 'directory_name', 'title_version', 'exheader_name', 'product_code', 'system_mode', 'system_mode_new3ds', 'cpu_speed_new3ds', 'code_bytes', 'text_size', 'ro_size', 'data_size', 'service_access', 'ncch_contents', 'romfs_files', 'romfs_bytes', 'romfs_top_extensions', 'relation_to_other_model',
     'rtti_classes', 'rtti_vtables', 'rtti_vptr_init_functions', 'source_ref_functions', 'svc_wrappers', 'ipc_candidates', 'service_strings', 'string_ref_functions', 'library_matches']
with open(f'{out}/TITLES_INVENTORY.csv', 'w', newline='') as f: w = csv.writer(f); w.writerow(H); w.writerows(inv)
with open(f'{out}/TITLES_SYMBOL_TABLE.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['title', 'title_id', 'ea', 'symbol_name', 'kind', 'confidence_level', 'technical_evidence']); w.writerows(sym)
print(model, len(inv), 'titles', len(sym), 'symbol rows')
