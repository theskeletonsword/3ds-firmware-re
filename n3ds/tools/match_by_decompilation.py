#!/usr/bin/env python3
"""Propose N3DS counterparts for still-unresolved O3DS symbols by comparing the *decompiled C* (normalized token shingles).

usage: match_by_decompilation.py <component_csv_stem> <o3ds_decompiled_dir> <n3ds_decompiled_dir> [--alias 0xFFF00000]
  e.g.  match_by_decompilation.py kernel11 ../o3ds/decrypted_binaries/Firm-NATIVE_FIRM-0004013800000002/decompiled_arm11_section1 decrypted_binaries/kernel_native/decompiled_arm11_section1 --alias 0xFFF00000
Candidates are all N3DS decompiled functions whose address is not already claimed by a matched row. Output: symbols/proposals/<stem>.csv
(o3ds_symbol, o3ds_ea, rank, candidate_ea, score, margin) - proposals only: confirm by reading both C files, then record in symbols/manual/.
"""
import collections, csv, glob, os, re, sys
R = os.path.abspath(os.path.dirname(__file__) + '/..')
def norm(c):
    c = re.sub(r'//.*', '', c); c = re.sub(r'/\*.*?\*/', '', c, flags=re.S)
    c = re.sub(r'\b(FUN|DAT|LAB|PTR|SUB|switchD|caseD|thunk_FUN)_[0-9a-fA-F]+', r'\1', c)
    c = re.sub(r'\b(?:[a-z]{1,3}Var\d+|param_\d+|local_[0-9a-f]+|in_\w+|unaff_\w+|extraout_\w+)\b', 'V', c)
    c = re.sub(r'\b0x[0-9a-fA-F]{6,}\b', 'ADDR', c)
    return re.findall(r'[A-Za-z_]\w*|0x[0-9a-fA-F]+|\d+|[^\sA-Za-z0-9_]', c)
def shingles(t, k=4): return collections.Counter(tuple(t[i:i + k]) for i in range(max(len(t) - k + 1, 0)))
def load(d):
    out = {}
    for f in glob.glob(d + '/*.c'):
        a = int(os.path.basename(f)[:-2], 16); t = open(f, errors='replace').read()
        tk = norm(t.split('\n', 1)[1] if t.startswith('//') else t)
        if len(tk) >= 12: out[a] = shingles(tk)
    return out
def sim(a, b):
    inter = sum((a & b).values()); uni = sum((a | b).values()); return inter / uni if uni else 0
if __name__ == '__main__':
    stem, od, nd = sys.argv[1:4]
    alias = int(sys.argv[sys.argv.index('--alias') + 1], 16) if '--alias' in sys.argv else None
    rows = list(csv.DictReader(open(f'{R}/symbols/{stem}.csv')))
    claimed = {int(r['ea_n3ds'], 16) for r in rows if r['ea_n3ds'] and r['confidence_level'] != 'unresolved'}
    O = load(od); N = load(nd)
    cand = {a: s for a, s in N.items() if a not in claimed}
    print(stem, 'o3ds funcs', len(O), 'n3ds funcs', len(N), 'unclaimed candidates', len(cand))
    os.makedirs(R + '/symbols/proposals', exist_ok=True); res = []
    for r in rows:
        if r['confidence_level'] != 'unresolved': continue
        ea = int(r['ea_o3ds'], 16)
        if alias and 0x1FF80000 <= ea < 0x20000000: ea = ea - 0x1FF80000 + alias
        o = O.get(ea)
        if not o: res.append([r['symbol_name'], hex(ea), 0, '', 0, 0, 'no decompiled O3DS function at that address']); continue
        sc = sorted(((sim(o, s), a) for a, s in cand.items()), reverse=True)[:3]
        for i, (s, a) in enumerate(sc): res.append([r['symbol_name'], hex(ea), i + 1, hex(a), round(s, 3), round(s - (sc[1][0] if i == 0 and len(sc) > 1 else 0), 3), ''])
    with open(f'{R}/symbols/proposals/{stem}.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['o3ds_symbol', 'o3ds_ea', 'rank', 'n3ds_candidate_ea', 'score', 'margin_to_rank2', 'note']); w.writerows(res)
    for x in res:
        if x[2] == 1: print(x[0][:40].ljust(40), x[1], x[3], x[4], x[5], x[6])
