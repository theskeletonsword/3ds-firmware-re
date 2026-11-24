#!/usr/bin/env python3
"""Propagate names across ALL analysed binaries (CTR-SDK / NintendoWare / libc code is statically linked into every title).

A function is *named* in a source binary when it has a real-evidence name: C++ class names from RTTI (ctor/dtor/virtual slots), source-file references,
or a semantic O3DS symbol (cecd/nwm/hid/gsp/i2c/mcu/ptm and the FIRM modules). Every other binary is searched for functions whose position-masked bytes
(bl/b, literal loads, address-like literal-pool words) are identical to such a function; the name is transferred when all matching sources agree.

usage: library_propagation.py        (reads the analysis/ folders written by title_analysis.py for o3ds and n3ds, writes analysis/library_matches.csv per binary
                                      and symbols/titles/LIBRARY_MATCHES.csv)
"""
import bisect, collections, csv, glob, hashlib, json, os, re, struct, subprocess, sys
import numpy as np
R = os.path.abspath(os.path.dirname(__file__) + '/../..')
MIN_SIZE = 32

def mask_arm(B):
    n = len(B) // 4 * 4
    w = np.frombuffer(bytes(B[:n]), dtype='<u4').copy()
    top = (w >> 25) & 7
    m_b = top == 5
    m_ldr = (w & 0x0F7F0000) == 0x051F0000
    m_add = ((w & 0x0FFF0000) == 0x028F0000) | ((w & 0x0FFF0000) == 0x024F0000)
    t = w >> 24
    m_ptr = np.isin(t, [0x08, 0x09, 0x1F, 0x1E, 0x10, 0xFF, 0x18, 0x20, 0x01, 0x00]) & (w >= 0x00100000) & ~m_b & ~m_ldr
    w[m_b] &= 0xFF000000; w[m_ldr] &= 0xFFFFF000; w[m_add] &= 0xFFFFF000; w[m_ptr] = 0
    return w.tobytes()

def mask_thumb(B):
    n = len(B) // 2 * 2
    h = np.frombuffer(bytes(B[:n]), dtype='<u2').copy()
    hi = h >> 11
    h[(h >= 0xF000) & (h <= 0xF7FF)] &= 0xF800
    h[(h >= 0xF800)] &= 0xF800
    h[(h >= 0xE800) & (h <= 0xEFFF)] &= 0xF800
    h[(h >= 0x4800) & (h <= 0x4FFF)] &= 0xFF00
    h[(h >= 0xA000) & (h <= 0xA7FF)] &= 0xFF00
    h[(h >= 0xE000) & (h <= 0xE7FF)] &= 0xF800
    h[(h >= 0xD000) & (h <= 0xDEFF)] &= 0xFF00
    out = bytearray(h.tobytes())
    w = np.frombuffer(bytes(B[:len(B) // 4 * 4]), dtype='<u4')
    t = w >> 24
    m = np.isin(t, [0x08, 0x09, 0x1F, 0x1E, 0x10, 0xFF, 0x18, 0x20, 0x01, 0x00]) & (w >= 0x00100000)
    for i in np.nonzero(m)[0]: out[i * 4:i * 4 + 4] = b'\0\0\0\0'
    return bytes(out)

def norm_name(n):
    n = re.sub(r'(_0x[0-9A-Fa-f]+|_[0-9a-f]{5,8})+$', '', n)
    n = re.sub(r'^(fs|ldr|pm|pxi|sm|nwm|cecd|hid|gsp|i2c|mcu|ptm|p9|k9|k11)_', '', n)
    return n

class Bin:
    def __init__(self, bid, code, base, fl, names):
        self.id, self.base, self.fl, self.names = bid, base, fl, names
        self.B = open(code, 'rb').read()
        self.sha = hashlib.sha1(self.B).hexdigest()
        self.keys = {}
    def hashes(self):
        ma, mt = mask_arm(self.B), mask_thumb(self.B)
        out = {}
        for f in self.fl:
            if f['size'] < MIN_SIZE: continue
            o = f['offset'] - self.base
            if o < 0 or o + f['size'] > len(self.B): continue
            ha = hashlib.md5(ma[o:o + f['size']]).digest() if o % 4 == 0 else None
            ht = hashlib.md5(mt[o:o + f['size']]).digest() if o % 2 == 0 else None
            out[f['offset']] = (ha, ht, f['size'])
        return out

def load_names_csv(path):
    d = {}
    if not os.path.exists(path): return d
    for r in csv.DictReader(open(path)):
        if r['kind'] in ('rtti_vptr_init', 'rtti_vslot', 'source_file_reference'):
            d[int(r['ea'], 16)] = (r['symbol_name'], r['kind'])
    return d

def load_all(d):
    names = load_names_csv(d + '/analysis/rtti.csv'); names.update(load_names_csv(d + '/analysis/sources.csv'))
    p = d + '/analysis/string_refs.csv'
    if os.path.exists(p):
        for r in csv.DictReader(open(p)): names.setdefault(int(r['ea'], 16), (r['symbol_name'], 'string_reference'))
    return names

def load_sym(path):
    d = {}
    for l in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'^0x([0-9A-Fa-f]+)\s+0x[0-9A-Fa-f]+\s+(CONFIRMED|EVIDENCE_BASED)\s+(\S+)', l)
        if m: d[int(m.group(1), 16)] = (m.group(3), 'o3ds_semantic')
    return d

def collect():
    bins = []
    for model in ('o3ds', 'n3ds'):
        for d in sorted(glob.glob(f'{R}/{model}/decrypted_titles/*')):
            fj = d + '/analysis/r2_functions.json'
            if not os.path.exists(fj): continue
            ex = subprocess.run(['ctrtool', '-t', 'exheader', d + '/exheader.bin'], capture_output=True, text=True).stdout
            mm = re.search(r'Code text address:\s+(0x\w+)', ex); base = int(mm.group(1), 16) if mm else (0x14000000 if d.endswith('loader') else 0x100000)
            names = load_all(d)
            bins.append((Bin(f'{model}:{os.path.basename(d)}', d + '/code.bin', base, json.load(open(fj)), names), d))
    # sysmodules / FIRM modules: semantic O3DS names (sources) and plain targets
    for model in ('o3ds', 'n3ds'):
        for d in sorted(glob.glob(f'{R}/{model}/decrypted_binaries/Module-*')) + sorted(glob.glob(f'{R}/{model}/decrypted_binaries/firm_modules/*')):
            fj = d + '/analysis/r2_functions.json'
            if not os.path.exists(fj): continue
            ex = subprocess.run(['ctrtool', '-t', 'exheader', d + '/exheader.bin'], capture_output=True, text=True).stdout
            mm = re.search(r'Code text address:\s+(0x\w+)', ex); base = int(mm.group(1), 16) if mm else (0x14000000 if d.endswith('loader') else 0x100000)
            names = {}
            if model == 'o3ds':
                for sy in glob.glob(d + '/*_friendly.sym'): names.update(load_sym(sy))
            names.update(load_all(d))
            bins.append((Bin(f'{model}:{os.path.basename(d)}', d + '/code.bin', base, json.load(open(fj)), names), d))
    return bins

def main():
    bins = collect(); print('binaries', len(bins))
    # database over *distinct* code images
    db = collections.defaultdict(set)         # (mode, hash) -> {(norm_name, raw_name, bin_id, ea, kind)}
    seen = set(); hs = {}
    for b, d in bins:
        hs[b.id] = b.hashes()
        if b.sha in seen: continue
        seen.add(b.sha)
        for ea, (nm, kind) in b.names.items():
            h = hs[b.id].get(ea)
            if not h: continue
            for mode, hv in (('a', h[0]), ('t', h[1])):
                if hv: db[(mode, hv)].add((norm_name(nm), nm, b.id, ea, kind))
    # semantic O3DS names that are really domain buckets (same normalized name used by >= 4 functions) are not function names: drop them
    cnt = collections.Counter()
    for k, v in db.items():
        for e in v:
            if e[4] == 'o3ds_semantic': cnt[(e[0], e[2], e[3])] += 1
    bucket = collections.Counter(n for (n, _, _) in cnt)
    for k in list(db):
        db[k] = {e for e in db[k] if not (e[4] == 'o3ds_semantic' and bucket[e[0]] >= 4)}
        if not db[k]: del db[k]
    print('db keys', len(db))
    allrows = []; done_sha = set()
    for b, d in bins:
        rows = []
        if b.sha in done_sha: continue          # identical image (other model): same names, no separate matching
        done_sha.add(b.sha)
        for f in b.fl:
            ea = f['offset']
            if ea in b.names: continue
            h = hs[b.id].get(ea)
            if not h: continue
            cands = set()
            for mode, hv in (('a', h[0]), ('t', h[1])):
                if hv and (mode, hv) in db: cands |= db[(mode, hv)]
            cands = {c for c in cands if c[2] != b.id}
            if not cands: continue
            norms = {c[0] for c in cands}
            if len(norms) != 1: continue
            c = sorted(cands)[0]
            nm = 'lib_' + re.sub(r'[^A-Za-z0-9_]', '_', c[0])[:100] + f'_{ea:x}'
            kinds = {x[4] for x in cands}
            rows.append([f'0x{ea:08X}', hex(f['size']), nm, 'library_match',
                         f'masked bytes identical to {len(cands)} named function(s), e.g. {c[2]} @0x{c[3]:08X} "{c[1]}" ({"/".join(sorted(kinds))})'])
        os.makedirs(d + '/analysis', exist_ok=True)
        with open(d + '/analysis/library_matches.csv', 'w', newline='') as f:
            w = csv.writer(f); w.writerow(['ea', 'size', 'symbol_name', 'kind', 'technical_evidence']); w.writerows(rows)
        allrows += [[b.id] + r for r in rows]
        print(b.id[:70].ljust(70), len(rows))
    os.makedirs(R + '/n3ds/symbols/titles', exist_ok=True)
    with open(R + '/n3ds/symbols/titles/LIBRARY_MATCHES.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['binary', 'ea', 'size', 'symbol_name', 'kind', 'technical_evidence']); w.writerows(allrows)
    print('total', len(allrows))

if __name__ == '__main__': main()
