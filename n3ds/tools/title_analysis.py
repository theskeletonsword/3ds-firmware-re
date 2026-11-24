#!/usr/bin/env python3
"""Reverse-engineering pass over every decrypted title (applications, applets, ...) of one model.

usage: title_analysis.py <decrypted_titles_dir> [--jobs 8]

Per title (needs <title>/code.bin + exheader.bin) it writes <title>/analysis/:
    r2_functions.json   radare2 `aaa; aflj` function list (cache)
    derived.csv         SVC wrappers, IPC handlers/client calls/dispatchers, service-name strings, pointer tables (tools/derive_ipc.py)
    rtti.csv            C++ run-time type information recovered from the binary:
                          * rtti_typeinfo   address of each type_info object, demangled class name, base class
                          * rtti_vtable     vtable start (offset-to-top word) named vtbl_<Class>, slot count
                          * rtti_vslot      each virtual-function slot, named <Class>::vslot<i>
                          * rtti_vptr_init  functions that load the vptr of a class (constructors / destructors / assignment)
    sources.csv         strings that are source-file paths (CTR_SDK / project paths) and the functions that reference them
    strings_interesting.txt  paths, URLs, service names, file names, error/format strings
All names are *evidence* names: class names come from Nintendo's own RTTI strings; virtual-slot / constructor names only add the index/address.
"""
import bisect, csv, json, os, re, struct, subprocess, sys, collections
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import derive_ipc

def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def u16(b, o): return b[o] | (b[o + 1] << 8)

def exh_info(path):
    t = subprocess.run(['ctrtool', '-t', 'exheader', path], capture_output=True, text=True).stdout
    g = lambda p: (re.search(p, t, re.M) or [None, None])[1]
    return {'name': g(r'^Name:\s+(\S+)'), 'text_addr': int(g(r'Code text address:\s+(0x\w+)') or '0x100000', 16),
            'text_size': int(g(r'Code text size:\s+(0x\w+)') or '0', 16)}

def demangle(names):
    p = subprocess.run(['c++filt', '-t'], input='\n'.join(names) + '\n', capture_output=True, text=True)
    out = p.stdout.split('\n')
    return out[:len(names)]

def san(s): return re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_')[:90]

def analyse_title(d):
    code = d + '/code.bin'; ad = d + '/analysis'; os.makedirs(ad, exist_ok=True)
    B = open(code, 'rb').read(); ex = exh_info(d + '/exheader.bin'); base = ex['text_addr']
    fj = ad + '/r2_functions.json'
    if not os.path.exists(fj):
        t = subprocess.run(['r2', '-q', '-a', 'arm', '-b', '32', '-m', hex(base), '-c', 'aaa;aflj', code], capture_output=True, text=True, timeout=1800).stdout
        try: fl = json.loads(t[t.index('['):])
        except Exception: fl = []
        json.dump([{'offset': f['offset'], 'size': f['size'], 'name': f['name']} for f in fl], open(fj, 'w'))
    fl = sorted(json.load(open(fj)), key=lambda f: f['offset'])
    starts = [f['offset'] for f in fl]; fset = set(starts)
    def func_of(a):
        k = bisect.bisect_right(starts, a) - 1
        return fl[k] if k >= 0 and a < fl[k]['offset'] + max(fl[k]['size'], 4) else None
    mod = ex['name'] or 'title'
    # ---- structural (SVC wrappers / IPC / services / tables)
    if fl:
        derive_ipc.analyse('title', code, base, d + '/exheader.bin', fl_json=fj, out_csv=ad + '/derived.csv')
    # ---- RTTI
    rows = []
    text_end = base + max(ex['text_size'], 0) + 0x1000
    pat = re.compile(rb'(?<![\x20-\x7e])(N[0-9][A-Za-z0-9_]{4,}E|[0-9]{1,2}[A-Za-z_][A-Za-z0-9_]{2,60})\x00')
    names = {}
    for m in pat.finditer(B): names[base + m.start(1)] = m.group(1).decode()
    ti = {}                                           # typeinfo address -> (name_str, name_addr, vptr)
    for p in range(0, len(B) - 11, 4):
        w = u32(B, p + 4)
        if w in names:
            ti[base + p] = (names[w], w, u32(B, p))
    cnt = collections.Counter(v[2] for v in ti.values())
    ti = {a: v for a, v in ti.items() if cnt[v[2]] >= 2 and base <= v[2] < base + len(B)}   # same type_info-class vptr shared by several typeinfos
    dm = dict(zip(ti, demangle([v[0] for v in ti.values()]))) if ti else {}
    def plausible(t):
        if not t or not re.fullmatch(r'[A-Za-z0-9_:<>,*&\[\]() .~\-]+', t): return False
        if '::' in t or '<' in t: return True
        return sum(c.isdigit() for c in t) <= 2 and sum(1 for a, b in zip(t, t[1:]) if a.isalpha() and b.isalpha() and a.islower() != b.islower()) <= 12
    ti = {a: v for a, v in ti.items() if dm.get(a) and plausible(dm[a])}   # keep real C++ type names only
    for a, (nm, na, vp) in sorted(ti.items()):
        baset = u32(B, a - base + 8) if a - base + 12 <= len(B) else 0
        bname = dm.get(baset)
        rows.append([f'0x{a:08X}', '0xC', f'typeinfo_{san(dm[a])}', 'rtti_typeinfo', f'type_info of class "{dm[a]}" (mangled {nm}); base class: {bname or "none/multiple"}'])
    # vtables: word pointing at a typeinfo, previous word = offset-to-top (0 or small), next words = code pointers
    vt = {}
    for p in range(4, len(B) - 11, 4):
        w = u32(B, p)
        if w in ti and u32(B, p - 4) in (0,) or (w in ti and u32(B, p - 4) < 0x100):
            cls = dm[w]; slots = []
            q = p + 4
            while q + 4 <= len(B):
                f = u32(B, q)
                if (f & ~1) in fset: slots.append(f & ~1); q += 4
                else: break
            vt.setdefault(cls, []).append((base + p - 4, slots))
            rows.append([f'0x{base + p - 4:08X}', hex(8 + 4 * len(slots)), f'vtbl_{san(cls)}', 'rtti_vtable', f'vtable of "{cls}" ({len(slots)} virtual slots after offset-to-top and typeinfo)'])
            for i, f in enumerate(slots):
                fn = func_of(f)
                rows.append([f'0x{f:08X}', hex(fn['size']) if fn else '0x0', f'{san(cls)}__vslot{i}_{f:x}', 'rtti_vslot', f'virtual slot {i} of "{cls}" (pointer at 0x{base + p + 4 + 4 * i:08X})'])
    # vptr loaders: literal word == &vtable[0] (vtable_base + 8)
    lit_loaders = collections.defaultdict(list)
    vptrs = {}
    for cls, lst in vt.items():
        for vb, slots in lst: vptrs[vb + 8] = cls
    for p in range(0, len(B) - 3, 2):
        h = u16(B, p); ea = base + p
        a = None
        if h & 0xF800 == 0x4800: a = ((ea + 4) & ~3) + (h & 0xFF) * 4
        elif p % 4 == 0:
            w = u32(B, p)
            if (w & 0x0F7F0000) == 0x051F0000:
                imm = w & 0xFFF; a = ea + 8 + (imm if (w >> 23) & 1 else -imm)
        if a is None: continue
        lo = a - base
        if 0 <= lo + 4 <= len(B):
            v = u32(B, lo)
            if v in vptrs:
                f = func_of(ea)
                if f: lit_loaders[(f['offset'], vptrs[v])].append(ea)
    seen = set()
    for (fo, cls), eas in sorted(lit_loaders.items()):
        f = next(x for x in fl if x['offset'] == fo)
        rows.append([f'0x{fo:08X}', hex(f['size']), f'{san(cls)}__vptr_init_{fo:x}', 'rtti_vptr_init', f'loads the vtable pointer of "{cls}" (constructor / destructor / assignment) at {", ".join("0x%X" % e for e in eas[:3])}'])
    rtti_rows = rows
    with open(ad + '/rtti.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['ea', 'size', 'symbol_name', 'kind', 'technical_evidence']); w.writerows(sorted(rtti_rows, key=lambda r: int(r[0], 16)))
    # ---- source-file strings and referencing functions
    srcpat = re.compile(rb'(?<![\x20-\x7e])((?:[A-Za-z]:)?[\\/A-Za-z0-9_.\-]*[\\/][A-Za-z0-9_.\-]+\.(?:c|cpp|cc|h|hpp|inl))\x00')
    srcs = {base + m.start(1): m.group(1).decode() for m in srcpat.finditer(B)}
    srefs = collections.defaultdict(set)
    for p in range(0, len(B) - 3, 2):
        h = u16(B, p); ea = base + p; a = None
        if h & 0xF800 == 0x4800: a = ((ea + 4) & ~3) + (h & 0xFF) * 4
        elif p % 4 == 0:
            w = u32(B, p)
            if (w & 0x0F7F0000) == 0x051F0000:
                imm = w & 0xFFF; a = ea + 8 + (imm if (w >> 23) & 1 else -imm)
        if a is None or not (0 <= a - base + 4 <= len(B)): continue
        v = u32(B, a - base)
        if v in srcs:
            f = func_of(ea)
            if f: srefs[f['offset']].add(srcs[v])
    with open(ad + '/sources.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['ea', 'size', 'symbol_name', 'kind', 'technical_evidence'])
        for a_, s_ in sorted(srcs.items()): w.writerow([f'0x{a_:08X}', hex(len(s_) + 1), f'str_srcpath_{san(os.path.basename(s_.replace(chr(92), "/")))}', 'source_path_string', s_])
        for fo, ss in sorted(srefs.items()):
            fn = next(x for x in fl if x['offset'] == fo); one = sorted(ss)[0]
            w.writerow([f'0x{fo:08X}', hex(fn['size']), f'srcref_{san(os.path.basename(one.replace(chr(92), "/")))}_{fo:x}', 'source_file_reference', 'function references source path(s): ' + ' | '.join(sorted(ss)[:3])])
    # ---- functions that reference specific strings (names derived from the strings themselves)
    asc = re.compile(rb'(?<![\x20-\x7e])([\x20-\x7e]{8,120})\x00')
    allstr = {base + m.start(1): m.group(1).decode() for m in asc.finditer(B)}
    good = lambda t: re.search(r'[A-Za-z]{4}', t) and not re.fullmatch(r'[\W_0-9]+', t) and (' ' in t or '/' in t or '_' in t or '%' in t or ':' in t or '.' in t or t[0].isupper())
    sref = collections.defaultdict(set)
    for p in range(0, len(B) - 3, 2):
        h = u16(B, p); ea = base + p; a = None
        if h & 0xF800 == 0x4800: a = ((ea + 4) & ~3) + (h & 0xFF) * 4
        elif p % 4 == 0:
            w = u32(B, p)
            if (w & 0x0F7F0000) == 0x051F0000:
                imm = w & 0xFFF; a = ea + 8 + (imm if (w >> 23) & 1 else -imm)
        if a is None or not (0 <= a - base + 4 <= len(B)): continue
        v = u32(B, a - base)
        if v in allstr and v not in srcs and good(allstr[v]):
            f = func_of(ea)
            if f: sref[f['offset']].add(allstr[v])
    with open(ad + '/string_refs.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['ea', 'size', 'symbol_name', 'kind', 'technical_evidence'])
        for fo, ss in sorted(sref.items()):
            if len(ss) > 4: continue                                  # functions touching many strings are big dispatchers, not identified by one string
            fn = next(x for x in fl if x['offset'] == fo); one = max(sorted(ss), key=len)
            w.writerow([f'0x{fo:08X}', hex(fn['size']), f'strref_{san(one)[:48]}_{fo:x}', 'string_reference', 'function references string(s): ' + ' | '.join(sorted(ss)[:3])])
    # ---- interesting strings
    ip = re.compile(rb'[\x20-\x7e]{6,160}')
    keep = re.compile(r'(https?://|\.(bin|bcres|bclim|bcfnt|bcwav|bcstm|cwav|ctpk|arc|lz|sarc|zip|dat|db|sav|cfg|xml|json|csv|msbt|cgfx|ccsnd|bcfna|bclyt)\b|nand:|sdmc:|data:|rom:|save:|[a-z]+::[A-Za-z]+|ERR|FAIL|Fail|fail|%[sdxu]|/[A-Za-z0-9_]+/)')
    ls = []
    for m in ip.finditer(B):
        s_ = m.group().decode()
        if keep.search(s_): ls.append(f'0x{base + m.start():08X}\t{s_}')
    open(ad + '/strings_interesting.txt', 'w').write('\n'.join(ls[:20000]) + '\n')
    return os.path.basename(d), len(fl), len(rtti_rows), len(ti), len(srcs)

if __name__ == '__main__':
    root = sys.argv[1]; jobs = int(sys.argv[sys.argv.index('--jobs') + 1]) if '--jobs' in sys.argv else 8
    dirs = [p for p in sorted(os.listdir(root)) if os.path.exists(f'{root}/{p}/code.bin')]
    def safe(p):
        try: return analyse_title(f'{root}/{p}')
        except Exception as e: return (p, 'ERR', repr(e)[:80], 0, 0)
    with ThreadPoolExecutor(jobs) as ex:
        for r in ex.map(safe, dirs): print(*r, flush=True)
