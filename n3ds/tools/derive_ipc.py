#!/usr/bin/env python3
"""Evidence-derived structural symbols for every N3DS module (no O3DS reference needed):

  * IPC command handlers   : ARM functions that read the TLS pointer (mrc p15,0,Rd,c13,c0,3) and store a header-shaped constant at
                             [tls+0x80] (str Rd,[Rn,#0x80]) -> name  <mod>_ipc_handler_cmd_<id>_<addr>
  * IPC dispatchers        : functions that load the request header ([tls+0x80]) and compare/select many command ids
  * service-name strings   : ASCII "xxx:yyy" / "xxx::YYY" strings; classified as 'client of' when the name is in the ExHeader service-access
                             list, otherwise 'server port'
  * pointer tables         : runs of >=3 consecutive words that point to function starts (vtables, jump/dispatch tables)

IPC header shape (3dbrew): cmd_id<<16 | normal_params<<6 | translate_params.  Limitations: Thumb-only handlers and headers built
with mov/orr are not seen; names are structural (derived), they are NOT Nintendo's original names.
Output: symbols/derived/<TID>.csv and symbols/N3DS_IPC_COMMANDS.csv
"""
import bisect, csv, glob, json, os, re, struct, subprocess, sys, collections
R = os.path.abspath(os.path.dirname(__file__) + '/..')
os.makedirs(R + '/symbols/derived', exist_ok=True)

def u32(b, o): return struct.unpack_from('<I', b, o)[0]

def exheader_services(path):
    t = subprocess.run(['ctrtool', '-t', 'exheader', path], capture_output=True, text=True).stdout
    name = (re.search(r'^Name:\s+(\S+)', t, re.M) or [None, '?'])[1]
    m = re.search(r'Service access:\s*\n((?:\s*>.*\n)+)', t)
    return name, ([x.strip()[2:].strip() for x in m.group(1).splitlines()] if m else [])

def plausible_header(v):
    return 1 <= (v >> 16) <= 0x1FF and (v & 0xF000) == 0 and ((v >> 6) & 0x3F) <= 16 and (v & 0x3F) <= 16 and (v & 0xFFFF) != 0

def svc_names():
    names = {}
    for l in open(R + '/../o3ds/KERNEL_ANALYSIS.md', encoding='utf-8'):
        m = re.match(r'^\| `0x([0-9A-F]{2})` \| `0xFFF[0-9A-F]{5}` \| `0x1FF[0-9A-F]{5}` \| ([A-Za-z0-9]+) \|', l)
        if m: names[int(m.group(1), 16)] = m.group(2)
    return names
SVCN = svc_names()

def analyse(tid, code_path, base, exh_path, mod_hint=None, fl_json=None, out_csv=None):
    B = open(code_path, 'rb').read()
    fl = json.load(open(fl_json or f'{R}/symbols/r2_functions/{tid}.json'))
    fl.sort(key=lambda f: f['offset'])
    starts = [f['offset'] for f in fl]
    def func_of(addr):
        k = bisect.bisect_right(starts, addr) - 1
        if k < 0: return None
        f = fl[k]
        return f if addr < f['offset'] + max(f['size'], 4) else None
    mod, services = exheader_services(exh_path) if exh_path else (mod_hint, [])
    per = collections.defaultdict(lambda: {'svc32': 0, 'hdr_all': set(), 'wr': [], 'tls': 0})
    def lit_at(a_):
        lo = a_ - base
        return u32(B, lo) if 0 <= lo + 4 <= len(B) else None
    # ARM
    for o in range(0, len(B) - 3, 4):
        w = u32(B, o); ea = base + o
        f = func_of(ea)
        if f is None: continue
        d = per[f['offset']]
        if w == 0xEF000032: d['svc32'] += 1
        if (w & 0xFFFF0FFF) == 0xEE1D0F70: d['tls'] += 1
        if (w & 0x0F7F0000) == 0x051F0000:
            imm = w & 0xFFF; v = lit_at(ea + 8 + (imm if (w >> 23) & 1 else -imm)); rd = (w >> 12) & 0xF
            if v is not None and plausible_header(v):
                d['hdr_all'].add(v)
                for k in range(1, 7):                                  # header stored soon after: str rd,[rn,#0] / [rn,#0x80]
                    if o + 4 * k + 4 > len(B): break
                    w2 = u32(B, o + 4 * k)
                    if (w2 & 0xFFF00FFF) in (0xE5800000, 0xE5800080) and ((w2 >> 12) & 0xF) == rd:
                        d['wr'].append((v, 0x80 if (w2 & 0xFFF) == 0x80 else 0)); break
    # Thumb (ldr rd,[pc,#]; ... str rd,[rn,#0])
    for o in range(0, len(B) - 3, 2):
        h = B[o] | (B[o + 1] << 8)
        if h & 0xF800 != 0x4800: continue
        ea = base + o; f = func_of(ea)
        if f is None: continue
        rd = (h >> 8) & 7; v = lit_at(((ea + 4) & ~3) + (h & 0xFF) * 4)
        if v is None or not plausible_header(v): continue
        d = per[f['offset']]; d['hdr_all'].add(v)
        for k in range(1, 7):
            if o + 2 * k + 2 > len(B): break
            h2 = B[o + 2 * k] | (B[o + 2 * k + 1] << 8)
            if (h2 & 0xFFC0) == 0x6000 and (h2 & 7) == rd: d['wr'].append((v, 0)); break
    rows = []; cmds = []
    for off, d in per.items():
        f = next(x for x in fl if x['offset'] == off)
        if d['wr']:
            client = d['svc32'] > 0 or any(i == 0x80 for _, i in d['wr'])
            ids = sorted({v >> 16 for v, _ in d['wr']})
            tag = '_'.join(f'{i:04X}' for i in ids[:3]) + ('_etc' if len(ids) > 3 else '')
            kind = 'ipc_client_call' if client else 'ipc_command_handler'
            rows.append([f"0x{off:08X}", hex(f['size']), f"{mod}_ipc_{'client' if client else 'handler'}_cmd_{tag}_{off:x}", kind,
                         ('uses SVC 0x32 SendSyncRequest or stores to [tls+0x80]: builds request header ' if client else 'stores header-shaped literal to the IPC command buffer argument: reply/response header ') +
                         ', '.join('0x%08X' % v for v, _ in d['wr'][:4])])
            for v, _ in d['wr']: cmds.append([tid, mod, f'0x{off:08X}', f'0x{v:08X}', f'0x{v >> 16:04X}', (v >> 6) & 0x3F, v & 0x3F, kind])
        elif len(d['hdr_all']) >= 4:
            rows.append([f"0x{off:08X}", hex(f['size']), f'{mod}_ipc_dispatcher_{off:x}', 'ipc_dispatcher',
                         f"{len(d['hdr_all'])} distinct header-shaped literals (command-id compare table), e.g. " + ', '.join('0x%08X' % v for v in sorted(d['hdr_all'])[:4])])
    # SVC wrappers: tiny ARM functions with exactly one `svc #n` and a return
    for f in fl:
        if f['size'] > 0x20 or f['offset'] % 4: continue
        lo = f['offset'] - base
        ws = [u32(B, lo + 4 * i) for i in range(f['size'] // 4)] if lo + f['size'] <= len(B) else []
        svcs = [w & 0xFF for w in ws if (w >> 8) == 0xEF0000]
        rets = [w for w in ws if w in (0xE12FFF1E, 0xE8BD8000) or (w & 0xFFFF0000) == 0xE49D0000 and (w & 0xF000) == 0xF000]
        if len(svcs) == 1 and rets and svcs[0] in SVCN:
            rows.append([f"0x{f['offset']:08X}", hex(f['size']), f'{mod}_svc_0x{svcs[0]:02X}_{SVCN[svcs[0]]}_{f["offset"]:x}', 'svc_wrapper',
                         f'function body is a single `svc #0x{svcs[0]:02X}` + return ({f["size"]} bytes); SVC name from the Kernel11 table (3dbrew naming, see o3ds/KERNEL_ANALYSIS.md)'])
    # service-name strings
    for m in re.finditer(rb'(?<![\x20-\x7e])([A-Za-z0-9_]{1,8}:{1,2}[A-Za-z0-9_]{0,8})\x00', B):
        s = m.group(1).decode(); off = m.start(1)
        if len(s) < 4 or s.count(':') == 0: continue
        client = s in services
        rows.append([f'0x{base + off:08X}', hex(len(s) + 1), f"{mod}_str_service_{re.sub(r'[^A-Za-z0-9]', '_', s)}", 'service_name_string',
                     ('client of (in ExHeader service-access list)' if client else 'name present in module data but not in the ExHeader access list (server port registered by this module, or an ACL/name table entry)') + f': "{s}"'])
    # pointer tables
    funcs = set(starts)
    i = 0; n = len(B)
    while i + 12 <= n:
        run = 0
        while i + 4 <= n and (u32(B, i) & ~1) in funcs:
            run += 1; i += 4
        if run >= 3:
            s0 = i - 4 * run
            rows.append([f'0x{base + s0:08X}', hex(4 * run), f'{mod}_func_ptr_table_{s0 + base:x}', 'pointer_table',
                         f'{run} consecutive pointers to function starts (vtable / dispatch / jump table)'])
        i += 4 if not run else 0
    rows.sort(key=lambda r: int(r[0], 16))
    with open(out_csv or f'{R}/symbols/derived/{tid}.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['ea_n3ds', 'size', 'symbol_name', 'kind', 'technical_evidence']); w.writerows(rows)
    return mod, rows, cmds

if __name__ == '__main__':
    allc = []; summary = []
    for d in sorted(glob.glob(R + '/decrypted_binaries/Module-*')):
        tid = d[-16:]
        mod, rows, cmds = analyse(tid, d + '/code.bin', 0x100000, d + '/exheader.bin')
        allc += cmds
        k = collections.Counter(r[3] for r in rows); summary.append((tid, mod, dict(k)))
        print(tid, mod, dict(k))
    for m, base in (('fs', 0x100000), ('loader', 0x14000000), ('pm', 0x100000), ('pxi', 0x100000), ('sm', 0x100000)):
        d = f'{R}/decrypted_binaries/firm_modules/{m}'
        mod, rows, cmds = analyse('firm_' + m, d + '/code.bin', base, d + '/exheader.bin', m)
        allc += cmds; print('firm_' + m, mod, dict(collections.Counter(r[3] for r in rows)))
    with open(R + '/symbols/N3DS_IPC_COMMANDS.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['module_tid', 'module', 'handler_ea', 'reply_or_request_header', 'cmd_id', 'normal_params', 'translate_params', 'kind']); w.writerows(allc)
    print('ipc header observations', len(allc))
