#!/usr/bin/env python3
"""N3DS vs O3DS module inventory: identity, exheader deltas, service access, SVC numbers actually used in code."""
import csv, glob, hashlib, os, re, struct, subprocess, collections, sys
R = os.path.abspath(os.path.dirname(__file__) + '/../..')
N = R + '/n3ds/decrypted_binaries'; O = R + '/o3ds/decrypted_binaries'
def ex(path):
    t = subprocess.run(['ctrtool', '-t', 'exheader', path], capture_output=True, text=True).stdout
    g = lambda p: (re.search(p, t, re.M) or [None, None])[1]
    d = {'name': g(r'^Name:\s+(\S+)'), 'text': g(r'Code text size:\s+(\S+)'), 'ro': g(r'Code ro size:\s+(\S+)'),
         'data': g(r'Code data size:\s+(\S+)'), 'bss': g(r'Code bss size:\s+(\S+)'), 'textaddr': g(r'Code text address:\s+(\S+)'),
         'n3ds_mode': g(r'System mode \(New3DS\):\s+(.+)'), 'cpu': g(r'CPU Speed \(New3DS\):\s+(.+)'), 'l2': g(r'Enable L2 Cache:\s+(\S+)'),
         'prio': g(r'Main thread priority:\s+(\S+)'), 'dep': g(r'Dependency:\s+(\S+)')}
    m = re.search(r'Service access:\s*\n((?:\s*>.*\n)+)', t)
    d['svc'] = sorted(x.strip()[2:].strip() for x in m.group(1).splitlines()) if m else []
    m = re.search(r'Allowed systemcalls:\s+(.*?)\nAllowed interrupts', t, re.S)
    d['allowed_svc'] = sorted(set(re.findall(r'[0-9A-F]{2}', m.group(1)))) if m else []
    return d
def svcs_used(code):
    c = collections.Counter()
    for i in range(0, len(code) - 3, 4):
        w = struct.unpack_from('<I', code, i)[0]
        if (w >> 8) == 0xEF0000: c[w & 0xFF] += 1          # ARM 'svc #n' (cond=AL, imm24<=0xFF); user mode is ARM
    return ' '.join(f'{k:02X}' for k in sorted(c))
sha = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()[:12]
omap = {d[-16:]: d for d in glob.glob(O + '/Module-*')}
rows = []
for d in sorted(glob.glob(N + '/Module-*')):
    tid = d[-16:]; e = ex(d + '/exheader.bin')
    ot = tid[:8] + '00' + tid[10:] if tid[8:10] == '20' else tid
    od = omap.get(ot); oe = ex(od + '/exheader.bin') if od else None
    code = open(d + '/code.bin', 'rb').read()
    if not od: rel, notes = 'N3DS_only', 'no O3DS counterpart present in o3ds/decrypted_binaries'
    elif sha(d + '/code.bin') == sha(od + '/code.bin'): rel, notes = 'identical_to_O3DS', 'code.bin sha256 equal: every O3DS symbol transfers 1:1 (same addresses)'
    else:
        rel = 'differs_from_O3DS'; diffs = []
        for k in ('text', 'ro', 'data', 'bss', 'dep', 'prio'):
            if e[k] != oe[k]: diffs.append(f'{k}:{oe[k]}->{e[k]}')
        a = set(e['svc']) - set(oe['svc']); b = set(oe['svc']) - set(e['svc'])
        if a: diffs.append('services_added:' + ','.join(sorted(a)))
        if b: diffs.append('services_removed:' + ','.join(sorted(b)))
        notes = ';'.join(diffs)
    rows.append([tid, e['name'], os.path.basename(d), ot if od else '', rel, len(code), (len(open(od + '/code.bin', 'rb').read()) if od else ''),
                 e['textaddr'], e['n3ds_mode'], e['cpu'], e['l2'], ' '.join(e['svc']), svcs_used(code), notes])
out = N + '/../symbols/N3DS_MODULE_INVENTORY.csv'
with open(out, 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['n3ds_tid', 'exheader_name', 'directory', 'o3ds_counterpart_tid', 'relation', 'code_size_n3ds', 'code_size_o3ds', 'text_addr', 'system_mode_new3ds', 'cpu_speed_new3ds', 'l2_cache', 'service_access(exheader)', 'svc_numbers_in_code(hex)', 'notes'])
    w.writerows(rows)
print(len(rows), collections.Counter(r[4] for r in rows))
