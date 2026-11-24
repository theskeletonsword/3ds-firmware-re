#!/usr/bin/env python3
"""Cache radare2 function lists (aaa; aflj) for every N3DS code.bin (modules, FIRM modules, kernels). usage: r2_functions.py"""
import glob, json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
R = os.path.abspath(os.path.dirname(__file__) + '/..')
jobs = []
for d in sorted(glob.glob(R + '/decrypted_binaries/Module-*')):
    jobs.append((os.path.basename(d)[-16:], d + '/code.bin', 0x100000))
for m, base in (('fs', 0x100000), ('loader', 0x14000000), ('pm', 0x100000), ('pxi', 0x100000), ('sm', 0x100000)):
    jobs.append(('firm_' + m, f'{R}/decrypted_binaries/firm_modules/{m}/code.bin', base))
def run(j):
    name, path, base = j
    out = f'{R}/symbols/r2_functions/{name}.json'
    if os.path.exists(out): return name, 'cached'
    try:
        t = subprocess.run(['r2', '-q', '-a', 'arm', '-b', '32', '-m', hex(base), '-c', 'aaa;aflj', path], capture_output=True, text=True, timeout=900).stdout
        fl = json.loads(t[t.index('['):])
        json.dump([{'offset': f['offset'], 'size': f['size'], 'name': f['name']} for f in fl], open(out, 'w'))
        return name, len(fl)
    except Exception as e: return name, f'ERR {e}'
with ThreadPoolExecutor(8) as ex:
    for name, r in ex.map(run, jobs): print(name, r, flush=True)
