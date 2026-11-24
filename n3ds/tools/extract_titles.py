#!/usr/bin/env python3
"""Decrypt and unpack every non-sysmodule CIA (applications, applets, system data, shared data, TWL titles).

usage: extract_titles.py <updates_dir> <out_dir> [--name-map o3ds_names.tsv]

For each CIA  ->  <out_dir>/<Name>-<TitleID>/
    info.txt                       ctrtool CIA summary (title version, content list)
    content_<idx>_<id>/            one directory per CIA content
        ncch_info.txt              ctrtool NCCH summary (when the content is an NCCH)
        exheader.bin, exefs.bin, exefs_dir/ (code.bin decompressed, icon.bin, banner.bin...), romfs/ (full tree), plain_region.bin, logo.bin
        raw.bin                    only for contents that are not NCCH (TWL SRL, DB files): kept as decrypted by the CIA layer
    code.bin, exheader.bin         copies from the main executable content (when there is one)
Sysmodules (00040130*) and FIRM (00040138*) are handled by extract_n3ds.sh / decrypted_binaries and skipped here.
"""
import glob, os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def process(cia, out_root, names):
    tid = re.search(r'([0-9A-Fa-f]{16})', os.path.basename(cia)).group(1).upper()
    if tid.startswith(('00040130', '00040138')): return tid, 'skipped(sysmodule/firm)'
    name = names.get(tid) or names.get(tid[:8] + '00' + tid[10:]) or 'Title'
    d = os.path.join(out_root, f'{name}-{tid}'); tmp = d + '.tmp'
    if os.path.exists(os.path.join(d, 'info.txt')): return tid, 'cached'
    shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    info = run(['ctrtool', cia]).stdout
    open(os.path.join(tmp, 'info.txt'), 'w').write(info)
    run(['ctrtool', '-q', f'--contents={tmp}/c', cia])
    main = None; summary = []
    for cf in sorted(glob.glob(tmp + '/c.*')):
        m = re.match(r'.*/c\.(\d{4})\.([0-9a-f]{8})$', cf)
        idx, cid = m.groups(); cd = os.path.join(tmp, f'content_{idx}_{cid}'); os.makedirs(cd)
        with open(cf, 'rb') as f: head = f.read(0x200)
        if head[0x100:0x104] == b'NCCH':
            r = run(['ctrtool', '--intype=ncch', f'--exheader={cd}/exheader.bin', f'--exefs={cd}/exefs.bin', f'--exefsdir={cd}/exefs_dir',
                     '--decompresscode', f'--romfsdir={cd}/romfs', f'--logo={cd}/logo.bin', f'--plainrgn={cd}/plain_region.bin', cf])
            open(cd + '/ncch_info.txt', 'w').write(r.stdout + r.stderr)
            if os.path.exists(cd + '/exefs_dir/code.bin') and main is None: main = cd
            summary.append((idx, cid, 'NCCH', os.path.exists(cd + '/exefs_dir/code.bin'), os.path.isdir(cd + '/romfs')))
            os.remove(cf)
        else:
            shutil.move(cf, cd + '/raw.bin'); summary.append((idx, cid, 'RAW', False, False))
    if main:
        shutil.copy(main + '/exefs_dir/code.bin', tmp + '/code.bin'); shutil.copy(main + '/exheader.bin', tmp + '/exheader.bin')
    open(tmp + '/summary.txt', 'w').write('\n'.join(map(str, summary)) + '\n')
    shutil.rmtree(d, ignore_errors=True); os.rename(tmp, d)
    return tid, f'{len(summary)} contents, code={"yes" if main else "no"}'

if __name__ == '__main__':
    ups, out = sys.argv[1], sys.argv[2]
    names = {}
    if '--name-map' in sys.argv:
        for l in open(sys.argv[sys.argv.index('--name-map') + 1]):
            a, b = l.rstrip('\n').split('\t'); names[a] = b
    os.makedirs(out, exist_ok=True)
    cias = sorted(glob.glob(ups + '/*.cia'))
    with ThreadPoolExecutor(6) as ex:
        for tid, r in ex.map(lambda c: process(c, out, names), cias): print(tid, r, flush=True)
