#!/usr/bin/env python3
"""Extract IPC command specifications (command IDs, parameter counts, 32-bit request headers, service ports)
from libctru (source/services/*.c, source/srv.c, source/errf.c) into n3ds/symbols/ipc/LIBCTRU_IPC_SPEC.csv.

Searches /home/skels/libctru/libctru or /tmp/libctru. If neither is present and LIBCTRU_IPC_SPEC.csv already
exists, keeps the existing CSV so downstream tools work standalone.
"""
import csv, glob, os, re, sys

R = os.path.abspath(os.path.dirname(__file__) + '/../..')
OUT_CSV = os.path.join(R, 'n3ds/symbols/ipc/LIBCTRU_IPC_SPEC.csv')

FILE_MAP = {
    'services/ac.c': ('ac', ['ac:u', 'ac:i']),
    'services/act.c': ('act', ['act:u', 'act:a']),
    'services/am.c': ('am', ['am:net', 'am:u', 'am:sys', 'am:app']),
    'services/ampxi.c': ('am', ['pxi:am9']),
    'services/apt.c': ('ns', ['APT:U', 'APT:S', 'APT:A']),
    'services/ns.c': ('ns', ['ns:s', 'ns:p', 'ns:c']),
    'services/boss.c': ('boss', ['boss:U', 'boss:P']),
    'services/cam.c': ('camera', ['cam:u', 'cam:s', 'cam:c', 'cam:q']),
    'services/y2r.c': ('camera', ['y2r:u']),
    'services/cdcchk.c': ('codec', ['cdc:CHK']),
    'services/cfgnor.c': ('cfg', ['cfg:nor']),
    'services/cfgu.c': ('cfg', ['cfg:u', 'cfg:s', 'cfg:i']),
    'services/csnd.c': ('csnd', ['csnd:SND']),
    'services/dsp.c': ('dsp', ['dsp::DSP']),
    'services/frd.c': ('friends', ['frd:u', 'frd:a']),
    'services/frdn.c': ('friends', ['frd:n']),
    'services/fs.c': ('fs', ['fs:USER']),
    'services/fspxi.c': ('fs', ['pxi:fs0', 'pxi:fs1', 'pxi:fsB', 'pxi:fsR']),
    'services/fsreg.c': ('fs', ['fs:REG']),
    'services/gspgpu.c': ('gsp', ['gsp::Gpu']),
    'services/gsplcd.c': ('gsp', ['gsp::Lcd']),
    'services/hid.c': ('hid', ['hid:USER', 'hid:SPVR']),
    'services/httpc.c': ('http', ['http:C']),
    'services/ir.c': ('ir', ['ir:u', 'ir:USER']),
    'services/irrst.c': ('ir', ['ir:rst']),
    'services/loader.c': ('loader', ['ldr:ro', 'Loader']),
    'services/mcucam.c': ('mcu', ['mcu::CAM']),
    'services/mcucdc.c': ('mcu', ['mcu::CDC']),
    'services/mcugpu.c': ('mcu', ['mcu::GPU']),
    'services/mcuhid.c': ('mcu', ['mcu::HID']),
    'services/mcuhwc.c': ('mcu', ['mcu::HWC']),
    'services/mcunwm.c': ('mcu', ['mcu::NWM']),
    'services/mcupls.c': ('mcu', ['mcu::PLS']),
    'services/mcurtc.c': ('mcu', ['mcu::RTC']),
    'services/mcusnd.c': ('mcu', ['mcu::SND']),
    'services/mic.c': ('mic', ['mic:u']),
    'services/mvd.c': ('mvd', ['mvd:STD']),
    'services/ndm.c': ('ndm', ['ndm:u', 'ndm:s', 'ndm:a']),
    'services/news.c': ('news', ['news:u', 'news:s']),
    'services/nfc.c': ('nfc', ['nfc:u', 'nfc:m']),
    'services/nim.c': ('nim', ['nim:u', 'nim:s', 'nim:aoc']),
    'services/nwmext.c': ('nwm', ['nwm::EXT']),
    'services/uds.c': ('nwm', ['nwm::UDS']),
    'services/pmapp.c': ('pm', ['pm:app']),
    'services/pmdbg.c': ('pm', ['pm:dbg']),
    'services/ps.c': ('ps', ['ps:ps']),
    'services/ptmgets.c': ('ptm', ['ptm:gets']),
    'services/ptmplays.c': ('ptm', ['ptm:play']),
    'services/ptmsets.c': ('ptm', ['ptm:sets']),
    'services/ptmsysm.c': ('ptm', ['ptm:sysm']),
    'services/ptmu.c': ('ptm', ['ptm:u']),
    'services/pxidev.c': ('pxi', ['pxi:dev']),
    'services/pxipm.c': ('pxi', ['pxi:pm']),
    'services/qtm.c': ('qtm', ['qtm:u', 'qtm:s', 'qtm:sp']),
    'services/qtmc.c': ('qtm', ['qtm:c']),
    'services/srvpm.c': ('sm', ['srv:pm']),
    'services/sslc.c': ('ssl', ['ssl:C']),
    'srv.c': ('sm', ['srv:']),
    'errf.c': ('errdisp', ['err:f']),
}

def find_libctru():
    for cand in (sys.argv[1:] + ['/tmp/libctru', '/home/skels/libctru/libctru', '/home/skels/libctru']):
        if os.path.isdir(os.path.join(cand, 'source/services')):
            return cand
        if os.path.isdir(os.path.join(cand, 'libctru/source/services')):
            return os.path.join(cand, 'libctru')
    return None

def main():
    root = find_libctru()
    if not root:
        if os.path.exists(OUT_CSV):
            print(f'libctru source tree not mounted; using existing {OUT_CSV}')
            return
        sys.exit('error: libctru source tree not found and LIBCTRU_IPC_SPEC.csv does not exist')
    src_root = os.path.join(root, 'source')
    rows = []
    fn_re = re.compile(r'(?:static\s+)?(?:Result|void|int|u32|s32|u64|u16|u8|bool|Handle|ssize_t|long|struct\s+\w+\s*\*)\s+([A-Za-z0-9_]+)\s*\([^;{]*\)\s*\{')
    hdr_re = re.compile(r'IPC_MakeHeader\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)|cmdbuf\[0\]\s*=\s*(0x[0-9a-fA-F]+)\s*;')
    for p in sorted(glob.glob(src_root + '/**/*.c', recursive=True)):
        rel = os.path.relpath(p, src_root)
        if rel.startswith('services/soc/'):
            mod, ports = ('socket', ['soc:U'])
        elif rel in FILE_MAP:
            mod, ports = FILE_MAP[rel]
        else:
            continue
        t = open(p, encoding='utf-8', errors='replace').read()
        for m in fn_re.finditer(t):
            fn = m.group(1)
            start = m.end()
            depth = 1; i = start
            while i < len(t) and depth > 0:
                if t[i] == '{': depth += 1
                elif t[i] == '}': depth -= 1
                i += 1
            body = t[start:i]
            for hm in hdr_re.finditer(body):
                if hm.group(4):
                    hdr = int(hm.group(4), 16)
                    cid, np, tp = (hdr >> 16) & 0xFFFF, (hdr >> 6) & 0x3F, hdr & 0x3F
                else:
                    cid, np, tp = int(hm.group(1), 0), int(hm.group(2), 0), int(hm.group(3), 0)
                    hdr = (cid << 16) | (np << 6) | tp
                port = ports[0]
                if mod == 'qtm' and rel == 'services/qtm.c':
                    port = 'qtm:sp' if fn.startswith('QTMSP_') else 'qtm:s' if fn.startswith('QTMS_') else 'qtm:u'
                elif mod == 'cfg' and rel == 'services/cfgu.c':
                    port = 'cfg:i' if cid >= 0x800 else 'cfg:s' if cid >= 0x400 else 'cfg:u'
                elif mod == 'am' and rel == 'services/am.c':
                    port = 'am:app' if cid >= 0x1000 else 'am:u/net/sys'
                elif mod == 'act':
                    port = 'act:a' if fn.startswith('ACTA_') or cid >= 0x400 else 'act:u'
                elif mod == 'ac':
                    port = 'ac:i' if fn.startswith('ACI_') or cid >= 0x400 else 'ac:u'
                elif mod == 'boss':
                    port = 'boss:P' if fn.startswith('BOSSP_') or cid >= 0x400 else 'boss:U'
                elif mod == 'friends' and rel == 'services/frd.c':
                    port = 'frd:a' if fn.startswith('FRDA_') or cid >= 0x400 else 'frd:u'
                elif mod == 'news':
                    port = 'news:s' if fn.startswith('NEWSS_') or cid > 1 else 'news:u'
                elif mod == 'nfc':
                    port = 'nfc:m' if fn.startswith('NFCM_') or cid >= 0x400 else 'nfc:u'
                elif mod == 'nim':
                    port = 'nim:aoc' if fn.startswith('NIMAOC_') else 'nim:s' if fn.startswith('NIMS_') else 'nim:u'
                rows.append([rel, mod, port, fn, f'0x{cid:04X}', np, tp, f'0x{hdr:08X}'])
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['file', 'module', 'port', 'func', 'cmd_id', 'normal_params', 'translate_params', 'request_header'])
        w.writerows(rows)
    print(f'Extracted {len(rows)} libctru IPC commands across {len({r[1] for r in rows})} modules -> {OUT_CSV}')

if __name__ == '__main__':
    main()
