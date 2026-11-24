#!/usr/bin/env python3
"""Rename Spanish-labelled module directories to English names.
The module name comes from the NCCH ExHeader `Name` field (ground truth), NOT from the old Spanish label
(several old labels did not match the real module, e.g. 'FS-...-1502' is really 'am').
Writes RENAME_MAP.tsv (old<TAB>new) next to the renamed tree so it is reversible.
usage: rename_to_english.py <dir> [--apply]"""
import os, re, subprocess, sys
DESC = {'am':'Application-Manager','camera':'Camera','cfg':'System-Config','codec':'Audio-Codec','dsp':'DSP-Audio',
 'gpio':'GPIO','gsp':'GPU-Service','hid':'Buttons-and-Touch-Input','i2c':'I2C-Bus','mcu':'Microcontroller-Power',
 'pdn':'Power-and-Clock-Domains','ptm':'Battery-and-Pedometer','spi':'SPI-Bus','ac':'Network-Connection','csnd':'Sound',
 'http':'HTTP-Client','ssl':'SSL-Web-Security','socket':'Internet-Sockets','nim':'Updates-and-Downloads','nwm':'WiFi',
 'ps':'Process-Services-and-Crypto','friends':'Friend-List','ir':'Infrared','boss':'SpotPass','news':'News-Notifications',
 'ro':'Dynamic-Libraries-CRO','act':'Nintendo-Network-Accounts','ns':'Nintendo-Shell','cecd':'StreetPass','dlp':'Download-Play',
 'ndm':'Network-Daemon-Manager','mp':'Local-Multiplayer','nfc':'amiibo-NFC','mic':'Microphone','mvd':'Video-Decoder',
 'qtm':'Head-Tracking-New3DS','fs':'File-System','loader':'Loader','pm':'Process-Manager','sm':'Service-Manager','pxi':'PXI-Inter-Processor'}
def exname(d):
    p = os.path.join(d, 'exheader.bin')
    if not os.path.exists(p): return None
    t = subprocess.run(['ctrtool','-t','exheader',p],capture_output=True,text=True).stdout
    m = re.search(r'^Name:\s+(\S+)', t, re.M); return m.group(1) if m else None
def new_name(d):
    base = os.path.basename(d.rstrip('/'))
    m = re.search(r'([0-9A-Fa-f]{16})$', base)
    if not m: return None
    tid = m.group(1).upper()
    if tid.startswith('00040138'):
        return 'Firm-' + {'002': 'NATIVE_FIRM', '102': 'TWL_FIRM', '202': 'AGB_FIRM', '003': 'SAFE_MODE_FIRM'}.get(tid[-3:], 'FIRM') + '-' + tid
    n = exname(d)
    if not n: return None
    safe = '-SafeMode' if tid.endswith('03') else ''
    new3 = '-N3DS' if tid[8:10] == '20' else ''
    return f"Module-{n.upper()}-{DESC.get(n,'Unknown')}{safe}{new3}-{tid}"
if __name__ == '__main__':
    root, apply = sys.argv[1], '--apply' in sys.argv
    rows = []
    for e in sorted(os.listdir(root)):
        d = os.path.join(root, e)
        if os.path.isdir(d) and re.search(r'[0-9A-F]{16}$', e) and (e.startswith('Modulo-') or re.fullmatch(r'[0-9A-F]{16}', e)):
            nn = new_name(d)
            if nn and nn != e: rows.append((e, nn))
    with open(os.path.join(root, 'RENAME_MAP.tsv'), 'a') as f:
        for o, n in rows:
            print(o, '->', n)
            if apply: os.rename(os.path.join(root, o), os.path.join(root, n)); f.write(f'{o}\t{n}\n')
