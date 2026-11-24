#!/usr/bin/env python3
"""O3DS -> N3DS symbol transfer by byte matching.

Levels (byte evidence only, nothing invented):
  exact                 function bytes identical and unique in the N3DS binary
  probable_by_transfer  identical after masking position-dependent operands
                        (bl/b, ldr/adr literal, address-like literal-pool words) and unique;
                        or several candidates resolved by the shift of neighbouring anchors
  unresolved            no unique match

usage: transfer_syms.py --old OLD.bin --old-base 0x.. --new NEW.bin --new-base 0x.. --sym O3DS.sym --out PREFIJO [--tag nombre]
"""
import re, sys, argparse, bisect, csv, struct

LINE = re.compile(r'^0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)\s+(\w+)\s+(\S+)\s*(.*)$')

def parse_sym(p):
    out = []
    for l in open(p, encoding='utf-8', errors='replace'):
        m = LINE.match(l.rstrip('\n'))
        if m:
            out.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4), m.group(5)))
    return out

def is_addr_word(w):
    t = w >> 24
    return t in (0x08, 0x09, 0x1F, 0x1E, 0x10, 0x18, 0xFF, 0xFE, 0x20, 0x00) and w >= 0x00100000 or (w >> 20) == 0x001 and False

def mask_arm(buf):
    """Per aligned 4-byte word mask (ARM mode)."""
    b = bytearray(buf)
    for i in range(0, len(b) - 3, 4):
        w = struct.unpack_from('<I', b, i)[0]
        nw = w
        top = (w >> 25) & 7
        if top == 0b101:                              # B/BL/BLX(imm)
            nw = w & 0xFF000000
        elif (w & 0x0C5F0000) == 0x041F0000:          # LDR literal (Rn=PC)
            nw = w & 0xFFFFF000
        elif (w & 0x0FFF0000) in (0x028F0000, 0x024F0000):  # ADD/SUB rX,pc,#imm (ADR)
            nw = w & 0xFFFFF000
        elif w >= 0x08000000 and (w >> 24) in (0x08, 0x09, 0x1F, 0x1E, 0x10, 0xFF, 0x18, 0x20, 0x01) :
            nw = 0
        if nw != w:
            struct.pack_into('<I', b, i, nw)
    return b

def mask_thumb(buf):
    """Per halfword mask (Thumb / Thumb-2 BL), applied at every even position."""
    b = bytearray(buf)
    for i in range(0, len(b) - 1, 2):
        h = b[i] | (b[i + 1] << 8)
        nh = h
        if 0xF000 <= h <= 0xF7FF:        # BL/BLX hi
            nh = h & 0xF800
        elif 0xF800 <= h <= 0xFFFF:      # BL lo
            nh = h & 0xF800
        elif 0xE800 <= h <= 0xEFFF:      # BLX lo
            nh = h & 0xF800
        elif 0x4800 <= h <= 0x4FFF:      # LDR rX,[pc,#imm8]
            nh = h & 0xFF00
        elif 0xA000 <= h <= 0xA7FF:      # ADR
            nh = h & 0xFF00
        elif 0xE000 <= h <= 0xE7FF:      # B uncond
            nh = h & 0xF800
        elif 0xD000 <= h <= 0xDEFF:      # B cond
            nh = h & 0xFF00
        if nh != h:
            b[i] = nh & 0xFF; b[i + 1] = nh >> 8
    # literal-pool words that look like addresses (4-aligned)
    for i in range(0, len(b) - 3, 4):
        w = struct.unpack_from('<I', b, i)[0]
        if w >= 0x08000000 and (w >> 24) in (0x08, 0x09, 0x1F, 0x1E, 0x10, 0xFF, 0x18, 0x20, 0x01):
            struct.pack_into('<I', b, i, 0)
    return b

def find_all(hay, needle, step, limit=8):
    res = []; s = 0
    while len(res) < limit:
        j = hay.find(needle, s)
        if j < 0: break
        if j % step == 0: res.append(j)
        s = j + 1
    return res

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old'); ap.add_argument('--old-base'); ap.add_argument('--new'); ap.add_argument('--new-base')
    ap.add_argument('--sym'); ap.add_argument('--out'); ap.add_argument('--tag', default='')
    ap.add_argument('--keep-base', action='store_true')
    ap.add_argument('--min-masked', type=int, default=16)
    ap.add_argument('--alias', default=None, help='alternate base (e.g. 0xFFF00000): addresses >= alias map to offset=addr-alias')
    a = ap.parse_args()
    hdr = open(a.sym, encoding='utf-8', errors='replace').read(600)
    mb = re.search(r'Load \.text: 0x([0-9A-Fa-f]+)', hdr)
    if mb and not a.keep_base:
        a.old_base = a.new_base = '0x' + mb.group(1)
    ob, nb = int(a.old_base, 16), int(a.new_base, 16)
    al = int(a.alias, 16) if a.alias else None
    def o_off(ea): return ea - al if (al and ea >= al) else ea - ob
    def n_addr(j, ea): return j + al if (al and ea >= al) else j + nb
    O = open(a.old, 'rb').read(); N = open(a.new, 'rb').read()
    syms = parse_sym(a.sym)
    syms.sort()
    addrs = [s[0] for s in syms]
    NA, NT = mask_arm(N), mask_thumb(N)
    OA, OT = mask_arm(O), mask_thumb(O)
    rows = []; anchors = []   # (old_addr, shift)
    identical = (O == N and ob == nb)
    res = {}
    for idx, (ea, sz, conf, name, note) in enumerate(syms):
        eff = sz
        probe = 'symbol_size'
        if identical:
            res[idx] = ('exact', ea, 'whole_binary_identical(same code.bin sha256, same base)', probe); continue
        if sz == 0:
            nxt = addrs[idx + 1] if idx + 1 < len(addrs) else ea + 32
            eff = min(max(nxt - ea, 0), 64) or 16
            probe = 'estimated_size(<=64)'
        off = o_off(ea)
        if off < 0 or off + eff > len(O): res[idx] = ('unresolved', None, 'out_of_O3DS_range', probe); continue
        raw = O[off:off + eff]
        # 1) exact
        c = [j for j in find_all(N, raw, 2)] if eff >= 4 else []
        if len(c) == 1 and eff >= 8:
            res[idx] = ('exact', n_addr(c[0], ea), 'identical_bytes_unique', probe); anchors.append((ea, n_addr(c[0], ea) - ea)); continue
        # 2) masked (ARM and Thumb)
        cand = {}
        for mode, OM, NM, step in (('arm', OA, NA, 4), ('thumb', OT, NT, 2)):
            m = OM[off:off + eff]
            if len(m) >= 4:
                for j in find_all(NM, bytes(m), step): cand.setdefault(j, mode)
                cl = sorted(cand)
        if len(cl) == 1 and eff >= a.min_masked:
            res[idx] = ('probable_by_transfer', n_addr(cl[0], ea), f'masked_bytes_unique({cand[cl[0]]},{eff}B)', probe)
            anchors.append((ea, n_addr(cl[0], ea) - ea)); continue
        res[idx] = ('pendiente', cl, cand, probe)
    # 3) resolve ambiguous / short ones by anchors
    anchors.sort(); aa = [x[0] for x in anchors]
    for idx, (ea, sz, conf, name, note) in enumerate(syms):
        r = res[idx]
        if r[0] != 'pendiente': continue
        cl = r[1]
        if not cl: res[idx] = ('unresolved', None, 'no_match', r[3]); continue
        k = bisect.bisect_left(aa, ea)
        near = [anchors[i] for i in (k - 1, k) if 0 <= i < len(anchors)]
        if not near: res[idx] = ('unresolved', None, 'ambiguous_no_anchors', r[3]); continue
        best = None
        for j in cl:
            for (ae, sh) in near:
                d = abs(n_addr(j, ea) - (ea + sh))
                if best is None or d < best[0]: best = (d, j, sh)
        if best[0] <= 0x40 and len(cl) <= 8:
            res[idx] = ('probable_by_transfer', n_addr(best[1], ea), f'{len(cl)}_candidates_resolved_by_anchor(delta={best[0]})', r[3])
        else:
            res[idx] = ('unresolved', None, f'{len(cl)}_candidates_no_nearby_anchor', r[3])
    # output
    fn = a.out
    stats = {}
    with open(fn + '.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['ea_n3ds', 'size', 'symbol_name', 'ea_o3ds', 'o3ds_equivalent', 'o3ds_confidence', 'confidence_level', 'technical_evidence'])
        for idx, (ea, sz, conf, name, note) in enumerate(syms):
            lvl, nea, ev, probe = res[idx]
            stats[lvl] = stats.get(lvl, 0) + 1
            if nea is None:
                w.writerow(['', f'0x{sz:X}', name, f'0x{ea:08X}', name, conf, lvl, ev]); continue
            nn = name
            oldhex = f'{ea:08x}'; oldhex2 = f'{ea:x}'
            newname = re.sub(r'(?i)0x' + oldhex, f'0x{nea:08X}', nn)
            newname = re.sub(r'(?i)_' + oldhex2 + r'$', f'_{nea:x}', newname)
            if nea == ea: newname = nn
            ev2 = ev + ('' if newname == nn else ';name_readdressed')
            w.writerow([f'0x{nea:08X}', f'0x{sz:X}', newname, f'0x{ea:08X}', name, conf, lvl, ev2 + ';' + probe])
    print(a.tag, 'total', len(syms), stats)
    # O3DS-style .r2 + .sym (resolved only)
    with open(fn + '.r2', 'w') as r2, open(fn + '.sym', 'w') as sy:
        sy.write(f'# N3DS symbols transferred from O3DS ({a.tag}); levels: exact/probable_by_transfer\n')
        sy.write('Address         Size    Confidence                  Name\n')
        for row in csv.DictReader(open(fn + '.csv')):
            if row['ea_n3ds']:
                sy.write(f"{row['ea_n3ds']:<14}  {row['size']:<7} {row['confidence_level']:<27} {row['symbol_name']}\n")
                r2.write(f"f {row['symbol_name']} @ {row['ea_n3ds']}\n")

if __name__ == '__main__':
    main()
