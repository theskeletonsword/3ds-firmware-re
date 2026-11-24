#!/usr/bin/env python3
"""Recover IPC command tables from both bulk-decompiled C (decompiled/*.c) AND Thumb switch tables in code.bin,
and cross-reference every dispatcher and command case against libctru (symbols/ipc/LIBCTRU_IPC_SPEC.csv).

Supports:
  1. ARM decompiled C dispatchers:
     - `switch(*cmdbuf >> 0x10)`
     - `uVar = *cmdbuf >> 0x10; ... switch(uVar)` and `switch(uVar - DAT_xxxxxxxx)` (resolving DAT_ literals from code.bin)
     - `if (uVar == N)` command comparison chains inside the dispatcher
  2. Thumb code.bin switch dispatchers (invisible to Ghidra's switch pattern matcher):
     - `__ARM_common_switch8` (`01c05ee5 0c0053e1 0c30de27 0330de37 83c08ee0 1cff2fe1`) 8-bit branch tables
     - 16-bit inline Thumb switch (`add rX, pc; ldrh rX, [rX, #4]; lsls rX, rX, #1; add pc, rX`)
     - Follows 2-byte unconditional Thumb branch trampolines (`b <actual_case_ea>`) and tracks `r1=cmd_id, r2=normal_params, r3=translate_params`
       into the per-dispatcher header-validator / reply-builder helpers to recover exact 16-bit command IDs (including 0x401+, 0x801+, 0x1001+),
       exact 32-bit request & reply headers, and the command handler function called by each case.
  3. Port-level matching against libctru (`LIBCTRU_IPC_SPEC.csv`): identifies which service port each dispatcher serves and maps each case
     to its official libctru function name (`QTMU_*`, `QTMS_*`, `QTMSP_*`, `QTMC_*`, `MVDSTD_*`, `Y2RU_*`, `CAMU_*`, `NFC_*`, `FSUSER_*`, etc.).

Outputs:
  - n3ds/symbols/ipc/IPC_COMMANDS_FROM_DECOMPILATION.csv
  - n3ds/docs/decompiled_notes/IPC_TABLES.md
"""
import collections, csv, glob, json, os, re, struct, sys

R = os.path.abspath(os.path.dirname(__file__) + '/../..')
SPEC_CSV = os.path.join(R, 'n3ds/symbols/ipc/LIBCTRU_IPC_SPEC.csv')
SW8 = bytes.fromhex('01c05ee50c0053e10c30de270330de3783c08ee01cff2fe1')

def u32(b, o):
    return struct.unpack_from('<I', b, o)[0] if b and 0 <= o <= len(b) - 4 else None

def load_libctru_profiles():
    """Build port-level profiles per module for accurate dispatcher -> service port + function matching."""
    if not os.path.exists(SPEC_CSV):
        import extract_libctru_spec
        extract_libctru_spec.main()
    raw = list(csv.DictReader(open(SPEC_CSV)))
    # Build profiles: (module, profile_port_name) -> {cmd_int: [entry, ...]}
    profiles = collections.defaultdict(lambda: collections.defaultdict(list))
    mod_profiles = collections.defaultdict(list)
    for r in raw:
        cid = int(r['cmd_id'], 16)
        e = {
            'file': r['file'], 'module': r['module'], 'port': r['port'], 'func': r['func'],
            'cmd_id': r['cmd_id'], 'cmd_int': cid,
            'normal_params': int(r['normal_params']), 'translate_params': int(r['translate_params']),
            'request_header': int(r['request_header'], 16), 'request_header_hex': r['request_header'],
        }
        mod = r['module']
        port = r['port']
        # For hierarchical services where a higher port inherits lower port commands (qtm:sp -> qtm:s -> qtm:u, cfg:i -> cfg:s -> cfg:u, etc.)
        if mod == 'qtm' and r['file'] == 'services/qtm.c':
            if port == 'qtm:u':
                for p in ('qtm:u', 'qtm:s', 'qtm:sp'): profiles[(mod, p)][cid].append(e)
            elif port == 'qtm:s':
                for p in ('qtm:s', 'qtm:sp'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'qtm:sp')][cid].append(e)
        elif mod == 'cfg' and r['file'] == 'services/cfgu.c':
            if port == 'cfg:u':
                for p in ('cfg:u', 'cfg:s', 'cfg:i'): profiles[(mod, p)][cid].append(e)
            elif port == 'cfg:s':
                for p in ('cfg:s', 'cfg:i'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'cfg:i')][cid].append(e)
        elif mod == 'ac':
            if port == 'ac:u':
                for p in ('ac:u', 'ac:i'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'ac:i')][cid].append(e)
        elif mod == 'act':
            if port == 'act:u':
                for p in ('act:u', 'act:a'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'act:a')][cid].append(e)
        elif mod == 'boss':
            if port == 'boss:U':
                for p in ('boss:U', 'boss:P'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'boss:P')][cid].append(e)
        elif mod == 'friends' and r['file'] == 'services/frd.c':
            if port == 'frd:u':
                for p in ('frd:u', 'frd:a'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'frd:a')][cid].append(e)
        elif mod == 'nfc':
            if port == 'nfc:u':
                for p in ('nfc:u', 'nfc:m'): profiles[(mod, p)][cid].append(e)
            else:
                profiles[(mod, 'nfc:m')][cid].append(e)
        elif mod == 'ptm' and port in ('ptm:u', 'ptm:gets', 'ptm:sets', 'ptm:play', 'ptm:sysm'):
            profiles[(mod, port)][cid].append(e)
            if port == 'ptm:u':
                for p in ('ptm:sysm', 'ptm:gets', 'ptm:sets', 'ptm:play'):
                    profiles[(mod, p)][cid].append(e)
        else:
            profiles[(mod, port)][cid].append(e)
        # MVD also hosts y2r2:u which uses the y2r:u protocol from services/y2r.c
        if r['file'] == 'services/y2r.c':
            e2 = dict(e, module='mvd', port='y2r2:u')
            profiles[('mvd', 'y2r2:u')][cid].append(e2)
    for (mod, port) in sorted(profiles.keys()):
        mod_profiles[mod].append(port)
    return profiles, mod_profiles

def match_dispatcher_port(mod, case_rows, profiles, mod_profiles):
    """case_rows: list of dicts with cmd_int, req_hdr_int, reply_hdr_int."""
    ports = mod_profiles.get(mod, [])
    if not ports:
        return '', {}
    best_port = ''
    best_score = -1
    for port in ports:
        cmap = profiles[(mod, port)]
        score = 0
        matched_ids = 0
        for c in case_rows:
            cid = c['cmd_int']
            if cid not in cmap:
                continue
            matched_ids += 1
            entries = cmap[cid]
            req = c.get('req_hdr_int')
            if req is not None and any(e['request_header'] == req and (e['normal_params'] > 0 or e['translate_params'] > 0) for e in entries):
                score += 15
            elif req is not None and any(e['request_header'] == req for e in entries):
                score += 6
            elif req is not None and mod == 'mvd':
                score -= 5
            else:
                score += 2
            # Disambiguate qtm:u (cmd 1 reply header 0x00010340 = 13 words) vs qtm:c (cmd 1 reply header 0x00010040 = 1 word)
            rep = c.get('reply_hdr_int')
            if mod == 'qtm' and cid == 1 and rep is not None:
                if port in ('qtm:u', 'qtm:s', 'qtm:sp') and rep == 0x00010340:
                    score += 30
                elif port == 'qtm:c' and rep == 0x00010040:
                    score += 30
        if matched_ids == 0:
            continue
        if cmap and case_rows:
            max_c = max(c['cmd_int'] for c in case_rows)
            max_f = max(cmap.keys())
            if max_c == max_f:
                score += 15
            elif abs(max_c - max_f) <= 2 and (max_c >> 8) == (max_f >> 8):
                score += 6
            # Penalize profiles with higher command ranges (0x400+, 0x800+) when dispatcher doesn't have them
            if (max_f >> 8) != (max_c >> 8):
                score -= 8
        if score > best_score:
            best_score = score
            best_port = port
    if best_score < 3:
        return '', {}
    return best_port, profiles[(mod, best_port)]

def pick_libctru_func(cmap, cid, req_hdr_int):
    if cid not in cmap:
        return '', ''
    entries = cmap[cid]
    if req_hdr_int is not None:
        exact = [e for e in entries if e['request_header'] == req_hdr_int]
        if exact:
            entries = exact
    funcs = []
    for e in entries:
        if e['func'] not in funcs:
            funcs.append(e['func'])
    return '/'.join(funcs), entries[0]['request_header_hex']

def module_short_name(binary_rel):
    bn = os.path.basename(binary_rel)
    if bn.startswith('Module-'):
        return bn.split('-')[1].lower()
    if 'firm_modules/' in binary_rel:
        return bn.lower()
    return ''

def load_decomp_func_map(cdir):
    """Map integer function EA (with Thumb bit stripped) -> C function name from decompiled/*.c headers or index.tsv."""
    fmap = {}
    idx = os.path.join(cdir, 'index.tsv')
    if os.path.exists(idx):
        for line in open(idx, errors='replace'):
            p = line.strip().split('\t')
            if len(p) >= 2 and p[0].startswith('0x'):
                try:
                    fmap[int(p[0], 16) & ~1] = p[1]
                except ValueError:
                    pass
    return fmap

def decode_b16(b, pos, base):
    if pos < 0 or pos + 2 > len(b): return None
    h = struct.unpack_from('<H', b, pos)[0]
    if (h & 0xF800) == 0xE000:
        imm = h & 0x7FF
        if imm & 0x400: imm -= 0x800
        return base + pos + 4 + imm * 2
    return None

def decode_bl16(b, pos, base):
    if pos < 0 or pos + 4 > len(b): return None
    h1, h2 = struct.unpack_from('<HH', b, pos)
    if (h1 & 0xF800) == 0xF000 and (h2 & 0xE800) in (0xE800, 0xF800):
        s = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; j1 = (h2 >> 13) & 1; j2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
        i1 = ~(j1 ^ s) & 1; i2 = ~(j2 ^ s) & 1
        off = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if s: off -= (1 << 25)
        pc = base + pos + 4
        return ((pc + off) & ~3) if (h2 & 0x1000) == 0 else (pc + off)
    return None

def find_base_cmd(B, o, base):
    for back in range(2, 18, 2):
        if o - back < 0: break
        h = struct.unpack_from('<H', B, o - back)[0]
        if (h & 0xF800) == 0x4800:
            lit_ea = ((base + o - back + 4) & ~3) + (h & 0xFF) * 4
            v = u32(B, lit_ea - base)
            if v is not None:
                if v >= 0xFFFF0000: return (1 << 32) - v
                if 0x40 <= v <= 0x2000: return v
        elif (h & 0xFE00) == 0x1E00:
            imm3 = (h >> 6) & 7
            if imm3 > 0: return imm3
        elif (h & 0xF800) == 0x3800:
            imm8 = h & 0xFF
            if imm8 > 0: return imm8
    return 0

def scan_thumb_case_body(B, cea, nxt, base):
    regs = {}
    bls = []
    pos = cea - base
    steps = 0
    while 0 <= pos < min(nxt - base, len(B) - 2) and steps < 80:
        steps += 1
        t = decode_bl16(B, pos, base)
        if t:
            bls.append((t, dict(regs)))
            pos += 4
            continue
        tb = decode_b16(B, pos, base)
        if tb is not None:
            prev_h = struct.unpack_from('<H', B, pos - 2)[0] if pos >= 2 else 0
            if 0xD000 <= (prev_h & 0xFF00) <= 0xDD00 and (prev_h & 0xFF) == 0:
                pos += 2
                continue
            if tb > base + pos and steps < 40:
                pos = tb - base
                nxt = max(nxt, tb + 40)
                continue
            break
        h = struct.unpack_from('<H', B, pos)[0]
        if (h & 0xFF00) == 0xBD00:
            break
        if (h & 0xF800) == 0x2000:
            regs[(h >> 8) & 7] = h & 0xFF
        elif (h & 0xF800) == 0x4800:
            lit_ea = ((base + pos + 4) & ~3) + (h & 0xFF) * 4
            v = u32(B, lit_ea - base)
            if v is not None: regs[(h >> 8) & 7] = v
        elif (h & 0xFFC0) == 0x0000:
            rd = h & 7; rm = (h >> 3) & 7
            if rm in regs: regs[rd] = regs[rm]
        elif (h & 0xFF00) == 0x4600:
            rd = (h & 7) | ((h >> 4) & 8); rm = (h >> 3) & 0xF
            if rm in regs: regs[rd] = regs[rm]
        elif (h & 0xFE00) == 0x1C00:
            rd = h & 7; rn = (h >> 3) & 7; imm3 = (h >> 6) & 7
            if rn in regs: regs[rd] = (regs[rn] + imm3) & 0xFFFFFFFF
        elif (h & 0xF800) == 0x3000:
            rd = (h >> 8) & 7
            if rd in regs: regs[rd] = (regs[rd] + (h & 0xFF)) & 0xFFFFFFFF
        pos += 2
    return bls

def extract_arm_dispatchers(cdir, B, base):
    """Extract ARM dispatchers from decompiled/*.c (including multi-switch and if-chain command checks)."""
    out = []
    def resolve_dat(s):
        if not s: return None
        m = re.match(r'^DAT_([0-9a-fA-F]+)$', s.strip())
        if m and B:
            return u32(B, int(m.group(1), 16) - base)
        try: return int(s, 0)
        except ValueError: return None

    for cf in sorted(glob.glob(cdir + '/*.c')):
        t = open(cf, errors='replace').read()
        if 'coproc_movefrom_User_R_Thread_and_Process_ID' not in t or '>> 0x10' not in t:
            continue
        fname = re.search(r'^// (\S+) @ (0x[0-9a-f]+)', t, re.M)
        if not fname:
            continue
        fn, fea = fname.group(1), f"0x{int(fname.group(2), 16):08x}"
        cases = {}
        # 1. Original direct switch(*puVar >> 0x10) OR multi-line uVar = *puVar >> 0x10; switch(uVar [- DAT_xxx])
        for sm in re.finditer(r'switch\(([^\n\)]+)\)\s*\{', t):
            expr = sm.group(1)
            base_add = 0
            m_sub = re.search(r'-\s*(DAT_[0-9a-fA-F]+|0x[0-9a-fA-F]+|\d+)', expr)
            if not m_sub:
                vname = expr.strip()
                m_def = re.search(rf'\b{re.escape(vname)}\s*=\s*\w+\s*-\s*(DAT_[0-9a-fA-F]+|0x[0-9a-fA-F]+|\d+)', t)
                if m_def: m_sub = m_def
            if m_sub:
                v = resolve_dat(m_sub.group(1))
                if v is not None and 0 < v <= 0x2000: base_add = v
            body = t[sm.end():]
            parts = re.split(r'\n\s*case\s+(0x[0-9a-fA-F]+|\d+):', '\n' + body)
            for i in range(1, len(parts) - 1, 2):
                cid = base_add + int(parts[i], 0)
                if cid < 0 or cid > 0x2000: continue
                blk = parts[i + 1].split('\n  default:')[0].split('\n  }')[0]
                call = re.search(r'\b((?:FUN|[A-Za-z_][A-Za-z0-9_]*)_?[0-9a-f]{6,8}|[A-Za-z_][A-Za-z0-9_]{5,})\s*\(', blk)
                reply = re.search(r'\*\s*\w+\s*=\s*(0x[0-9a-fA-F]+|DAT_[0-9a-f]+)\s*;', blk)
                nargs = len(set(re.findall(r'\+\s*(0x[0-9a-f]+|\d+)\)', blk)))
                rep_str = reply.group(1) if reply else ''
                rep_v = resolve_dat(rep_str)
                if rep_v is not None and rep_str.startswith('DAT_'):
                    rep_str = f'0x{rep_v:08X} ({rep_str})'
                cases.setdefault(cid, {
                    'cmd_int': cid, 'first_call': call.group(1) if call else '',
                    'reply_str': rep_str, 'reply_hdr_int': rep_v,
                    'nargs': nargs, 'req_hdr_int': None, 'req_hdr_str': '',
                })
        # 2. Additional if (uVar == N) checks on the command variable inside the same dispatcher
        m_var = re.search(r'\b(\w+)\s*=\s*\*?\w+(?:\[0\])?\s*>>\s*0x10\s*;', t)
        if m_var and cases:
            cvar = m_var.group(1)
            var_bases = {cvar: 0}
            for md in re.finditer(rf'\b(\w+)\s*=\s*{re.escape(cvar)}\s*-\s*(DAT_[0-9a-fA-F]+|0x[0-9a-fA-F]+|\d+)\s*;', t):
                v = resolve_dat(md.group(2))
                if v is not None and 0 < v <= 0x2000: var_bases[md.group(1)] = v
            for vname, badd in var_bases.items():
                for im in re.finditer(rf'if\s*\(\s*{re.escape(vname)}\s*==\s*(DAT_[0-9a-fA-F]+|0x[0-9a-fA-F]+|\d+)\s*\)\s*\{{', t):
                    v = resolve_dat(im.group(1))
                    if v is None: continue
                    cid = badd + v
                    if cid <= 0 or cid > 0x2000: continue
                    blk = t[im.end():im.end() + 600].split('\n    }')[0].split('\n  }')[0]
                    call = re.search(r'\b((?:FUN|[A-Za-z_][A-Za-z0-9_]*)_?[0-9a-f]{6,8}|[A-Za-z_][A-Za-z0-9_]{5,})\s*\(', blk)
                    reply = re.search(r'\*\s*\w+\s*=\s*(0x[0-9a-fA-F]+|DAT_[0-9a-f]+)\s*;', blk)
                    nargs = len(set(re.findall(r'\+\s*(0x[0-9a-f]+|\d+)\)', blk)))
                    rep_str = reply.group(1) if reply else ''
                    rep_v = resolve_dat(rep_str)
                    if rep_v is not None and rep_str.startswith('DAT_'):
                        rep_str = f'0x{rep_v:08X} ({rep_str})'
                    cases.setdefault(cid, {
                        'cmd_int': cid, 'first_call': call.group(1) if call else '',
                        'reply_str': rep_str, 'reply_hdr_int': rep_v,
                        'nargs': nargs, 'req_hdr_int': None, 'req_hdr_str': '',
                    })
        if cases:
            out.append((fea, fn, 'ARM', [cases[k] for k in sorted(cases)]))
    return out

def extract_thumb_dispatchers(cdir, B, base, fmap):
    """Extract Thumb switch dispatchers (__ARM_common_switch8 and 16-bit inline Thumb switch) from code.bin."""
    if not B:
        return []
    starts = sorted(fmap.keys())
    def enclosing_func(ea):
        best = None
        for s in starts:
            if s <= ea: best = s
            else: break
        if best is not None and ea - best < 0x2000:
            return f'0x{best:08x}', fmap.get(best, f'FUN_{best:08x}')
        return f'0x{ea:08x}', f'thumb_ipc_dispatcher_{ea:08x}'

    raw_switches = []
    # 1. __ARM_common_switch8 callers
    sw8_pos = B.find(SW8)
    if sw8_pos != -1:
        sw8_ea = base + sw8_pos
        for o in range(0, len(B) - 4, 2):
            t = decode_bl16(B, o, base)
            if t == sw8_ea:
                tbl_o = o + 4
                if tbl_o >= len(B): continue
                ncases = B[tbl_o]
                if not (2 <= ncases <= 220) or tbl_o + 1 + ncases >= len(B): continue
                def_off = B[tbl_o + 1 + ncases]
                def_ea = base + tbl_o + def_off * 2
                if decode_b16(B, def_ea - base, base): def_ea = decode_b16(B, def_ea - base, base)
                targets = []
                for idx in range(ncases):
                    x = B[tbl_o + 1 + idx]
                    if x == def_off:
                        targets.append((idx, None))
                        continue
                    t_ea = base + tbl_o + x * 2
                    b_t = decode_b16(B, t_ea - base, base)
                    cea = b_t if b_t is not None else t_ea
                    targets.append((idx, None if cea == def_ea else cea))
                raw_switches.append(('Thumb-sw8', base + o, find_base_cmd(B, o, base), targets))
    # 2. 16-bit inline Thumb switch
    for o in range(0, len(B) - 12, 2):
        h0, h1, h2, h3, h4 = struct.unpack_from('<HHHHH', B, o)
        if (h1 & 0xFFF8) == 0x4478 and (h2 & 0xFFC0) == 0x8880 and (h3 & 0xFFC0) == 0x0040 and (h4 & 0xFFC7) == 0x4487:
            ncases = None
            for back in range(2, 14, 2):
                if o - back < 0: break
                hp = struct.unpack_from('<H', B, o - back)[0]
                if (hp & 0xF800) == 0x2800:
                    ncases = hp & 0xFF; break
            if not ncases or not (2 <= ncases <= 250): continue
            tbl_o = o + 10
            if tbl_o + 2 * ncases > len(B): continue
            hws = struct.unpack_from(f'<{ncases}H', B, tbl_o)
            targets = []
            for idx, x in enumerate(hws):
                t_ea = base + o + 12 + x * 2
                b_t = decode_b16(B, t_ea - base, base)
                targets.append((idx, b_t if b_t is not None else t_ea))
            raw_switches.append(('Thumb-sw16', base + o, find_base_cmd(B, o, base), targets))

    # Group switches by enclosing function
    by_func = collections.defaultdict(list)
    for kind, sw_ea, base_cmd, targets in raw_switches:
        fea, fn = enclosing_func(sw_ea)
        by_func[(fea, fn)].append((kind, sw_ea, base_cmd, targets))

    out = []
    for (fea, fn), sw_list in sorted(by_func.items()):
        # Analyze all cases across switches in this function
        all_targets = sorted({t for _, _, _, targets in sw_list for _, t in targets if t is not None})
        call_counts = collections.Counter()
        per_sw_cases = []
        for kind, sw_ea, base_cmd, targets in sw_list:
            sw_bls = []
            for idx, cea in targets:
                if cea is None: continue
                pos_idx = all_targets.index(cea)
                nxt = all_targets[pos_idx + 1] if pos_idx + 1 < len(all_targets) else cea + 120
                bls = scan_thumb_case_body(B, cea, min(nxt, cea + 140), base)
                sw_bls.append((idx, cea, bls))
                for t, _ in bls: call_counts[t] += 1
            per_sw_cases.append((kind, sw_ea, base_cmd, sw_bls))
        helpers = {t for t, c in call_counts.items() if c >= 3}
        # Verify this is an actual IPC dispatcher: either >= 2 cases pass r1=cmd_id (1..0x2000), r2<=32, r3<=32 to a common helper,
        # OR the decompiled function reads TLS / cmdbuf (+0x80).
        ipc_helper_calls = 0
        cases = {}
        for kind, sw_ea, base_cmd, sw_bls in per_sw_cases:
            # First pass: check if r1 in first helper call gives a consistent base_cmd
            inferred_bases = collections.Counter()
            for idx, cea, bls in sw_bls:
                for t, rmap in bls:
                    if t in helpers and 1 in rmap and 2 in rmap and 3 in rmap:
                        if 1 <= rmap[1] <= 0x2000 and rmap[2] <= 32 and rmap[3] <= 32:
                            ipc_helper_calls += 1
                            diff = rmap[1] - idx
                            if diff >= 0: inferred_bases[diff] += 1
                        break
            if inferred_bases:
                best_base, freq = inferred_bases.most_common(1)[0]
                if freq >= 2: base_cmd = best_base
            for idx, cea, bls in sw_bls:
                cid = base_cmd + idx
                req_hdr = None
                rep_hdr = None
                handler_ea = None
                helper_idx = 0
                for t, rmap in bls:
                    if t in helpers:
                        helper_idx += 1
                        if 1 in rmap and 2 in rmap and 3 in rmap and 1 <= rmap[1] <= 0x2000 and rmap[2] <= 64 and rmap[3] <= 64:
                            hdr_val = (rmap[1] << 16) | (rmap[2] << 6) | rmap[3]
                            if helper_idx == 1 and req_hdr is None:
                                cid = rmap[1]
                                req_hdr = hdr_val
                            else:
                                rep_hdr = hdr_val
                    elif handler_ea is None:
                        handler_ea = t
                if cid <= 0 or cid > 0x2000:
                    continue
                if handler_ea is None and req_hdr is None and rep_hdr is None:
                    continue
                h_name = fmap.get(handler_ea & ~1, f'FUN_{handler_ea & ~1:08x}') if handler_ea else ''
                nargs = ((req_hdr >> 6) & 0x3F) + (req_hdr & 0x3F) if req_hdr is not None else 0
                cases.setdefault(cid, {
                    'cmd_int': cid,
                    'first_call': h_name,
                    'handler_ea': handler_ea & ~1 if handler_ea else None,
                    'reply_str': f'0x{rep_hdr:08X}' if rep_hdr is not None else '',
                    'reply_hdr_int': rep_hdr,
                    'nargs': nargs,
                    'req_hdr_int': req_hdr,
                    'req_hdr_str': f'0x{req_hdr:08X}' if req_hdr is not None else '',
                })
        if ipc_helper_calls >= 2 and len(cases) >= 2:
            modes = sorted({k for k, _, _, _ in sw_list})
            out.append((fea, fn, '/'.join(modes), [cases[k] for k in sorted(cases)]))
    return out

def main():
    profiles, mod_profiles = load_libctru_profiles()
    rows = []
    cdirs = sorted(glob.glob(f'{R}/*/*/*/decompiled') + glob.glob(f'{R}/*/*/*/*/decompiled'))
    for cdir in cdirs:
        bdir = os.path.dirname(cdir)
        binary = os.path.relpath(bdir, R)
        mod = module_short_name(binary)
        code_path = os.path.join(bdir, 'code.bin')
        B = open(code_path, 'rb').read() if os.path.exists(code_path) else None
        base = 0x14000000 if os.path.basename(bdir) == 'loader' else 0x00100000
        fmap = load_decomp_func_map(cdir)

        disps = extract_arm_dispatchers(cdir, B, base)
        arm_eas = {int(fea, 16) & ~1 for fea, _, _, _ in disps}
        if mod:
            for fea, fn, mode, crows in extract_thumb_dispatchers(cdir, B, base, fmap):
                if (int(fea, 16) & ~1) not in arm_eas:
                    disps.append((fea, fn, mode, crows))

        disps.sort(key=lambda x: int(x[0], 16))
        for fea, fn, mode, crows in disps:
            port, cmap = match_dispatcher_port(mod, crows, profiles, mod_profiles) if mod else ('', {})
            for c in crows:
                cid = c['cmd_int']
                lfunc, lhdr = pick_libctru_func(cmap, cid, c.get('req_hdr_int')) if cmap else ('', '')
                req_str = c.get('req_hdr_str') or lhdr
                rows.append([
                    binary, fea, fn, mode, port, f'0x{cid:04X}',
                    c['first_call'], c['reply_str'], c['nargs'], req_str, lfunc
                ])

    os.makedirs(R + '/n3ds/symbols/ipc', exist_ok=True)
    out_csv = R + '/n3ds/symbols/ipc/IPC_COMMANDS_FROM_DECOMPILATION.csv'
    with open(out_csv, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'binary', 'dispatcher_ea', 'dispatcher_name', 'mode', 'service_port',
            'cmd_id', 'first_call_in_case', 'reply_header_or_data_ref',
            'cmdbuf_words_touched', 'request_header', 'libctru_func'
        ])
        w.writerows(rows)

    n_disp = len({(r[0], r[1]) for r in rows})
    n_bin = len({r[0] for r in rows})
    n_lib = sum(1 for r in rows if r[10])
    print(f'{len(rows)} case rows ({n_lib} matched to libctru) from {n_disp} dispatchers in {n_bin} binaries')

    # Generate markdown summary
    by = collections.defaultdict(list)
    for r in rows:
        by[(r[0], r[1], r[2], r[3], r[4])].append(r)
    md = [
        '# IPC dispatchers recovered from decompiled C and Thumb switch tables (auto-generated by tools/extract_ipc_from_decomp.py)\n',
        f'Total: **{len(rows):,} command cases** (**{n_lib:,}** matched to official `libctru` functions) across **{n_disp} dispatchers** in **{n_bin} binaries**.\n',
        '* **ARM dispatchers** are extracted from `decompiled/*.c` (`switch(cmdbuf[0] >> 16)`, `switch(cmd_id - base)`, and `if (cmd_id == N)` chains, with `DAT_` literals resolved from `code.bin`).',
        '* **Thumb dispatchers** (`Thumb-sw8` via `__ARM_common_switch8` and `Thumb-sw16` inline 16-bit table branches) are extracted directly from `code.bin` with register tracking (`r1 = cmd_id, r2 = normal_params, r3 = translate_params`) into the per-dispatcher header-validator and reply-builder helpers.',
        '* **Service port & `libctru` function mapping** cross-references every dispatcher against `symbols/ipc/LIBCTRU_IPC_SPEC.csv` (1,242 command specifications from `libctru`).',
        '* Full per-case rows: `symbols/ipc/IPC_COMMANDS_FROM_DECOMPILATION.csv`.\n',
        '| binary | dispatcher | mode | service port | cases | command ids | distinct handlers | libctru matched |',
        '|---|---|---|---|---:|---|---:|---:|',
    ]
    for (b, ea, nm, mode, port), rs in sorted(by.items()):
        ids = sorted({int(x[5], 16) for x in rs})
        span = f'0x{ids[0]:02X}..0x{ids[-1]:02X}' if ids else ''
        lib_cnt = sum(1 for x in rs if x[10])
        md.append(f"| `{os.path.basename(b)}` | `{nm}` @ {ea} | `{mode}` | `{port or '-'}` | {len(rs)} | {span} | {len({x[6] for x in rs if x[6]})} | {lib_cnt} |")
    os.makedirs(R + '/n3ds/docs/decompiled_notes', exist_ok=True)
    open(R + '/n3ds/docs/decompiled_notes/IPC_TABLES.md', 'w').write('\n'.join(md) + '\n')

if __name__ == '__main__':
    main()
