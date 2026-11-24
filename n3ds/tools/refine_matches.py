#!/usr/bin/env python3
"""Call-graph / string based refinement and verification of the O3DS -> N3DS symbol transfer.

Input : the per-component CSV written by transfer_syms.py (+ O3DS and N3DS binaries).
Output: the same CSV rewritten in place with
  * new column `verification`
  * previously `unresolved` rows promoted to `probable_by_callgraph` when matched callers vote for them
  * `probable_by_transfer` rows demoted to `unresolved` if their own call sites contradict the mapping

How (byte evidence only):
 1. For every matched pair (O3DS fn, N3DS fn) the call instructions found at the SAME offsets inside both bodies are decoded
    (ARM BL/BLX imm, Thumb BL/BLX pair). Aligned call sites give target pairs (t_o -> t_n).
    The ISA of a body is chosen as the one whose O3DS targets land more often on known O3DS symbol starts.
 2. A target t_o that is still unresolved receives the N3DS address that its matched callers vote for
    (unanimous, or >= 2x the runner-up), if that address is not used by another symbol.
 3. Iterates to a fixpoint (newly resolved functions give new aligned call sites).
 4. Verification per row: calls whose O3DS target is resolved must land on the mapped N3DS target; literal-pool string references
    at the same offsets must be equal strings.
"""
import argparse, csv, re, struct, collections, sys
import numpy as np

import importlib.util, os
_sp = importlib.util.spec_from_file_location('ts', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'transfer_syms.py'))
_ts = importlib.util.module_from_spec(_sp); _sp.loader.exec_module(_ts)

def similarity(a, b):
    """max over ISA of the fraction of equal position-masked words/halfwords (same offsets)."""
    n = min(len(a), len(b)) & ~3
    if n < 8: return 0.0
    a, b = a[:n], b[:n]
    best = 0.0
    for m, st in ((_ts.mask_arm, 4), (_ts.mask_thumb, 2)):
        x, y = m(a), m(b)
        eq = sum(1 for i in range(0, n, st) if x[i:i + st] == y[i:i + st]); best = max(best, eq / (n // st))
    return best

def u16(b, o): return b[o] | (b[o + 1] << 8)
def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def sext(v, bits): return v - (1 << bits) if v >> (bits - 1) else v

def calls_arm(buf, base, start, end):
    """yield (offset_from_start, target) for ARM BL / BLX(imm)."""
    for o in range(start, min(end, len(buf)) - 3, 4):
        w = u32(buf, o)
        if w >> 25 & 7 != 0b101: continue
        c = w >> 28
        if c == 0xE and (w >> 24) & 1:                       # BL
            yield o - start, base + o + 8 + (sext(w & 0xFFFFFF, 24) << 2)
        elif c == 0xF:                                       # BLX imm -> Thumb
            yield o - start, base + o + 8 + (sext(w & 0xFFFFFF, 24) << 2) + (((w >> 24) & 1) << 1)

def calls_thumb(buf, base, start, end):
    for o in range(start, min(end, len(buf)) - 3, 2):
        h1 = u16(buf, o)
        if h1 & 0xF800 != 0xF000: continue
        h2 = u16(buf, o + 2); k = h2 & 0xF800
        if k not in (0xF800, 0xE800): continue
        off = sext(((h1 & 0x7FF) << 11) | (h2 & 0x7FF), 22) << 1
        t = base + o + 4 + off
        if k == 0xE800: t &= ~3
        yield o - start, t

def read_str(buf, base, v):
    o = v - base
    if o < 0 or o + 6 >= len(buf): return None
    a = bytearray()
    while o < len(buf) and 0x20 <= buf[o] < 0x7F and len(a) < 80: a.append(buf[o]); o += 1
    if len(a) >= 5 and o < len(buf) and buf[o] == 0: return bytes(a)
    o = v - base; a = bytearray()                              # UTF-16LE
    while o + 1 < len(buf) and 0x20 <= buf[o] < 0x7F and buf[o + 1] == 0 and len(a) < 80: a.append(buf[o]); o += 2
    if len(a) >= 5 and o + 1 < len(buf) and buf[o] == 0 and buf[o + 1] == 0: return b'u16:' + bytes(a)
    return None

def lits(buf, base, start, end, mode):
    """yield (offset, string) for literal-pool loads that point to strings."""
    for o in range(start, min(end, len(buf)) - 3, 4 if mode == 'arm' else 2):
        if mode == 'arm':
            w = u32(buf, o)
            if (w & 0x0F7F0000) != 0x051F0000: continue
            imm = w & 0xFFF; a = base + o + 8 + (imm if (w >> 23) & 1 else -imm)
        else:
            h = u16(buf, o)
            if h & 0xF800 != 0x4800: continue
            a = ((base + o + 4) & ~3) + (h & 0xFF) * 4
        lo = a - base
        if lo < 0 or lo + 4 > len(buf): continue
        s = read_str(buf, base, u32(buf, lo))
        if s: yield o - start, s

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old'); ap.add_argument('--old-base'); ap.add_argument('--new'); ap.add_argument('--new-base')
    ap.add_argument('--sym'); ap.add_argument('--csv'); ap.add_argument('--alias'); ap.add_argument('--tag', default='')
    a = ap.parse_args()
    hdr = open(a.sym, encoding='utf-8', errors='replace').read(600)
    mb = re.search(r'Load \.text: 0x([0-9A-Fa-f]+)', hdr)
    if mb: a.old_base = a.new_base = '0x' + mb.group(1)
    ob, nb = int(a.old_base, 16), int(a.new_base, 16)
    al = int(a.alias, 16) if a.alias else None
    O = open(a.old, 'rb').read(); N = open(a.new, 'rb').read()
    def ooff(ea): return ea - al if (al and ea >= al) else ea - ob
    def noff(ea): return ea - al if (al and ea >= al) else ea - nb
    def obase(ea): return al if (al and ea >= al) else ob
    def nbase(ea): return al if (al and ea >= al) else nb
    rows = list(csv.DictReader(open(a.csv)))
    if 'verification' in rows[0]: return                     # idempotent
    for r in rows:
        r['verification'] = ''
        r['_o'] = int(r['ea_o3ds'], 16); r['_n'] = int(r['ea_n3ds'], 16) if r['ea_n3ds'] else None
        r['_sz'] = int(r['size'], 16)
    rows.sort(key=lambda r: r['_o'])
    starts = [r['_o'] for r in rows]; S = set(starts)
    ext = {}
    for i, r in enumerate(rows):
        nxt = starts[i + 1] if i + 1 < len(rows) else r['_o'] + 0x400
        ext[r['_o']] = r['_sz'] if r['_sz'] else min(max(nxt - r['_o'], 4), 0x400)
        if 'estimated_size' in r['technical_evidence']: ext[r['_o']] = min(ext[r['_o']], 64)
    byo = {r['_o']: r for r in rows}
    byn = collections.defaultdict(list)
    for r in rows:
        if r['_n'] is not None: byn[r['_n']].append(r)
    for n_, grp in byn.items():
        if len(grp) > 1 and not all('whole_binary_identical' in g['technical_evidence'] for g in grp):
            for g in grp:       # several O3DS symbols claim the same N3DS address -> identical copies, cannot tell which is which
                g['technical_evidence'] = f'ambiguous_identical_functions({len(grp)} O3DS symbols map to one N3DS address 0x{n_:08X});was:{g["confidence_level"]}/{g["technical_evidence"]}'
                g['confidence_level'] = 'unresolved'; g['ea_n3ds'] = ''; g['_n'] = None
    used = {r['_n'] for r in rows if r['_n'] is not None}
    ident = all('whole_binary_identical' in r['technical_evidence'] for r in rows if r['_n'] is not None) and any(r['_n'] is not None for r in rows)
    cache = {}
    def pair_calls(o_ea, n_ea):
        key = (o_ea, n_ea)
        if key in cache: return cache[key]
        L = ext[o_ea]; best = ([], 'arm', [])
        for mode, fn in (('arm', calls_arm), ('thumb', calls_thumb)):
            oc = dict(fn(O, obase(o_ea), ooff(o_ea), ooff(o_ea) + L)); nc = dict(fn(N, nbase(n_ea), noff(n_ea), noff(n_ea) + L))
            al_ = [(oc[k], nc[k]) for k in oc if k in nc]
            score = sum(1 for t, _ in al_ if t in S)
            if score > sum(1 for t, _ in best[0] if t in S) or not best[0]: best = (al_, mode, [])
        cache[key] = best; return best
    promoted = 0
    def gap_fill():
        """Layout rule: between two matched neighbours the unresolved symbols keep the link order. If the N3DS distance between the
        neighbours equals the O3DS one (rule A) or only the single unresolved symbol in between changed size (rule B), place it at the
        same relative offset; accept only if the position-masked body similarity >= 0.4."""
        got = 0
        res = [r for r in rows if r['_n'] is not None]
        order = [r for r in rows]
        k = 0
        while k < len(order):
            if order[k]['_n'] is None: k += 1; continue
            i = k; k += 1; m = k
            while m < len(order) and order[m]['_n'] is None: m += 1
            if m >= len(order) or m == k: continue
            ri, rj = order[i], order[m]; mid = order[k:m]
            if rj['_n'] <= ri['_n'] or obase(ri['_o']) != obase(rj['_o']): continue
            dO = rj['_o'] - ri['_o']; dN = rj['_n'] - ri['_n']
            if dO <= 0: continue
            if dN == dO: pass                                           # rule A: identical layout
            elif len(mid) == 1 and abs(dN - dO) <= max(0x100, ext[mid[0]['_o']]): pass   # rule B: one function changed size
            else: continue
            for u in mid:
                n_ea = ri['_n'] + (u['_o'] - ri['_o'])
                if n_ea in used or not (0 <= noff(n_ea) < len(N)): continue
                L = ext[u['_o']]
                sim = similarity(O[ooff(u['_o']):ooff(u['_o']) + L], N[noff(n_ea):noff(n_ea) + L])
                if sim < 0.4: continue
                u['_n'] = n_ea; used.add(n_ea); u['ea_n3ds'] = f'0x{n_ea:08X}'; u['confidence_level'] = 'probable_by_layout'
                u['technical_evidence'] = f'layout_gap(rule {"A" if dN == dO else "B"}; neighbours {ri["symbol_name"]}..{rj["symbol_name"]}; masked_similarity={sim:.2f});was:{u["technical_evidence"]}'
                nn = re.sub(r'(?i)0x' + f'{u["_o"]:08x}', f'0x{n_ea:08X}', u['symbol_name']); nn = re.sub(r'(?i)_' + f'{u["_o"]:x}' + r'$', f'_{n_ea:x}', nn)
                if nn != u['symbol_name']: u['symbol_name'] = nn; u['technical_evidence'] += ';name_readdressed'
                got += 1
        return got
    # --- pointer tables (vtables, dispatch tables, worker/name pointer arrays) ---
    otables = []
    def find_tables():
        i = 0; n = len(O)
        while i + 12 <= n:
            run = []
            while i + 4 <= n:
                w = u32(O, i)
                if (w & ~1) in S: run.append((i, w))
                else: break
                i += 4
            if len(run) >= 3: otables.append(run)
            i += 4 if not run else 0
    find_tables()
    def table_pass():
        got = 0
        nbase0 = nb
        for run in otables:
            first_off = run[0][0]
            pred = []
            for off, w in run:
                m = byo.get(w & ~1)
                pred.append((m['_n'] | (w & 1)) if m is not None and m['_n'] is not None else None)
            known = [i for i, v in enumerate(pred) if v is not None]
            unknown = [i for i, v in enumerate(pred) if v is None]
            r_start = byo.get(ob + first_off)
            if not unknown and not (r_start is not None and r_start['_n'] is None): continue
            if len(known) < 2:                      # fallback: same pointer-spacing pattern (e.g. per-device worker thread entries)
                if len(run) < 4: continue
                dl = [(run[i + 1][1] & ~1) - (run[i][1] & ~1) for i in range(len(run) - 1)]
                hits = []
                import bisect as _b
                ro = [x for x in rows if x['_n'] is not None]
                ko = _b.bisect_left([x['_o'] for x in ro], ob + first_off)
                w_lo = noff(ro[ko - 1]['_n']) if ko > 0 else 0
                w_hi = noff(ro[ko]['_n']) if ko < len(ro) else len(N)
                if w_hi - w_lo > 0x400: w_lo, w_hi = w_lo, w_lo + 0x400
                for j in range(max(w_lo, 0) & ~3, min(w_hi, len(N)) - 4 * len(run) + 1, 4):
                    ws2 = [u32(N, j + 4 * i) for i in range(len(run))]
                    if not all(nb <= (w & ~1) < nb + len(N) for w in ws2): continue
                    if any((ws2[i + 1] & ~1) <= (ws2[i] & ~1) for i in range(len(ws2) - 1)): continue
                    if not (all(ws2[i] & 1 == ws2[0] & 1 for i in range(len(ws2)))): continue
                    if hits and j - hits[-1] < 4 * len(run): continue     # same (longer) pointer array seen at a shifted start
                    hits.append(j)
                    if len(hits) > 1: break
                if len(hits) != 1: continue
                bp = hits[0]
                for i in unknown:
                    t_n = u32(N, bp + 4 * i); tgt = t_n & ~1; r = byo.get(run[i][1] & ~1)
                    if r is None or r['_n'] is not None or tgt in used or not (0 <= noff(tgt) < len(N)): continue
                    r['_n'] = tgt; used.add(tgt); r['ea_n3ds'] = f'0x{tgt:08X}'; r['confidence_level'] = 'probable_by_table'
                    r['technical_evidence'] = f'pointer_table_shape(O3DS table@0x{ob + first_off:08X} slot {i}; unique N3DS table@0x{nb + bp:08X} with identical {len(dl)} pointer deltas);was:{r["technical_evidence"]}'
                    nn = re.sub(r'(?i)0x' + f'{r["_o"]:08x}', f'0x{tgt:08X}', r['symbol_name']); nn = re.sub(r'(?i)_' + f'{r["_o"]:x}' + r'$', f'_{tgt:x}', nn)
                    if nn != r['symbol_name']: r['symbol_name'] = nn; r['technical_evidence'] += ';name_readdressed'
                    got += 1
                r0 = byo.get(ob + first_off)
                if r0 is not None and r0['_n'] is None and (nb + bp) not in used:
                    n_ea = nb + bp; r0['_n'] = n_ea; used.add(n_ea); r0['ea_n3ds'] = f'0x{n_ea:08X}'; r0['confidence_level'] = 'probable_by_table'
                    r0['technical_evidence'] = f'pointer_table_shape(start);was:{r0["technical_evidence"]}'; got += 1
                continue
            if False: continue
            k0 = known[0]; needle = struct.pack('<I', pred[k0]); cands = []; pos = 0
            while True:
                j = N.find(needle, pos)
                if j < 0: break
                pos = j + 1
                if j % 4: continue
                base_pos = j - 4 * k0
                if base_pos < 0 or base_pos + 4 * len(pred) > len(N): continue
                if all(u32(N, base_pos + 4 * i) == pred[i] for i in known): cands.append(base_pos)
            if len(cands) != 1: continue
            bp = cands[0]
            for cand_o in {ob + first_off, (al + first_off) if al else ob + first_off}:
                r0 = byo.get(cand_o)
                if r0 is not None and r0['_n'] is None:
                    n_ea = (al + bp) if (al and cand_o >= al) else nb + bp
                    if n_ea not in used:
                        r0['_n'] = n_ea; used.add(n_ea); r0['ea_n3ds'] = f'0x{n_ea:08X}'; r0['confidence_level'] = 'probable_by_table'
                        r0['technical_evidence'] = f'pointer_table_start({len(known)} of {len(pred)} slots matched);was:{r0["technical_evidence"]}'
                        nn = re.sub(r'(?i)0x' + f'{r0["_o"]:08x}', f'0x{n_ea:08X}', r0['symbol_name']); nn = re.sub(r'(?i)_' + f'{r0["_o"]:x}' + r'$', f'_{n_ea:x}', nn)
                        if nn != r0['symbol_name']: r0['symbol_name'] = nn; r0['technical_evidence'] += ';name_readdressed'
                        got += 1
            for i in unknown:
                t_n = u32(N, bp + 4 * i); tgt = t_n & ~1
                r = byo.get(run[i][1] & ~1)
                if r is None or r['_n'] is not None or tgt in used or not (0 <= noff(tgt) < len(N)): continue
                r['_n'] = tgt; used.add(tgt); r['ea_n3ds'] = f'0x{tgt:08X}'; r['confidence_level'] = 'probable_by_table'
                r['technical_evidence'] = f'pointer_table_slot(O3DS table@0x{ob + first_off:08X} slot {i}; {len(known)} neighbouring slots matched at N3DS table@0x{nb + bp:08X});was:{r["technical_evidence"]}'
                nn = re.sub(r'(?i)0x' + f'{r["_o"]:08x}', f'0x{tgt:08X}', r['symbol_name']); nn = re.sub(r'(?i)_' + f'{r["_o"]:x}' + r'$', f'_{tgt:x}', nn)
                if nn != r['symbol_name']: r['symbol_name'] = nn; r['technical_evidence'] += ';name_readdressed'
                got += 1
        return got
    def strtable_pass():
        """Data symbols that are arrays of pointers to strings (service-name tables): locate the same strings in N3DS and the pointer array that references them."""
        got = 0
        for r in rows:
            if r['_n'] is not None or r['_sz'] < 8 or r['_sz'] > 0x40 or r['_sz'] % 4: continue
            off = ooff(r['_o'])
            if off < 0 or off + r['_sz'] > len(O): continue
            ws = [u32(O, off + 4 * i) for i in range(r['_sz'] // 4)]
            strs = [read_str(O, ob, w) for w in ws]
            if not all(strs): continue
            preds = []
            for st in strs:
                raw = st[4:].decode() if st.startswith(b'u16:') else st.decode()
                pat = (raw.encode('utf-16le') if st.startswith(b'u16:') else raw.encode()) + (b'\0\0' if st.startswith(b'u16:') else b'\0')
                hits = [m.start() for m in re.finditer(re.escape(pat), N)]
                hits = [h for h in hits if h == 0 or N[h - 1] == 0 or True]
                if len(hits) != 1: preds = None; break
                preds.append(nb + hits[0])
            if not preds: continue
            needle = b''.join(struct.pack('<I', p) for p in preds)
            j = N.find(needle)
            if j < 0 or N.find(needle, j + 1) >= 0: continue
            n_ea = nb + j
            if n_ea in used: continue
            r['_n'] = n_ea; used.add(n_ea); r['ea_n3ds'] = f'0x{n_ea:08X}'; r['confidence_level'] = 'probable_by_table'
            r['technical_evidence'] = f'string_pointer_array({len(preds)} unique strings re-found in N3DS and referenced by this array);was:{r["technical_evidence"]}'; got += 1
        return got
    def lit_loads(buf, base, start, end):
        """(offset_in_function, value) for every pc-relative literal load in both ISAs (the right ISA is the one that yields consistent values)."""
        out = []
        for o in range(start, min(end, len(buf)) - 3, 2):
            h = u16(buf, o)
            if h & 0xF800 == 0x4800:
                a = ((base + o + 4) & ~3) + (h & 0xFF) * 4; lo = a - base
                if 0 <= lo + 4 <= len(buf): out.append((o - start, u32(buf, lo)))
            if o % 4 == 0:
                w = u32(buf, o)
                if (w & 0x0F7F0000) == 0x051F0000:
                    imm = w & 0xFFF; a = base + o + 8 + (imm if (w >> 23) & 1 else -imm); lo = a - base
                    if 0 <= lo + 4 <= len(buf): out.append((o - start, u32(buf, lo)))
        return out
    Nloads = None
    def const_pass():
        """Place a changed function by the rare 32-bit constants of its literal pool (MMIO bases, sizes, magic numbers): all aligned loads of the same
        constants in N3DS must imply the same function start."""
        nonlocal Nloads
        got = 0
        if Nloads is None:
            Nloads = collections.defaultdict(list)
            for pos, val in lit_loads(N, nb, 0, len(N)): Nloads[val].append(pos)
        claimed = sorted((r['_n'], r['_n'] + (r['_sz'] if r['_sz'] else 4)) for r in rows if r['_n'] is not None)
        for u in rows:
            if u['_n'] is not None: continue
            L = ext[u['_o']]
            if L < 0x20: continue
            lo_ = ooff(u['_o'])
            loads = [(off, v) for off, v in lit_loads(O, obase(u['_o']), lo_, lo_ + L) if not (ob <= v < ob + len(O)) and v > 0xFFF and v not in (0xFFFFFFFF,)]
            if len(loads) < 2: continue
            votes = collections.Counter()
            for off, v in loads:
                ps = Nloads.get(v, [])
                if 0 < len(ps) <= 4:
                    for pn in ps: votes[pn - off] += 1
            if not votes: continue
            (st, cnt), = votes.most_common(1)
            second = votes.most_common(2)[1][1] if len(votes) > 1 else 0
            if cnt < max(2, (len(loads) + 1) // 2) or cnt <= second: continue
            n_ea = st + (al if al and u['_o'] >= al else nb)
            if n_ea in used or not (0 <= noff(n_ea) < len(N)) or noff(n_ea) % 2: continue
            if any(a < n_ea + L and n_ea < b for a, b in claimed if b - a > 4 and a < n_ea + L and b > n_ea): continue
            sim = similarity(O[lo_:lo_ + L], N[noff(n_ea):noff(n_ea) + L])
            if sim < 0.2: continue
            u['_n'] = n_ea; used.add(n_ea); u['ea_n3ds'] = f'0x{n_ea:08X}'; u['confidence_level'] = 'probable_by_constants'
            u['technical_evidence'] = f'literal_constants({cnt} of {len(loads)} rare constants of the O3DS literal pool loaded at the same offsets from this start; masked_similarity={sim:.2f});was:{u["technical_evidence"]}'
            nn = re.sub(r'(?i)0x' + f'{u["_o"]:08x}', f'0x{n_ea:08X}', u['symbol_name']); nn = re.sub(r'(?i)_' + f'{u["_o"]:x}' + r'$', f'_{n_ea:x}', nn)
            if nn != u['symbol_name']: u['symbol_name'] = nn; u['technical_evidence'] += ';name_readdressed'
            claimed.append((n_ea, n_ea + L)); claimed.sort(); got += 1
        return got
    r2fn = None
    def gap_functions():
        """radare2 function boundaries of the N3DS binary: when the unresolved O3DS symbols between two matched neighbours are as many as the
        unclaimed radare2 functions between the same neighbours, pair them in link order (one unresolved + several candidates: closest size)."""
        nonlocal r2fn
        import subprocess, json
        if r2fn is None:
            base_arg = al if al else nb
            out = subprocess.run(['r2', '-q', '-a', 'arm', '-b', '32', '-m', hex(base_arg), '-c', 'aaa;aflj', a.new], capture_output=True, text=True).stdout
            try: fl = json.loads(out[out.index('['):])
            except Exception: fl = []
            r2fn = sorted((f['offset'] - base_arg + (0), f['size']) for f in fl if f.get('size', 0) >= 2)   # file offsets
        got = 0
        res = [r for r in rows if r['_n'] is not None]
        claimed = sorted((noff(r['_n']), noff(r['_n']) + (r['_sz'] if r['_sz'] else 4)) for r in res)
        import bisect
        ci = [c[0] for c in claimed]
        def unclaimed(f_off, f_sz):
            k = bisect.bisect_right(ci, f_off) - 1
            if k >= 0 and claimed[k][1] > f_off: return False
            return True
        order = rows; k = 0
        while k < len(order):
            if order[k]['_n'] is None: k += 1; continue
            i = k; k += 1; m = k
            while m < len(order) and order[m]['_n'] is None: m += 1
            if m >= len(order) or m == k: continue
            ri, rj = order[i], order[m]; mid = [u for u in order[k:m] if ext[u['_o']] >= 8]
            if not mid or obase(ri['_o']) != obase(rj['_o']) or noff(rj['_n']) <= noff(ri['_n']): continue
            lo, hi = noff(ri['_n']), noff(rj['_n'])
            F = [(o, sz) for o, sz in r2fn if lo < o < hi and unclaimed(o, sz)]
            if not F: continue
            pairs = []
            if len(F) == len(mid): pairs = list(zip(mid, F))
            elif len(mid) == 1:
                L = ext[mid[0]['_o']]
                cand = sorted(F, key=lambda f: abs(f[1] - L))
                if abs(cand[0][1] - L) <= max(8, L // 3) and (len(cand) == 1 or abs(cand[1][1] - L) > abs(cand[0][1] - L) + max(8, L // 8)): pairs = [(mid[0], cand[0])]
            for u, (o, sz) in pairs:
                n_ea = o + (al if al and u['_o'] >= al else nb)
                if n_ea in used: continue
                u['_n'] = n_ea; used.add(n_ea); u['ea_n3ds'] = f'0x{n_ea:08X}'; u['confidence_level'] = 'probable_by_gap_function'
                u['technical_evidence'] = f'unclaimed_radare2_function(size 0x{sz:X} vs O3DS 0x{ext[u["_o"]]:X}) between matched neighbours {ri["symbol_name"]}..{rj["symbol_name"]};was:{u["technical_evidence"]}'
                nn = re.sub(r'(?i)0x' + f'{u["_o"]:08x}', f'0x{n_ea:08X}', u['symbol_name']); nn = re.sub(r'(?i)_' + f'{u["_o"]:x}' + r'$', f'_{n_ea:x}', nn)
                if nn != u['symbol_name']: u['symbol_name'] = nn; u['technical_evidence'] += ';name_readdressed'
                got += 1
        return got
    NA_, NT_ = None, None; NA32 = NT16 = None
    def fuzzy():
        """Best masked-similarity placement of an unresolved function inside the unclaimed N3DS space between its matched neighbours."""
        nonlocal NA_, NT_, NA32, NT16
        if NA_ is None:
            NA_, NT_ = _ts.mask_arm(N), _ts.mask_thumb(N)
            NA32 = np.frombuffer(bytes(NA_[:len(NA_) // 4 * 4]), dtype=np.uint32); NT16 = np.frombuffer(bytes(NT_[:len(NT_) // 2 * 2]), dtype=np.uint16)
        got = 0
        res = [r for r in rows if r['_n'] is not None]
        res_o = [r['_o'] for r in res]
        import bisect
        claimed = sorted((r['_n'], r['_n'] + (r['_sz'] if r['_sz'] else 4)) for r in res)
        for u in rows:
            if u['_n'] is not None: continue
            L = ext[u['_o']]
            if L < 12: continue
            k = bisect.bisect_left(res_o, u['_o'])
            lo_r = res[k - 1] if k > 0 else None; hi_r = res[k] if k < len(res) else None
            lo = (lo_r['_n'] if lo_r else 0 if not al else noff(u['_o'])); hi = (hi_r['_n'] if hi_r else lo + 0x2000)
            if lo_r and obase(lo_r['_o']) != obase(u['_o']): continue
            ob = O[ooff(u['_o']):ooff(u['_o']) + L]
            oa, ot = _ts.mask_arm(ob), _ts.mask_thumb(ob)
            def scan(lo_o, hi_o):
                lo_o = max(lo_o, 0); hi_o = min(hi_o, len(N))
                out = []
                for width, narr, oarr_b in ((4, NA32, oa), (2, NT16, ot)):
                    m = len(oarr_b) // width
                    if m < 3: continue
                    oarr = np.frombuffer(bytes(oarr_b[:m * width]), dtype=np.uint32 if width == 4 else np.uint16)
                    M = len(narr) - m + 1
                    if M <= 0: continue
                    acc = np.zeros(M, dtype=np.int32)
                    for k in range(m): acc += (narr[k:k + M] == oarr[k])
                    sc = acc / m
                    p0 = lo_o // width; p1 = min(M, hi_o // width + 1)
                    if p1 <= p0: continue
                    seg = sc[p0:p1]
                    idx = np.argpartition(seg, -min(64, len(seg)))[-min(64, len(seg)):]
                    for q in idx:
                        pos = (p0 + int(q)) * width
                        ea = pos + (al if al and u['_o'] >= al else nb)
                        if any(a < ea + L and ea < b for a, b in claimed if a < ea + L and b > ea): continue
                        out.append((float(seg[q]), ea))
                out.sort(reverse=True); return out
            best = []; thr = (0.5, 0.15)
            if 0 < hi - lo <= 0x6000: best = scan(noff(lo) if lo_r else lo, noff(hi))
            if (not best or best[0][0] < 0.5) and lo_r is not None:     # shift of the previous matched neighbour +-0x1000
                exp = noff(u['_o']) + (noff(lo_r['_n']) - ooff(lo_r['_o']))
                best = scan(exp - 0x1000, exp + 0x1000 + L)
            if not best or best[0][0] < 0.5:        # moved function: search the whole image, stricter thresholds
                g = scan(0, len(N))
                if g and g[0][0] >= 0.75: best = g; thr = (0.75, 0.25)
            if not best: continue
            best.sort(reverse=True)
            top = best[0]; sec = next((b for b in best[1:] if abs(b[1] - top[1]) > 8), (0.0, 0))
            if top[0] >= thr[0] and top[0] - sec[0] >= thr[1] and top[1] not in used:
                n_ea = top[1]
                u['_n'] = n_ea; used.add(n_ea); u['ea_n3ds'] = f'0x{n_ea:08X}'; u['confidence_level'] = 'probable_by_similarity'
                u['technical_evidence'] = f'masked_similarity={top[0]:.2f}(runner_up={sec[0]:.2f}) inside unclaimed gap between matched neighbours;was:{u["technical_evidence"]}'
                nn = re.sub(r'(?i)0x' + f'{u["_o"]:08x}', f'0x{n_ea:08X}', u['symbol_name']); nn = re.sub(r'(?i)_' + f'{u["_o"]:x}' + r'$', f'_{n_ea:x}', nn)
                if nn != u['symbol_name']: u['symbol_name'] = nn; u['technical_evidence'] += ';name_readdressed'
                claimed.append((n_ea, n_ea + L)); claimed.sort(); got += 1
        return got
    if not ident:
        for it in range(8):
            votes = collections.defaultdict(collections.Counter); who = collections.defaultdict(list)
            for r in rows:
                if r['_n'] is None: continue
                al_, _, _ = pair_calls(r['_o'], r['_n'])
                for t_o, t_n in al_:
                    if t_o in S and t_o != r['_o']: votes[t_o][t_n] += 1; who[t_o].append(r['symbol_name'])
            new = 0
            for r in rows:
                if r['_n'] is not None or r['_o'] not in votes: continue
                c = votes[r['_o']].most_common(); top, cnt = c[0]; rest = sum(v for _, v in c[1:])
                if top in used or cnt < 1 or (rest and cnt < 2 * rest): continue
                if not (0 <= noff(top) < len(N)): continue
                r['_n'] = top; used.add(top); r['ea_n3ds'] = f'0x{top:08X}'; r['confidence_level'] = 'probable_by_callgraph'
                r['technical_evidence'] = f'callgraph_vote({cnt} aligned call sites from matched callers e.g. {who[r["_o"]][0]});was:{r["technical_evidence"]}'
                nn = re.sub(r'(?i)0x' + f'{r["_o"]:08x}', f'0x{top:08X}', r['symbol_name'])
                nn = re.sub(r'(?i)_' + f'{r["_o"]:x}' + r'$', f'_{top:x}', nn)
                if nn != r['symbol_name']: r['symbol_name'] = nn; r['technical_evidence'] += ';name_readdressed'
                new += 1
            promoted += new
            new += gap_fill()
            new += table_pass()
            new += strtable_pass()
            if not new:
                new = fuzzy() + const_pass()
                if not new and any(r['_n'] is None and ext[r['_o']] >= 8 for r in rows): new = gap_functions()
                promoted += new
            if not new: break
    # verification
    stats = collections.Counter()
    inc = collections.defaultdict(collections.Counter)
    if not ident:
        for r in rows:
            if r['_n'] is None: continue
            for t_o, t_n in pair_calls(r['_o'], r['_n'])[0]:
                if t_o in S: inc[t_o][t_n] += 1
    for r in rows:
        if r['_n'] is None: continue
        if ident: r['verification'] = 'identical_binary'; stats['identical'] += 1; continue
        al_, mode, _ = pair_calls(r['_o'], r['_n'])
        ag = dis = unk = 0
        for t_o, t_n in al_:
            m = byo.get(t_o)
            if m is None or m['_n'] is None: unk += 1
            elif m['_n'] == t_n: ag += 1
            else: dis += 1
        sa = sd = 0
        L = ext[r['_o']]
        so = dict(lits(O, obase(r['_o']), ooff(r['_o']), ooff(r['_o']) + L, mode)); sn = dict(lits(N, nbase(r['_n']), noff(r['_n']), noff(r['_n']) + L, mode))
        for k, s in so.items():
            if k in sn:
                if sn[k] == s: sa += 1
                else: sd += 1
        ia = inc[r['_o']].get(r['_n'], 0); idis = sum(v for k, v in inc[r['_o']].items() if k != r['_n'])
        if (dis or idis) and not (ag or sa or ia): st = 'conflict'
        elif dis or sd or idis: st = 'partial'
        elif ag or sa or ia: st = 'verified'
        else: st = 'no_evidence'
        r['verification'] = f'{st};calls_agree={ag},disagree={dis},unmapped={unk};strings_agree={sa},disagree={sd};callers_agree={ia},disagree={idis}'
        stats[st] += 1
        if st == 'conflict' and r['confidence_level'] == 'exact':
            r['confidence_level'] = 'probable_by_transfer'; r['technical_evidence'] += ';downgraded_from_exact:identical_bytes_but_call_graph_disagrees'; stats['downgraded'] += 1
        elif st == 'conflict' and r['confidence_level'] in ('probable_by_transfer', 'probable_by_callgraph', 'probable_by_layout', 'probable_by_similarity', 'probable_by_table', 'probable_by_constants', 'probable_by_gap_function'):
            r['technical_evidence'] += ';rejected:call_sites_contradict_mapping'
            r['confidence_level'] = 'unresolved'; r['ea_n3ds'] = ''; r['_n'] = None; stats['demoted'] += 1
    rows.sort(key=lambda r: int(r['ea_o3ds'], 16))
    cols = [c for c in rows[0] if not c.startswith('_')]
    with open(a.csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in rows: w.writerow({c: r[c] for c in cols})
    print(a.tag, 'promoted', promoted, dict(stats))

if __name__ == '__main__': main()
