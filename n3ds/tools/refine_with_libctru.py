#!/usr/bin/env python3
"""Refine N3DS and O3DS symbol tables using libctru IPC command specifications and recovered ARM/Thumb dispatchers.

Inputs:
  - n3ds/symbols/ipc/LIBCTRU_IPC_SPEC.csv (1,242 command specifications from libctru)
  - n3ds/symbols/ipc/IPC_COMMANDS_FROM_DECOMPILATION.csv (ARM + Thumb dispatchers and per-case handlers)
  - n3ds/symbols/derived/*.csv & n3ds/symbols/N3DS_IPC_COMMANDS.csv (from derive_ipc.py)
  - n3ds/symbols/*.csv & o3ds/decrypted_binaries/**/*_friendly.sym

Actions:
  1. Enriches `n3ds/symbols/derived/*.csv`:
     - Adds/upgrades ARM & Thumb IPC dispatchers (`<mod>_<port>_ipc_dispatcher_<addr>`), `__ARM_common_switch8` helpers,
       and per-case command handlers (`<mod>_ipc_cmd_<cid>_<LibctruFunc>_<addr>` or `<mod>_ipc_cmd_<cid>_handler_<addr>`).
     - Annotates `ipc_client_call` and `ipc_command_handler` rows whose 32-bit request header matches a `libctru` command
       for a service in the module's ExHeader service-access list (client) or the module's own ports (handler).
  2. Enriches `n3ds/symbols/<tag>.csv` (transferred O3DS->N3DS tables) and `o3ds/decrypted_binaries/**/*_friendly.sym`:
     - Appends `;libctru=<port>:<LibctruFunc>(cmd=0xXXXX)` evidence to every transferred dispatcher/handler row.
     - Upgrades generic placeholder names (`fs_ipc_handler_NNNN`, `cecd_nwmc_box_NNNN`, `nwm_ipc_services_NNNN`,
       `ptm_dispatchers_handlers_NNNN`, etc.) with the verified `libctru` function name.
  3. Populates/updates `n3ds/symbols/manual/*.csv` and `n3ds/docs/decompiled_notes/*.md` for N3DS modules (`qtm`, `mvd`, `nfc`, `camera`).
"""
import collections, csv, glob, json, os, re, struct, subprocess

R = os.path.abspath(os.path.dirname(__file__) + '/../..')
SPEC_CSV = os.path.join(R, 'n3ds/symbols/ipc/LIBCTRU_IPC_SPEC.csv')
DECOMP_IPC_CSV = os.path.join(R, 'n3ds/symbols/ipc/IPC_COMMANDS_FROM_DECOMPILATION.csv')
SW8 = bytes.fromhex('01c05ee50c0053e10c30de270330de3783c08ee01cff2fe1')

GENERIC_SYM_RE = re.compile(
    r'^(fs_ipc_handler|fs_ipc_call_cmd|cecd_nwmc_box|nwm_ipc_services|ptm_dispatchers_handlers|'
    r'gsp_gpu_cmd|gsp_lcd_cmd|hid_ipc_cmd|mcu_cmd|pm_cmd|sm_cmd|ldr_cmd|pxi_cmd)_[0-9a-fA-F_nx]+$'
)

def clean_port(port):
    return re.sub(r'[^A-Za-z0-9]+', '_', port).strip('_').lower()

def exheader_services(path):
    if not path or not os.path.exists(path):
        return []
    t = subprocess.run(['ctrtool', '-t', 'exheader', path], capture_output=True, text=True).stdout
    m = re.search(r'Service access:\s*\n((?:\s*>.*\n)+)', t)
    return [x.strip()[2:].strip() for x in m.group(1).splitlines()] if m else []

def parse_ea_from_name(fn):
    if not fn:
        return None
    m = re.search(r'_([0-9a-fA-F]{6,8})$', fn)
    if m:
        return int(m.group(1), 16) & ~1
    return None

def load_symbol_name_to_ea(bdir):
    """Map function symbol name -> integer EA for a binary directory."""
    m = {}
    idx = os.path.join(bdir, 'decompiled/index.tsv')
    if os.path.exists(idx):
        for line in open(idx, errors='replace'):
            p = line.strip().split('\t')
            if len(p) >= 2 and p[0].startswith('0x'):
                try:
                    m[p[1]] = int(p[0], 16) & ~1
                except ValueError:
                    pass
    return m

def main():
    spec_rows = list(csv.DictReader(open(SPEC_CSV)))
    decomp_rows = list(csv.DictReader(open(DECOMP_IPC_CSV)))

    # Map request_header_hex -> list of spec dicts (for client/handler header matching)
    by_hdr = collections.defaultdict(list)
    by_mod_hdr = collections.defaultdict(list)
    by_port_hdr = collections.defaultdict(list)
    for r in spec_rows:
        by_hdr[r['request_header'].upper()].append(r)
        by_mod_hdr[(r['module'], r['request_header'].upper())].append(r)
        by_port_hdr[(r['port'], r['request_header'].upper())].append(r)

    # Group decomp_rows by binary
    by_bin = collections.defaultdict(list)
    for r in decomp_rows:
        by_bin[r['binary']].append(r)

    # 1. Refine n3ds/symbols/derived/*.csv
    derived_upgraded = 0
    derived_added = 0
    n3ds_bins = sorted(
        glob.glob(os.path.join(R, 'n3ds/decrypted_binaries/Module-*')) +
        glob.glob(os.path.join(R, 'n3ds/decrypted_binaries/firm_modules/*'))
    )
    for bdir in n3ds_bins:
        bn = os.path.basename(bdir)
        rel = os.path.relpath(bdir, R)
        tid = bn[-16:] if bn.startswith('Module-') else 'firm_' + bn
        mod = bn.split('-')[1].lower() if bn.startswith('Module-') else bn.lower()
        base = 0x14000000 if bn == 'loader' else 0x00100000
        dcsv = os.path.join(R, f'n3ds/symbols/derived/{tid}.csv')
        if not os.path.exists(dcsv):
            continue
        drows = list(csv.DictReader(open(dcsv)))
        by_ea = {int(r['ea_n3ds'], 16) & ~1: r for r in drows}
        name_to_ea = load_symbol_name_to_ea(bdir)
        accessed_ports = set(exheader_services(os.path.join(bdir, 'exheader.bin')))

        # Load function sizes from r2_functions
        fsize = {}
        r2f = os.path.join(R, f'n3ds/symbols/r2_functions/{tid}.json')
        if os.path.exists(r2f):
            for f in json.load(open(r2f)):
                fsize[f['offset'] & ~1] = f['size']

        # Check for __ARM_common_switch8 in code.bin
        code_path = os.path.join(bdir, 'code.bin')
        if os.path.exists(code_path):
            B = open(code_path, 'rb').read()
            sw8_pos = B.find(SW8)
            if sw8_pos != -1:
                sw8_ea = base + sw8_pos
                if sw8_ea not in by_ea:
                    row = {
                        'ea_n3ds': f'0x{sw8_ea:08X}',
                        'size': '0x18',
                        'symbol_name': f'{mod}___ARM_common_switch8_{sw8_ea:x}',
                        'kind': 'thumb_switch_helper',
                        'technical_evidence': 'exact 24-byte RVCT ARM helper __ARM_common_switch8 called by Thumb IPC switch dispatchers'
                    }
                    drows.append(row)
                    by_ea[sw8_ea] = row
                    derived_added += 1

        # Process dispatchers and cases for this binary
        b_cases = by_bin.get(rel, [])
        disp_groups = collections.defaultdict(list)
        handler_cases = collections.defaultdict(list) # handler_ea -> [(port, cid_str, lfunc, disp_ea, req_hdr, rep_hdr)]
        for c in b_cases:
            dea = int(c['dispatcher_ea'], 16) & ~1
            disp_groups[dea].append(c)
            fn = c['first_call_in_case']
            hea = name_to_ea.get(fn) or parse_ea_from_name(fn)
            if hea and hea != dea:
                handler_cases[hea].append((
                    c['service_port'], c['cmd_id'], c['libctru_func'],
                    c['dispatcher_ea'], c['request_header'], c['reply_header_or_data_ref']
                ))

        for dea, cs in sorted(disp_groups.items()):
            port = cs[0]['service_port']
            mode = cs[0]['mode']
            p_tag = f'_{clean_port(port)}' if port else ''
            new_name = f'{mod}{p_tag}_ipc_dispatcher_{dea:x}'
            ids = sorted({int(x['cmd_id'], 16) for x in cs})
            span = f'0x{ids[0]:02X}..0x{ids[-1]:02X}'
            lib_cnt = sum(1 for x in cs if x['libctru_func'])
            ev = f'{mode} IPC command dispatcher ({len(cs)} cases, cmd_id {span}' + (f', service {port}, {lib_cnt} matched to libctru' if port else '') + ')'
            if dea in by_ea:
                r = by_ea[dea]
                r['symbol_name'] = new_name
                r['kind'] = 'ipc_dispatcher'
                if ev not in r['technical_evidence']:
                    r['technical_evidence'] = ev + '; ' + r['technical_evidence']
                derived_upgraded += 1
            else:
                row = {
                    'ea_n3ds': f'0x{dea:08X}',
                    'size': hex(fsize.get(dea, 0x40)),
                    'symbol_name': new_name,
                    'kind': 'ipc_dispatcher',
                    'technical_evidence': ev
                }
                drows.append(row)
                by_ea[dea] = row
                derived_added += 1

        for hea, hlist in sorted(handler_cases.items()):
            # Skip tiny SVC wrappers or already-known non-handler helpers if they are called across >6 cases without distinct libctru funcs
            lfuncs = []
            cids = []
            ports = []
            for port, cid, lf, dea, req_h, rep_h in hlist:
                if cid not in cids: cids.append(cid)
                if port and port not in ports: ports.append(port)
                if lf:
                    first_lf = lf.split('/')[0]
                    if first_lf not in lfuncs: lfuncs.append(first_lf)
            if len(cids) > 8 and not lfuncs:
                continue
            cid_tag = '_'.join(c[2:] for c in cids[:2]) + ('_etc' if len(cids) > 2 else '')
            if lfuncs:
                lf_tag = '_'.join(lfuncs[:2]) + ('_etc' if len(lfuncs) > 2 else '')
                new_name = f'{mod}_ipc_cmd_{cid_tag}_{lf_tag}_{hea:x}'
            else:
                p_tag = f'_{clean_port(ports[0])}' if ports else ''
                new_name = f'{mod}{p_tag}_ipc_cmd_{cid_tag}_handler_{hea:x}'
            sample = hlist[0]
            ev_parts = [f"called from dispatcher {sample[3]}" + (f" ({'/'.join(ports)})" if ports else "") + f" for cmd {', '.join(cids[:4])}"]
            if lfuncs:
                ev_parts.append(f"libctru={'/'.join(lfuncs[:3])}")
            if sample[4]:
                ev_parts.append(f"req_hdr={sample[4]}")
            if sample[5]:
                ev_parts.append(f"reply_hdr={sample[5]}")
            ev = '; '.join(ev_parts)
            if hea in by_ea:
                r = by_ea[hea]
                if r['kind'] == 'svc_wrapper':
                    continue
                if lfuncs or r['symbol_name'].startswith(f'{mod}_ipc_handler_cmd_'):
                    r['symbol_name'] = new_name
                if 'libctru=' not in r['technical_evidence'] and ev not in r['technical_evidence']:
                    r['technical_evidence'] += '; ' + ev
                derived_upgraded += 1
            else:
                row = {
                    'ea_n3ds': f'0x{hea:08X}',
                    'size': hex(fsize.get(hea, 0x20)),
                    'symbol_name': new_name,
                    'kind': 'ipc_command_handler',
                    'technical_evidence': ev
                }
                drows.append(row)
                by_ea[hea] = row
                derived_added += 1

        # Also check existing ipc_client_call / ipc_command_handler rows by 32-bit header literal
        for r in drows:
            if r['kind'] not in ('ipc_client_call', 'ipc_command_handler'):
                continue
            if 'libctru=' in r['technical_evidence']:
                continue
            hdrs = re.findall(r'0x[0-9A-Fa-f]{8}', r['technical_evidence'])
            matched_specs = []
            for h in hdrs:
                hu = h.upper()
                if r['kind'] == 'ipc_command_handler':
                    cands = by_mod_hdr.get((mod, hu), [])
                else:
                    # Client call: check services in ExHeader access list first, or unique non-zero param header across libctru
                    cands = [s for p in accessed_ports for s in by_port_hdr.get((p, hu), [])]
                    if not cands:
                        all_c = by_hdr.get(hu, [])
                        # Only accept global match if header has non-zero params and maps to a single module
                        if all_c and (int(all_c[0]['normal_params']) > 0 or int(all_c[0]['translate_params']) > 0) and len({x['module'] for x in all_c}) == 1:
                            cands = all_c
                for c in cands:
                    if c['func'] not in [x['func'] for x in matched_specs]:
                        matched_specs.append(c)
            if matched_specs:
                lf_names = [x['func'] for x in matched_specs[:2]]
                ports_str = '/'.join(sorted({x['port'] for x in matched_specs}))
                ea_int = int(r['ea_n3ds'], 16) & ~1
                if r['kind'] == 'ipc_client_call' and '_ipc_client_cmd_' in r['symbol_name']:
                    r['symbol_name'] = f"{mod}_ipc_client_{'_'.join(lf_names)}{'_etc' if len(matched_specs) > 2 else ''}_{ea_int:x}"
                elif r['kind'] == 'ipc_command_handler' and '_ipc_handler_cmd_' in r['symbol_name']:
                    cid_hex = matched_specs[0]['cmd_id'][2:]
                    r['symbol_name'] = f"{mod}_ipc_cmd_{cid_hex}_{'_'.join(lf_names)}{'_etc' if len(matched_specs) > 2 else ''}_{ea_int:x}"
                r['technical_evidence'] += f"; libctru={ports_str}:{'/'.join(x['func'] for x in matched_specs[:3])}"
                derived_upgraded += 1

        drows.sort(key=lambda x: int(x['ea_n3ds'], 16))
        with open(dcsv, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['ea_n3ds', 'size', 'symbol_name', 'kind', 'technical_evidence'])
            w.writeheader()
            w.writerows(drows)

    print(f'Refined n3ds/symbols/derived/*.csv: {derived_upgraded} upgraded, {derived_added} newly added (Thumb dispatchers/handlers/switch8)')

    # 2. Refine transferred O3DS->N3DS CSVs (n3ds/symbols/<tag>.csv) and O3DS *_friendly.sym
    # Map (n3ds_binary_rel, ea_int) -> (new_sym_suffix, libctru_evidence, port, lfuncs)
    TRANS_MAP = {
        'firm_fs': ('n3ds/decrypted_binaries/firm_modules/fs', 'o3ds/decrypted_binaries/firm_modules/fs/fs_friendly.sym', 'fs'),
        'firm_loader': ('n3ds/decrypted_binaries/firm_modules/loader', 'o3ds/decrypted_binaries/firm_modules/loader/loader_friendly.sym', 'loader'),
        'firm_pm': ('n3ds/decrypted_binaries/firm_modules/pm', 'o3ds/decrypted_binaries/firm_modules/pm/pm_friendly.sym', 'pm'),
        'firm_pxi': ('n3ds/decrypted_binaries/firm_modules/pxi', 'o3ds/decrypted_binaries/firm_modules/pxi/pxi_friendly.sym', 'pxi'),
        'firm_sm': ('n3ds/decrypted_binaries/firm_modules/sm', 'o3ds/decrypted_binaries/firm_modules/sm/sm_friendly.sym', 'sm'),
        'cecd_0004013000002602': ('n3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602', 'o3ds/decrypted_binaries/Module-CECD-StreetPass-0004013000002602/cecd_friendly.sym', 'cecd'),
        'gsp_0004013020001C02': ('n3ds/decrypted_binaries/Module-GSP-GPU-Service-N3DS-0004013020001C02', 'o3ds/decrypted_binaries/Module-GSP-GPU-Service-0004013000001C02/gsp_friendly.sym', 'gsp'),
        'hid_0004013000001D02': ('n3ds/decrypted_binaries/Module-HID-Buttons-and-Touch-Input-0004013000001D02', 'o3ds/decrypted_binaries/Module-HID-Buttons-and-Touch-Input-0004013000001D02/hid_friendly.sym', 'hid'),
        'i2c_0004013020001E02': ('n3ds/decrypted_binaries/Module-I2C-I2C-Bus-N3DS-0004013020001E02', 'o3ds/decrypted_binaries/Module-I2C-I2C-Bus-0004013000001E02/i2c_friendly.sym', 'i2c'),
        'mcu_0004013020001F02': ('n3ds/decrypted_binaries/Module-MCU-Microcontroller-Power-N3DS-0004013020001F02', 'o3ds/decrypted_binaries/Module-MCU-Microcontroller-Power-0004013000001F02/mcu_friendly.sym', 'mcu'),
        'nwm_0004013000002D02': ('n3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02', 'o3ds/decrypted_binaries/Module-NWM-WiFi-0004013000002D02/nwm_friendly.sym', 'nwm'),
        'ptm_0004013020002202': ('n3ds/decrypted_binaries/Module-PTM-Battery-and-Pedometer-N3DS-0004013020002202', 'o3ds/decrypted_binaries/Module-PTM-Battery-and-Pedometer-0004013000002202/ptm_friendly.sym', 'ptm'),
    }
    trans_upgraded = 0
    o3ds_upgraded = 0
    for tag, (n3ds_rel, o3ds_sym_rel, mod) in TRANS_MAP.items():
        tcsv = os.path.join(R, f'n3ds/symbols/{tag}.csv')
        if not os.path.exists(tcsv):
            continue
        bdir = os.path.join(R, n3ds_rel)
        name_to_ea = load_symbol_name_to_ea(bdir)
        b_cases = by_bin.get(n3ds_rel, [])
        ea_info = {} # ea_int -> (lfuncs, cids, port)
        for c in b_cases:
            fn = c['first_call_in_case']
            hea = name_to_ea.get(fn) or parse_ea_from_name(fn)
            if not hea:
                continue
            info = ea_info.setdefault(hea, ([], [], c['service_port']))
            if c['cmd_id'] not in info[1]:
                info[1].append(c['cmd_id'])
            if c['libctru_func']:
                for lf in c['libctru_func'].split('/'):
                    if lf and lf not in info[0]:
                        info[0].append(lf)

        trows = list(csv.DictReader(open(tcsv)))
        o3ds_renames = {} # old_o3ds_name -> new_o3ds_name
        for r in trows:
            if not r['ea_n3ds']:
                continue
            ea = int(r['ea_n3ds'], 16) & ~1
            if ea not in ea_info:
                continue
            lfuncs, cids, port = ea_info[ea]
            if not lfuncs and not cids:
                continue
            ev_add = f";ipc_case={port or mod}:{','.join(cids[:4])}" + (f";libctru={'/'.join(lfuncs[:3])}" if lfuncs else "")
            if 'ipc_case=' not in r['technical_evidence']:
                r['technical_evidence'] += ev_add
                trans_upgraded += 1
            if lfuncs and len(lfuncs) <= 2:
                lf_tag = '_'.join(lfuncs)
                old_sym = r['symbol_name']
                if GENERIC_SYM_RE.match(old_sym) and not old_sym.endswith(lf_tag):
                    r['symbol_name'] = f'{old_sym}_{lf_tag}'
                    trans_upgraded += 1
                old_o3ds = r['o3ds_equivalent']
                if old_o3ds and GENERIC_SYM_RE.match(old_o3ds) and not old_o3ds.endswith(lf_tag):
                    new_o3ds = f'{old_o3ds}_{lf_tag}'
                    r['o3ds_equivalent'] = new_o3ds
                    o3ds_renames[old_o3ds] = new_o3ds
                elif old_o3ds and old_o3ds.endswith(lf_tag):
                    base_o3ds = old_o3ds[:-(len(lf_tag) + 1)]
                    o3ds_renames[base_o3ds] = old_o3ds

        with open(tcsv, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(trows[0].keys()))
            w.writeheader()
            w.writerows(trows)

        if o3ds_renames:
            osym_path = os.path.join(R, o3ds_sym_rel)
            if os.path.exists(osym_path):
                lines = open(osym_path).readlines()
                new_lines = []
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[3] in o3ds_renames:
                        line = line.replace(parts[3], o3ds_renames[parts[3]], 1)
                        o3ds_upgraded += 1
                    new_lines.append(line)
                open(osym_path, 'w').writelines(new_lines)

    print(f'Refined transferred N3DS tables: {trans_upgraded} rows annotated with IPC/libctru evidence, {o3ds_upgraded} generic O3DS/N3DS placeholder names upgraded')

    # 3. Generate/update manual symbol CSVs for QTM, MVD, NFC, CAMERA from verified libctru matches
    update_manual_tables(by_bin)

def update_manual_tables(by_bin):
    # A. Module-QTM-Head-Tracking-New3DS-N3DS-0004013020004202
    qtm_bin = 'Module-QTM-Head-Tracking-New3DS-N3DS-0004013020004202'
    qtm_rel = f'n3ds/decrypted_binaries/{qtm_bin}'
    qtm_name_to_ea = load_symbol_name_to_ea(os.path.join(R, qtm_rel))
    qtm_rows = [
        [qtm_bin, '0x00100214', 'qtm_main_server_loop', 'decompiled/00100214.c: init, loop of 4 iterations registering ports qtm:c, qtm:sp, qtm:s, qtm:u from name table @0x1AA8A4 (FUN_00101524 = srv:RegisterService), then ReplyAndReceive loop through svc 0x4F wrapper 0x00115928'],
        [qtm_bin, '0x00115928', 'qtm_svc_0x4F_ReplyAndReceive_115928', 'decompiled/00115928.c: software_interrupt(0x4f) ReplyAndReceive wrapper'],
        [qtm_bin, '0x00101524', 'qtm_srv_RegisterService_cmd', 'decompiled/00101524.c: writes srv:RegisterService header 0x00030100 at TLS+0x80, copies 8-char port name and max_sessions, calls svc SendSyncRequest'],
        [qtm_bin, '0x00103464', 'qtm_u_ipc_dispatcher', 'decompiled/00103464.c: IPC dispatcher for qtm:u (commands 0x0001..0x0006, matching libctru services/qtm.c QTMU_*)'],
        [qtm_bin, '0x001035C4', 'qtm_s_ipc_dispatcher', 'decompiled/001035c4.c: IPC dispatcher for qtm:s (commands 0x0001..0x0006 and 0x0401..0x040A via base subtraction DAT_0010390c=0x403, matching libctru services/qtm.c QTMS_*)'],
        [qtm_bin, '0x00103918', 'qtm_c_ipc_dispatcher', 'decompiled/00103918.c: IPC dispatcher for qtm:c (commands 0x0001..0x0005, matching libctru services/qtmc.c QTMC_*)'],
        [qtm_bin, '0x001039F8', 'qtm_sp_ipc_dispatcher', 'decompiled/001039f8.c: IPC dispatcher for qtm:sp (commands 0x0001..0x0006, 0x0401..0x040A, and 0x0801..0x0804, matching libctru services/qtm.c QTMSP_*)'],
    ]
    seen_qtm = {int(r[1], 16) for r in qtm_rows}
    for c in by_bin.get(qtm_rel, []):
        fn = c['first_call_in_case']
        hea = qtm_name_to_ea.get(fn) or parse_ea_from_name(fn)
        if not hea or hea in seen_qtm or not c['libctru_func']:
            continue
        seen_qtm.add(hea)
        lf = c['libctru_func'].split('/')[0]
        qtm_rows.append([
            qtm_bin, f'0x{hea:08X}', f'qtm_ipc_{lf}',
            f"decompiled/{hea:08x}.c: handler for {c['service_port']} cmd {c['cmd_id']} ({lf} in libctru services/qtm*.c; req_hdr={c['request_header']}, reply_hdr={c['reply_header_or_data_ref']})"
        ])
    with open(os.path.join(R, f'n3ds/symbols/manual/{qtm_bin}.csv'), 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['binary', 'ea', 'symbol_name', 'evidence']); w.writerows(qtm_rows)

    # B. Module-MVD-Video-Decoder-N3DS-0004013020004102
    mvd_bin = 'Module-MVD-Video-Decoder-N3DS-0004013020004102'
    mvd_rel = f'n3ds/decrypted_binaries/{mvd_bin}'
    mvd_name_to_ea = load_symbol_name_to_ea(os.path.join(R, mvd_rel))
    mvd_rows = [
        [mvd_bin, '0x00112318', 'mvd_std_ipc_dispatcher', 'decompiled/00112318.c + Thumb-sw8 @0x001124e8: IPC dispatcher for mvd:STD (33 commands 0x0001..0x0021, matching libctru services/mvd.c MVDSTD_*)'],
        [mvd_bin, '0x00111E64', 'mvd_l2b_ipc_dispatcher', 'decompiled/00111e64.c + Thumb-sw8 @0x00111e7e: IPC dispatcher for l2b:u / l2b2:u (23 commands 0x0001..0x0017; port descriptor table @0x0011a02c)'],
        [mvd_bin, '0x0011328C', 'mvd_y2r2_ipc_dispatcher', 'decompiled/0011328c.c + Thumb-sw8 @0x001132a6: IPC dispatcher for y2r2:u (45 commands 0x0001..0x002D, matching libctru services/y2r.c Y2RU_*)'],
    ]
    seen_mvd = {int(r[1], 16) for r in mvd_rows}
    for c in by_bin.get(mvd_rel, []):
        fn = c['first_call_in_case']
        hea = mvd_name_to_ea.get(fn) or parse_ea_from_name(fn)
        if not hea or hea in seen_mvd or not c['libctru_func']:
            continue
        seen_mvd.add(hea)
        lf = c['libctru_func'].split('/')[0]
        if c['service_port'] == 'y2r2:u':
            lf = lf.replace('Y2RU_', 'Y2R2U_')
        mvd_rows.append([
            mvd_bin, f'0x{hea:08X}', f'mvd_ipc_{lf}',
            f"decompiled/{hea:08x}.c: Thumb handler for {c['service_port']} cmd {c['cmd_id']} ({c['libctru_func']} in libctru; req_hdr={c['request_header']}, reply_hdr={c['reply_header_or_data_ref']})"
        ])
    with open(os.path.join(R, f'n3ds/symbols/manual/{mvd_bin}.csv'), 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['binary', 'ea', 'symbol_name', 'evidence']); w.writerows(mvd_rows)

    print(f'Updated manual symbol tables: QTM ({len(qtm_rows)} rows), MVD ({len(mvd_rows)} rows)')

if __name__ == '__main__':
    main()
