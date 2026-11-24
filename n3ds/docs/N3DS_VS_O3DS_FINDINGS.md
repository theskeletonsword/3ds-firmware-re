# N3DS vs O3DS – what transferred, what changed, what is new

Both sides are system version **NATIVE_FIRM 31.58.1** (title version 32673 in both CIAs), so differences are model differences, not version drift
(the sysmodules carry their own title versions, e.g. `nwm` 11.0.0, N3DS `gsp` 14.0.0, N3DS `qtm` 3.0.0).

## 1. Transferred cleanly (identical bytes → symbols valid at the same addresses)

* 24 sysmodules whose TitleID is shared (`0004013000xxxxxx`): `code.bin` sha256 equal to the O3DS copy:
  ac (2402), act (3802), am (1502), boss (3402), cecd (2602), cfg (1702), codec (1802), csnd (2702), dlp (2802), dsp (1A02), friends (3202), gpio (1B02), hid (1D02), http (2902), ir (3302), ndm (2B02), news (3502), nim (2C02), ns (8002), nwm (2D02), ps (3102), ro (3702), socket (2E02), ssl (2F02).
* FIRM-embedded modules `fs`, `loader`, `pxi`, `sm` (identical to O3DS `firm_modules/*`).
* Of the O3DS symbol-bearing binaries this gives 100 % `exact` for `fs` (1 572), `loader` (115), `pxi` (111), `sm` (107), `cecd` (1 676), `hid` (263), `nwm` (2 784).
  These include the O3DS IPC handler names (`nwm_ipc_*`, `fs_*`, …) because the code is the same file.

## 2. Transferred with byte-level work (different builds)

Placement after all refinement passes (full per-level table: [`STATS.md`](STATS.md)); "unresolved" are the only symbols of the O3DS reference without a consistent N3DS counterpart:

| Component | O3DS symbols | placed | unresolved |
|---|---|---|---|
| ARM9 Kernel9+Process9 (NATIVE_FIRM) | 4 849 | 4 809 | 40 (35 are tiny virtual-method / vtable-slot stubs and Thumb interworking helpers that are byte-identical to many other stubs; 4 are early-boot MPU/AES/CFG9 setup functions that differ in N3DS) |
| ARM11 Kernel11 (NATIVE_FIRM) | 838 | 822 | 16 (boot-time functions `arm11_core_bringup_init`, `arm11_mmu_and_scu_enable`, `k11_kernel_sync_barrier_on_boot`, `k11_boot_enable_cpacr_vfp`; cache/MMU helpers; a few small stubs — their code differs from O3DS) |
| FIRM module `pm` | 142 | 142 | 0 |
| `gsp` (N3DS `…20001C02`) | 352 | 343 | 9 (large functions rewritten for N3DS: GX command queue, IRQ handler, …) |
| `i2c` (N3DS `…20001E02`) | 153 | 153 | 0 |
| `mcu` (N3DS `…20001F02`) | 257 | 256 | 1 |
| `ptm` (N3DS `…20002202`) | 769 | 769 | 0 |
| ARM9 / Kernel11 of SAFE_MODE_FIRM (older build) | 4 849 / 838 | 4 550 / 759 | 299 / 79 |

`adapted_n3ds` rows keep the underlying match level in column `match_basis` (exact 4 177, probable_by_transfer 4 152, callgraph 625, layout 174, …); most are mechanical address re-writes of names such as `k9_swi_helper_0x08025F8E`.

Spot checks that confirm placement:

| Symbol | O3DS | N3DS | Evidence |
|---|---|---|---|
| `p9_movable_sed_path_handler` | `0x08025EA4` | `0x08025CA4` | exact bytes; UTF-16 `movable` string at +0x62 in both (REA `search_bytes`) |
| `p9_memcpy` | `0x08056CBC` | `0x08056ABC` | exact bytes |
| `k9_swi_0x7B_Backdoor` | `0x08007B30` | `0x08007B2C` | exact bytes |
| `arm11_firm_entry_point` | `0x1FFAE034` | `0x1FFAF064` | FIRM header ARM11 entrypoint (ctrtool) |
| `kernel11_exception_vectors` | `0x1FFAD000` | `0x1FFAE000` | masked bytes, unique |

## 3. Changed / new in N3DS

### FIRM level
| | O3DS NATIVE_FIRM | N3DS NATIVE_FIRM |
|---|---|---|
| ARM11 entrypoint | `0x1FFAE034` | `0x1FFAF064` |
| ARM9 entrypoint | `0x0801B01C` (Kernel9 start) | `0x0808AA3C` (**arm9loader**, new) |
| Section 0 (ARM11 modules) | `0x1FF00000`, 0x35600 | `0x1FF00000`, 0x35800 |
| Section 1 (Kernel11) | `0x1FF80000`, 0x32000 | `0x1FF80000`, 0x34000 |
| Section 2 (ARM9) | `0x08006800`, 0x84200 – plain | `0x08006000`, 0x8A400 – 0x800 header + **K9L2-encrypted** ARM9 (540 928 B) + plain arm9loader tail |
| Embedded NCCH modules | fs, loader, pm, sm, pxi | same five; `pm` differs (25 symbols unresolved) |

N3DS Kernel9+Process9 is functionally the O3DS code (≈ 70 % of 32-byte chunks identical, shifted by −0x200 at the Process9 start, e.g. `0x08025EA4 → 0x08025CA4`).
`arm9loader` (`arm9loader_tail.bin`, 23 296 B at `0x0808A900`) has no O3DS counterpart. Its entry `0x0808AA3C` begins with the usual ARM9 reset stub
(`mrs r0,cpsr; orr r0,r0,#0x80; msr cpsr_c,r0; mov r0,#0x78; mcr p15…`).

### Sysmodules that exist as separate N3DS builds (`00040130 20xxxxxx`) – ExHeader / code deltas vs O3DS counterpart
Generated from `symbols/N3DS_MODULE_INVENTORY.csv`. All N3DS ExHeaders show `System mode (New3DS) = ctr prod (AppMemory: 64MB)`, `CPU Speed (New3DS) = 268MHz`, `Enable L2 Cache = NO` (i.e. these modules do not opt into the N3DS 804 MHz / L2 mode), so those fields are not differences.

| N3DS TitleID | Module (ExHeader name) | O3DS counterpart | Relation | Code size N3DS / O3DS | Deltas (O3DS → N3DS) |
|---|---|---|---|---|---|
| `0004013020002403` | ac | `0004013000002403` | differs_from_O3DS | 151552 / 139264 | text:0x0001A3B8->0x0001D760; ro:0x000013DC->0x000015B0; data:0x00004858->0x00004B04; bss:0x0001BB68->0x0001A248 |
| `0004013020001503` | am | `0004013000001503` | differs_from_O3DS | 81920 / 45056 | text:0x00008CC4->0x00011BA8; ro:0x000006B4->0x00000BD4; data:0x000002A4->0x000004DC; bss:0x00006464->0x00004DE0; services_added:fs:USER |
| `0004013020001602` | camera | `0004013000001602` | differs_from_O3DS | 122880 / 98304 | text:0x0000ED04->0x000143E4; ro:0x000006F8->0x00007EF4; data:0x00007C6C->0x00000634; bss:0x00002150->0x0000270C |
| `0004013020001703` | cfg | `0004013000001703` | differs_from_O3DS | 57344 / 45056 | text:0x00007A94->0x0000AA34; ro:0x00001510->0x0000191C; data:0x000008E4->0x00000D08; bss:0x0000A680->0x0000A6E0 |
| `0004013020001803` | codec | `0004013000001803` | differs_from_O3DS | 40960 / 40960 | text:0x00007250->0x0000722C; ro:0x00000370->0x00000404; data:0x00000114->0x00000168; bss:0x000022E8->0x00002308; services_removed:SPI::CD1,SPI::PMC |
| `0004013020002703` | csnd | `0004013000002703` | differs_from_O3DS | 36864 / 32768 | text:0x00005E88->0x000061F0; ro:0x000001B8->0x0000023C; data:0x00000110->0x0000010C; bss:0x00000BE4->0x00000C1C |
| `0004013020001A03` | dsp | `0004013000001A03` | differs_from_O3DS | 40960 / 40960 | text:0x00007570->0x000077E0; ro:0x00000210->0x000002BC; data:0x00000318->0x00000354; bss:0x0000409C->0x000040C8 |
| `0004013020003203` | friends | `0004013000003203` | differs_from_O3DS | 413696 / 376832 | text:0x0004FB84->0x00056CEC; ro:0x0000A634->0x0000AFDC; data:0x000007C4->0x00002A90; bss:0x000B5AB4->0x000AD9E4 |
| `0004013020001B03` | gpio | `0004013000001B03` | differs_from_O3DS | 20480 / 20480 | text:0x00002A1C->0x00002E08; ro:0x00000238->0x000002BC; data:0x000000A0->0x000000B0; bss:0x000006E4->0x0000072C |
| `0004013020001C02` | gsp | `0004013000001C02` | differs_from_O3DS | 69632 / 61440 | text:0x0000C5B8->0x0000E300; ro:0x00000378->0x000004F8; data:0x00000278->0x0000029C; bss:0x000018EC->0x00001B4C; dep:None->0004013020004202; services_added:qtm:sp |
| `0004013020001C03` | gsp | `0004013000001C03` | differs_from_O3DS | 65536 / 61440 | text:0x0000C4B0->0x0000DBD8; ro:0x000002D0->0x000004F4; data:0x00000228->0x0000027C; bss:0x0000184C->0x00001A00; services_added:qtm:s; services_removed:gpio:GXS |
| `0004013020001D03` | hid | `0004013000001D03` | differs_from_O3DS | 53248 / 45056 | text:0x00008B18->0x000092B4; ro:0x0000025C->0x000012D8; data:0x00000A88->0x00000B08; bss:0x00000B08->0x00000B74 |
| `0004013020002903` | http | `0004013000002903` | differs_from_O3DS | 114688 / 110592 | text:0x000186D0->0x00019800; ro:0x000009C0->0x00000B0C; data:0x000002EC->0x000003F0; bss:0x00004320->0x0000561C; prio:50->58; services_added:ptm:s |
| `0004013020001E02` | i2c | `0004013000001E02` | differs_from_O3DS | 32768 / 28672 | text:0x00004740->0x00005394; ro:0x0000025C->0x0000027C; data:0x000000B0->0x000000C8; bss:0x00002200->0x00004E10 |
| `0004013020001E03` | i2c | `0004013000001E03` | differs_from_O3DS | 32768 / 28672 | text:0x00004BB4->0x000059A4; ro:0x00000224->0x0000027C; data:0x00000094->0x000000C8; bss:0x000021B8->0x00004DD0 |
| `0004013020003303` | ir | `0004013000003303` | differs_from_O3DS | 77824 / 32768 | text:0x00005830->0x0000FB28; ro:0x000001FC->0x000014D0; data:0x000000D8->0x0000051C; bss:0x00000E8C->0x00002094; prio:40->27; services_added:cfg:s |
| `0004013020001F02` | mcu | `0004013000001F02` | differs_from_O3DS | 61440 / 61440 | text:0x00008290->0x0000832C; ro:0x0000023C->0x00004240; data:0x000040D8->0x000000D8; bss:0x00002DE8->0x00002E28 |
| `0004013020001F03` | mcu | `0004013000001F03` | differs_from_O3DS | 61440 / 61440 | text:0x00008510->0x00008250; ro:0x00000200->0x0000023C; data:0x000040D4->0x000040DC; bss:0x00002DC8->0x00002DEC |
| `0004013020004102` | mvd | — | N3DS_only | 139264 / — | no O3DS counterpart present in o3ds/decrypted_binaries |
| `0004013020004002` | nfc | `0004013000004002` | differs_from_O3DS | 245760 / 110592 | text:0x000165FC->0x00034A64; ro:0x00001C00->0x000041E0; data:0x000018CC->0x0000149C; bss:0x0000F204->0x0002CC00; dep:0004013000001702->None; services_added:cfg:s,gpio:NFC,hid:NFC,i2c::NFC; services_removed:cfg:u,ir:USER |
| `0004013020002C03` | nim | `0004013000002C03` | differs_from_O3DS | 385024 / 225280 | text:0x00034BA8->0x0005A8E0; ro:0x00000E18->0x00001AAC; data:0x00000730->0x000008BC; bss:0x00185844->0x0018C7E4; services_added:ptm:gets; services_removed:ssl:C |
| `0004013020008003` | ns | `0004013000008003` | differs_from_O3DS | 143360 / 110592 | text:0x00017074->0x0001D2F0; ro:0x000008E0->0x00001520; data:0x00001F70->0x00002420; bss:0x000FAD8C->0x000F31BC; services_added:cam:s,qtm:s |
| `0004013020002D03` | nwm | `0004013000002D03` | differs_from_O3DS | 348160 / 327680 | text:0x0003804C->0x0003C824; ro:0x00002364->0x00002854; data:0x00013C40->0x00014D60; bss:0x0000CA64->0x0000AEE8; dep:0004013000001f03->0004013000001703; services_added:cfg:u; services_removed:fs:USER |
| `0004013020002103` | pdn | `0004013000002103` | differs_from_O3DS | 20480 / 16384 | text:0x00001D9C->0x00002364; ro:0x00000204->0x0000023C; data:0x00000088->0x00000090; bss:0x00000654->0x0000067C |
| `0004013020003103` | ps | `0004013000003103` | differs_from_O3DS | 28672 / 24576 | text:0x00003B24->0x00004378; ro:0x00000254->0x000002B8; data:0x000002B0->0x00000388; bss:0x00000D58->0x00000F80 |
| `0004013020002202` | ptm | `0004013000002202` | differs_from_O3DS | 61440 / 61440 | text:0x0000C4DC->0x0000C4F0 |
| `0004013020002203` | ptm | `0004013000002203` | differs_from_O3DS | 61440 / 53248 | text:0x0000AD48->0x0000C330; ro:0x00000810->0x000008A4; data:0x00000368->0x00000484; bss:0x00004EA0->0x000034AC |
| `0004013020004202` | qtm | — | N3DS_only | 704512 / — | no O3DS counterpart present in o3ds/decrypted_binaries |
| `0004013020002E03` | socket | `0004013000002E03` | differs_from_O3DS | 208896 / 217088 | text:0x00032B6C->0x00030FB0; ro:0x0000043C->0x000004C8; bss:0x0000E5DC->0x000099F0; prio:51->59 |
| `0004013020002302` | spi | `0004013000002302` | differs_from_O3DS | 24576 / 24576 | text:0x000036F0->0x00003720; data:0x0000007C->0x00000080; bss:0x000005B4->0x000005B8 |
| `0004013020002303` | spi | `0004013000002303` | differs_from_O3DS | 24576 / 24576 | text:0x000034A4->0x00003720; ro:0x000001AC->0x000001E4; data:0x00000078->0x00000080; bss:0x00000594->0x000005B8 |
| `0004013020002F03` | ssl | `0004013000002F03` | differs_from_O3DS | 356352 / 356352 | text:0x00044A98->0x00045BB0; ro:0x00007068->0x00007000; data:0x00009050->0x000092A0; bss:0x00003678->0x0000930C; prio:50->58; services_removed:soc:P |

Notable verified N3DS-specific facts from those rows:

* **`gsp` (`0004013020001C02`)** gains the service `qtm:sp` and an explicit ExHeader dependency on `0004013020004202` (qtm): the GPU service talks to the new head-tracking module (New-3DS stable-3D). The N3DS safe-mode gsp (`…1C03`) uses `qtm:s` instead of `gpio:GXS`.
* **`qtm` (`0004013020004202`)** is N3DS-only: 245 760 B code, services used `cam:q`, `cfg:s`, `gpio:QTM`, `hid:QTM`, `i2c::QTM`, `ptm:s` (ExHeader) and `srv:pm` (string), embedded face-detection data (`face_SIRL_SVD.lbp`, `<METADATA>`); SVC numbers present in code: `00 01 02 03 08 09 0A 13 17 18 1F 20 21 22 23 24 25 27 28 2B 2D 32 35 3C 4A 4F`.
* **`ns` (`…8003`, safe mode)** additionally uses `cam:s`, `qtm:s`.
* **`nfc` (`…4002`)** is a different build: services `cfg:s gpio:NFC hid:NFC i2c::NFC` added, `cfg:u`/`ir:USER` removed (verified from ExHeader); code is 245 760 B in N3DS vs 110 592 B in O3DS.
* **`mvd` (`…4102`)** has no O3DS counterpart in `o3ds/decrypted_binaries/` (ExHeader name `mvd`).
* **`ptm` (`…2202`)** differs from O3DS only by +0x14 bytes of `.text` (O3DS 0xC4DC → N3DS 0xC4F0): 611 of 769 symbols match byte-exactly, which makes it a good reference build for diffing.
* Safe-mode (`…03`) N3DS modules no longer allow SVCs `04 05 07 0D 0E 10` and often use newer service sets (e.g. `http` adds `ptm:s`, `nim` adds `ptm:gets`, drops `ssl:C`).

## 4. Derived (no O3DS reference)
Every module has `derived_structural` rows in `symbols/N3DS_SYMBOL_TABLE.csv` (`symbols/derived/<TID>.csv`): SVC wrappers named after their SVC, IPC handler / client-call / dispatcher candidates with the header constants they use (`symbols/N3DS_IPC_COMMANDS.csv`), service-name strings and pointer tables.
For the N3DS-only `qtm`: ports `qtm:c`, `qtm:sp`, `qtm:s`, `qtm:u` sit together in `.data` at `0x1AA8A4..0x1AA8B7` (no `qtm:*` name is in its ExHeader access list, i.e. they are ports the module registers); `cam:q`, `gpio:QTM`, `i2c::QTM`, `cfg:s`, `hid:QTM`, `ptm:s` are the services it consumes; 4 SVC wrappers and 3 reply-header writers (replies `0x00010340`, `0x00030040`, `0x00040040`, `0x00050040`, `0x00060080`) were named.

## 5. Not covered / uncertain
See [`PENDING.md`](PENDING.md).
