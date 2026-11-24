# mvd (N3DS only, `0004013020004102`) - manual & libctru-verified notes

* **Overview**: N3DS-only hardware video decoder and colour-space / line-to-block converter sysmodule (`Module-MVD-Video-Decoder-N3DS-0004013020004102`).
* **Registered Service Ports** (port table in `.rodata` at `0x0011A02C..0x0011A05B`):
  1. `mvd:STD` (max sessions = 1) -> Thumb-sw8 dispatcher `mvd_std_ipc_dispatcher` (`0x00112318`, switch @ `0x001124E8`, 33 commands `0x0001..0x0021`, matched to `libctru` `services/mvd.c` `MVDSTD_*`).
  2. `l2b:u` and `l2b2:u` (max sessions = 2 each) -> Thumb-sw8 dispatcher `mvd_l2b_ipc_dispatcher` (`0x00111E64`, switch @ `0x00111E7E`, 23 commands `0x0001..0x0017`, H.264 line-to-block hardware converter).
  3. `y2r2:u` (max sessions = 4) -> Thumb-sw8 dispatcher `mvd_y2r2_ipc_dispatcher` (`0x0011328C`, switch @ `0x001132A6`, 45 commands `0x0001..0x002D`, second YUV-to-RGB hardware block using the exact `services/y2r.c` `Y2RU_*` protocol).
* **Manual symbols**: `n3ds/symbols/manual/Module-MVD-Video-Decoder-N3DS-0004013020004102.csv` (61 verified symbols: 3 dispatchers, 14 `MVDSTD_*` handlers, and 44 `Y2R2U_*` handlers).

## `mvd:STD` IPC Command Table (`mvd_std_ipc_dispatcher` @ `0x00112318`)

| Cmd ID | Request Header | Reply Header | Handler EA | Symbol Name (`libctru` / structural) |
|---|---|---|---|---|
| `0x0001` | `0x00010142` | `0x00010040` | `0x0010DA20` | `mvd_ipc_MVDSTD_Initialize` |
| `0x0002` | `0x00020000` | `0x00020040` | `0x0010DB28` | `mvd_ipc_MVDSTD_Shutdown` |
| `0x0003` | `0x00030302` | `0x00030040` | `0x0010B55C` | `mvd_ipc_MVDSTD_CalculateWorkBufSize` |
| `0x0004` | `0x00040102` | `0x00040040` | `0x0010DC00` | `mvd_mvd_std_ipc_cmd_0004_handler_10dc00` |
| `0x0005` | `0x00050042` | `0x00050040` | `0x0010DC94` | `mvd_mvd_std_ipc_cmd_0005_handler_10dc94` |
| `0x0006` | `0x00060000` | `0x00060040` | `0x0010DCFC` | `mvd_mvd_std_ipc_cmd_0006_handler_10dcfc` |
| `0x0007` | `0x00070040` | `0x00070040` | `0x0010DD3C` | `mvd_mvd_std_ipc_cmd_0007_handler_10dd3c` |
| `0x0008` | `0x00080242` | `0x00080080` | `0x0010DD84` | `mvd_ipc_MVDSTD_ProcessNALUnit` |
| `0x0009` | `0x00090042` | `0x00090080` | `0x0010DE24` | `mvd_ipc_MVDSTD_ControlFrameRendering` |
| `0x000A` | `0x000A0000` | `0x000A0480` | `0x0010DEA0` | `mvd_ipc_MVDSTD_GetStatus` |
| `0x000B` | `0x000B0000` | `0x000B01C0` | `0x0010DF14` | `mvd_ipc_MVDSTD_GetConfig` |
| `0x000C` | `0x000C0184` | `0x000C0040` | `0x0010DF70` | `mvd_ipc_MVDSTD_SetConfig` |
| `0x000D` | `0x000D0982` | `0x000D0040` | `0x0010E018` | `mvd_ipc_MVDSTD_SetOutputBuffers` |
| `0x000E` | `0x000E0282` | `0x000E0040` | `0x0010E098` | `mvd_ipc_MVDSTD_OverrideOutputBuffers` |
| `0x0018` | `0x00180040` | `0x00180080` | `0x0010E4D4` | `mvd_ipc_MVDSTD_ConvertImage` |
| `0x001D` | `0x001D0040` | `0x001D0040` | `0x0010E7F4` | `mvd_ipc_MVDSTD_SetFramerate` |
| `0x001E` | `0x001E0040` | `0x001E0040` | `0x0010E84C` | `mvd_ipc_MVDSTD_SelectOutputBuffer` |
| `0x001F` | `0x001F0182` | `0x001F0040` | `0x0010E8A4` | `mvd_ipc_MVDSTD_SetupOutputBuffers` |
