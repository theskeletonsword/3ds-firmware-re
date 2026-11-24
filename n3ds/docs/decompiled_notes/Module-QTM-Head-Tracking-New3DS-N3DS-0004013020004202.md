# qtm (N3DS only, `0004013020004202`) - manual & libctru-verified notes

* **Overview**: N3DS-only Super-Stable 3D head-tracking sysmodule (`Module-QTM-Head-Tracking-New3DS-N3DS-0004013020004202`). Registers four ports `qtm:c`, `qtm:sp`, `qtm:s`, `qtm:u` (names adjacent in `.data` at `0x001AA8A4..0x001AA8B7`); consumes `cam:q`, `gpio:QTM`, `hid:QTM`, `i2c::QTM`, `cfg:s`, `ptm:s`. Embeds the cascade classifier string `face_SIRL_SVD.lbp`. `gsp` (N3DS build) and `ns` depend on it (`qtm:sp` / `qtm:s`).
* **Main server loop**: `qtm_main_server_loop` (`0x00100214`): initialisation, 4-port registration via `qtm_srv_RegisterService_cmd` (`0x00101524`), and `ReplyAndReceive` loop through `qtm_svc_0x4F_ReplyAndReceive_115928` (`0x00115928`).
* **IPC Dispatchers (all 4 ports identified and matched 100% against `libctru` `services/qtm.c` and `services/qtmc.c`)**:
  1. `qtm_u_ipc_dispatcher` @ `0x00103464` -> serves **`qtm:u`** (6 commands: `0x0001..0x0006`)
  2. `qtm_s_ipc_dispatcher` @ `0x001035C4` -> serves **`qtm:s`** (16 commands: `0x0001..0x0006` + `0x0401..0x040A`, using `DAT_0010390c = 0x403` base subtraction and `if` checks for `0x0401`/`0x0402`)
  3. `qtm_sp_ipc_dispatcher` @ `0x001039F8` -> serves **`qtm:sp`** (20 commands: `0x0001..0x0006` + `0x0401..0x040A` + `0x0801..0x0804`)
  4. `qtm_c_ipc_dispatcher` @ `0x00103918` -> serves **`qtm:c`** (5 commands: `0x0001..0x0005`)

## Complete IPC Command & Handler Table

| Port(s) | Cmd ID | Request Header | Reply Header | Handler EA | Symbol Name (`libctru`) | Verified Behaviour in Decompiled C |
|---|---|---|---|---|---|---|
| `qtm:u`, `qtm:s`, `qtm:sp` | `0x0001` | `0x00010080` | `0x00010340` | `0x00113A38` | `qtm_ipc_QTMU_GetRawTrackingDataEx` | Copies raw tracking struct (12 words = 48 bytes) into `cmdbuf[2..13]` |
| `qtm:u`, `qtm:s`, `qtm:sp` | `0x0002` | `0x00020080` | `0x00020400` | `0x001137E0` | `qtm_ipc_QTMU_GetTrackingDataEx` | 564-byte function computing 4 floating-point head-tracking coordinates (`cmdbuf[2..15]`) |
| `qtm:u`, `qtm:s`, `qtm:sp` | `0x0003` | `0x00030000` | `0x00030040` | `0x0011378C` | `qtm_ipc_QTMU_EnableManualIrLedControl` | Sets manual IR LED state byte (`+4`) to `1`, calls `0x001136AC(0)`, notifies object `+0x74` vtable slot 1 |
| `qtm:u`, `qtm:s`, `qtm:sp` | `0x0004` | `0x00040000` | `0x00040040` | `0x00113738` | `qtm_ipc_QTMU_DisableManualIrLedControl` | Calls `0x001136AC(0)`, notifies object `+0x74` vtable slot 1, clears manual IR LED state byte (`+4`) |
| `qtm:u`, `qtm:s`, `qtm:sp` | `0x0005` | `0x00050040` | `0x00050040` | `0x001136AC` | `qtm_ipc_QTMU_SetIrLedStatus` | When manual control active (`+4 == 1`), calls vtable slot 7 (`+0x1C`) of object at `+4` with `active` flag |
| `qtm:u`, `qtm:s`, `qtm:sp` | `0x0006` | `0x00060000` | `0x00060080` | `0x00113694` | `qtm_ipc_QTMU_IsCurrentAppBlacklisted` | Returns blacklist flag byte at `+0x11` of the state block |
| `qtm:s`, `qtm:sp` | `0x0401` | `0x04010040` | `0x04010040` | `0x00107430` | `qtm_ipc_QTMS_SetCentralBarrierPosition` | Sets central parallax barrier position |
| `qtm:s`, `qtm:sp` | `0x0402` | `0x04020000` | `0x04020080` | `0x001070E8` | `qtm_ipc_QTMS_GetCameraLuminance` | Returns camera luminance float (`cmdbuf[2]`) |
| `qtm:s`, `qtm:sp` | `0x0403` | `0x04030000` | `0x04030040` | `0x00114C38` | `qtm_ipc_QTMS_EnableAutoBarrierControl` | Enables automatic parallax barrier control |
| `qtm:s`, `qtm:sp` | `0x0404` | `0x04040000` | `0x04040040` | `0x0011366C` | `qtm_ipc_QTMS_DisableAutoBarrierControl` | Disables automatic parallax barrier control |
| `qtm:s`, `qtm:sp` | `0x0405` | `0x04050040` | `0x04050040` | `0x00113630` | `qtm_ipc_QTMS_SetBarrierPosition` | Manually sets parallax barrier position (`cmdbuf[1]`) |
| `qtm:s`, `qtm:sp` | `0x0406` | `0x04060000` | `0x04060080` | `0x00113604` | `qtm_ipc_QTMS_GetCurrentBarrierPosition` | Returns current parallax barrier position (`cmdbuf[2]`) |
| `qtm:s`, `qtm:sp` | `0x0407` | `0x04070040` | `0x04070040` | `0x0011238C` | `qtm_ipc_QTMS_SetIrLedStatusOverride` | Sets IR LED override state (`cmdbuf[1]`) |
| `qtm:s`, `qtm:sp` | `0x0408` | `0x04080140` | `0x04080040` | `0x00113594` | `qtm_ipc_QTMS_SetCalibrationData` | Applies 16-byte `QtmCalibrationData` (`cmdbuf[1..4]`) and save flag (`cmdbuf[5]`) |
| `qtm:s`, `qtm:sp` | `0x0409` | `0x04090000` | `0x04090080` | `0x0011357C` | `qtm_ipc_QTMS_GetQtmStatus` | Returns `QtmStatus` byte (`cmdbuf[2]`) |
| `qtm:s`, `qtm:sp` | `0x040A` | `0x040A0040` | `0x040A0040` | `0x00113514` | `qtm_ipc_QTMS_SetQtmStatus` | Updates `QtmStatus` byte (`cmdbuf[1]`) |
| `qtm:sp` | `0x0801` | `0x08010040` | `0x08010040` | `0x0011349C` | `qtm_ipc_QTMSP_NotifyTopLcdModeChange` | Notifies QTM of top LCD 2D/3D mode change (`cmdbuf[1]`) |
| `qtm:sp` | `0x0802` | `0x08020000` | `0x08020040` | `0x00113428` | `qtm_ipc_QTMSP_NotifyTopLcdPowerOn` | Notifies QTM that top LCD powered on |
| `qtm:sp` | `0x0803` | `0x08030000` | `0x08030080` | `0x00112358` | `qtm_ipc_QTMSP_IsExpanderInUse` | Returns bool indicating whether I2C GPIO expander is active |
| `qtm:sp` | `0x0804` | `0x08040000` | `0x08040040` | `0x001133C0` | `qtm_ipc_QTMSP_NotifyTopLcdPowerOff` | Notifies QTM that top LCD powered off |
| `qtm:c` | `0x0001` | `0x00010000` | `0x00010040` | `0x00105A90` | `qtm_ipc_QTMC_StartHardwareCheck` | Starts factory/calibration QTM hardware check |
| `qtm:c` | `0x0002` | `0x00020000` | `0x00020040` | `0x00105A5C` | `qtm_ipc_QTMC_StopHardwareCheck` | Stops QTM hardware check |
| `qtm:c` | `0x0003` | `0x00030040` | `0x00030040` | `0x00105A30` | `qtm_ipc_QTMC_SetBarrierPattern` | Sets test barrier pattern (`cmdbuf[1]`) |
| `qtm:c` | `0x0004` | `0x00040080` | `0x00040080` | `0x0010599C` | `qtm_ipc_QTMC_WaitAndCheckExpanderWorking` | Waits for timeout (`cmdbuf[1..2]` ns) and returns expander status bool (`cmdbuf[2]`) |
| `qtm:c` | `0x0005` | `0x00050040` | `0x00050040` | `0x00105A0C` | `qtm_ipc_QTMC_SetIrLedStatusOverride` | Sets IR LED override on `qtm:c` |
