# spi (N3DS build, `0004013020002302`) - manual notes

Source: `decrypted_binaries/Module-SPI-SPI-Bus-N3DS-0004013020002302/decompiled/*.c` (headless Ghidra), `analysis/derived.csv`. 114 functions, ExHeader services: none consumed.

* **Ports** (strings at `0x104058..0x104085`): `SPI::CD2`, `SPI::CS2`, `SPI::CS3`, `SPI::DEF`, `SPI::NOR`, plus `srv:`, `srv:pm`, `err:f`. The same names appear in the access lists of other modules (e.g. `cfg` uses `SPI::NOR`, `codec` uses `SPI::CD2`), confirming they are the ports this module serves.
* **IPC dispatcher** `0x10104C` (`spi_ipc_command_dispatcher`): `switch(cmdbuf[0] >> 16)`, commands 1-9; unknown ids reply with header `0x40`.
  | cmd | handler | cmdbuf use (words are `cmdbuf[n]`) |
  |---|---|---|
  | 1 | `0x1012E8` | byte [1], byte [2] -> result [1] |
  | 2 | inline | result [1] = 0 |
  | 3 | `0x101510` | byte [1], [2..], [3], [4]; result [1] |
  | 4 | `0x10153C` | byte [1], [2..], [3], [4..], [0x24] |
  | 5 | `0x101308` | byte [1], [2..], [3] |
  | 6 | `0x10143C` | requires translate descriptor `(d & 0xF) == 0xC` at [5] (3dbrew: write-only mapped buffer), pointer [6]; reply echoes the descriptor |
  | 7 | `0x10141C` | requires `(d & 0xF) == 0xA` (3dbrew: read-only mapped buffer), pointer [6] |
  | 8 | `0x10145C` | three bytes [1],[2],[3] |
  | 9 | `0x1014EC` | signed byte [1] |
* The meaning of each command (register read/write, buffer transfer, CS control) is **not yet established**: the handlers call lower-level functions (`0x1012E8`...) that still have to be read. Do that next (`decompiled/001012e8.c` etc.) and rename.
* Manual symbols: `symbols/manual/Module-SPI-SPI-Bus-N3DS-0004013020002302.csv`.
