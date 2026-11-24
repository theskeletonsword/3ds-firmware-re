# Manual symbols (hand-verified from decompiled C)

One CSV per binary: `symbols/manual/<binary directory name>.csv` with header
`binary,ea,symbol_name,evidence`
* `binary`  = directory name of the binary (e.g. `Module-SPI-SPI-Bus-N3DS-0004013020002302`, `Internet-Browser-0004003020009402`, `kernel_native/arm9`)
* `ea`      = address in the load-address space used everywhere in this workspace (see CLAUDE.md)
* `symbol_name` = name chosen from evidence only (strings, constants, SVC/IPC usage, call structure). Prefix guessed-but-plausible names with `maybe_`.
* `evidence` = one line: what in the decompiled code justifies the name (file `decompiled/<addr>.c`, string, constant, caller).

`tools/build_master_table.py` merges these rows into `N3DS_SYMBOL_TABLE.csv` as level `manual_decompiled`; `tools/ghidra_decompile.py` feeds them back as function names
when a binary is re-decompiled (`--fresh`).
