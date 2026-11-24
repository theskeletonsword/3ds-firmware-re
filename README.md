# 3DS Firmware Reverse Engineering (`11.17.0-50U`)

Symbol tables, structural/RTTI/IPC analyses, documentation, and reproducible Python/Ghidra/radare2 tooling for **Old 3DS (`o3ds/`)** and **New 3DS (`n3ds/`)** system firmware (`11.17.50U` / `11.17.0-50U`).

| Path | Contents |
|---|---|
| `o3ds/` | **Old 3DS** reference: recreated symbol tables (`*_friendly.sym`, `.r2`, `_ghidra.py`), per-title/module analyses (`analysis/`), and English documentation (start with `o3ds/README.md`). Spanish originals: `o3ds/docs_es_backup/`. |
| `o3ds/symbols_titles/`, `n3ds/symbols/` | Master symbol tables (`N3DS_SYMBOL_TABLE.csv`, `TITLES_SYMBOL_TABLE.csv`, `N3DS_IPC_COMMANDS.csv`, `N3DS_MODULE_INVENTORY.csv`), per-component CSV/sym/r2 files, `derived/`, `derived_decomp/`, `ipc/`, `manual/`, and `proposals/`. |
| `n3ds/` | **New 3DS** pipeline: tools (`tools/`), transferred/verified symbol tables (`symbols/`), per-title/module analyses (`analysis/`), and documentation (start with `n3ds/README.md`, `n3ds/docs/HANDOFF.md`). |
| `rename-3ds.sh` | Original title-extraction/rename script. |

> Note: Console keys (`aes_keys.txt`, `movable.sed`), encrypted CIAs (`updates/`, `o3ds/extracted/`), decrypted Nintendo binaries/RomFS, and bulk decompiled C outputs (`decompiled*/`, `pseudocode*/`) are excluded via `.gitignore`. Place your own 11.17.0-50U dumps locally to re-run `n3ds/tools/run_all.sh` or `n3ds/tools/decompile_all.sh`.

Directory names inside `decrypted_binaries/` follow `Module-<EXHEADER-NAME>-<Role>[-SafeMode][-N3DS]-<TitleID>` (module name from each ExHeader; old Spanish labels were often wrong — see `n3ds/docs/O3DS_LABEL_CORRECTIONS.md`). Old → new names: `RENAME_MAP.tsv` in each `decrypted_binaries/`.

## License

MIT — see [LICENSE](LICENSE).
