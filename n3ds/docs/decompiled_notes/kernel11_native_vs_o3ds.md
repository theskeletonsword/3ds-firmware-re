# Kernel11 (NATIVE_FIRM) - N3DS vs O3DS, findings from the decompiled C

Method: unresolved O3DS symbols were compared with the N3DS decompilation (`decrypted_binaries/kernel_native/decompiled_arm11_section1/`, boot code in `decompiled_arm11_boot/`) with `tools/match_by_decompilation.py` and then read by hand. Names recorded in `symbols/manual/kernel_native_arm11.csv`.

| Finding | Evidence |
|---|---|
| **N3DS kernel is core-count aware.** O3DS loops over a fixed 2 per-core slots (`iVar < 2`, stride 0x9000); N3DS loops over `(*cfg_reg & 3) + 1` slots (up to 4 cores) | `k11_kdebug_op_0xFFF2C538` (O3DS fff2c538) vs `fff2d6ec` (N3DS) |
| **`KProcess` is 8 bytes bigger before the debug field**: `KProcess_has_debug_attached` tests `+0x78` on O3DS, `+0x80` on N3DS (explains why many Kernel11 functions differ only by struct offsets) | `fff0ceb4` vs `fff0cfbc` |
| **Extra physical range in the PA->VA helper**: besides `0x1F000000+ -> +0xF9000000` and `0x1EC00000..0x1FC00000 -> +0xF1500000`, N3DS maps `0x1E800000.. -> +0x800000` | `k11_result_check_op_0xFFF153E0` vs `fff15950` |
| Boot code is shifted `+0x1030` (entry `0x1FFAF064`) and reworked: `arm11_core_bringup_init` (`0x1FFAF168`) gains a config-register test (`(~reg & 3) == 0`, value `<<1`); `arm11_mmu_and_scu_enable` (`0x1FFAFC78`) is much larger (TTBR0 write at file offset `0x2FFB0`, SCTLR at `0x30004`) | `decompiled_arm11_boot/fff2f168.c`, TTBR0/SCTLR write scan of both images |
| `k11_dcache_clean_entire_dsb` unchanged (only callee address moved: `0xFFF2B60C`) | `fff2b60c.c` |
| Open: `svc_0x7C_KernelSetState`, `k11_pmu_write_ccnt`, `KAutoObject_virtual_base_stub`, `k11_kernel_sync_barrier_on_boot` (Ghidra starts the N3DS function mid-body at `0xFFF012A4`), `k11_boot_enable_cpacr_vfp`, `KDmaObject_create_or_init`, `k11_accessor_helper_0xFFF1AF6C`, `k11_kernel_routine_0xFFF26230`, `k11_mmu_remap_or_split_l2_pages` | see `docs/PENDING.md` |
