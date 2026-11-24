# O3DS directory-label corrections

The original Spanish directory names in `o3ds/binarios_descifrados/` were derived from TitleID guesses and **do not match the module that is actually inside**
for most entries. The truth is the `Name` field of each module's own `exheader.bin` (ExHeader), plus the module's own strings (e.g. service names).

Examples (old label → real module):

| TitleID | Old label | Real module (ExHeader `Name`) |
|---|---|---|
| `0004013000001502` | FS – File system | **am** |
| `0004013000001602` | PM – Process manager | **camera** |
| `0004013000001702` | SM – Service manager | **cfg** |
| `0004013000001802` | PXI – Inter-processor comms | **codec** |
| `0004013000001A02` | NS – Nintendo Shell | **dsp** |
| `0004013000001B02` | CFG – System config | **gpio** |
| `0004013000001C02` | GPIO – Pins | **gsp** |
| `0004013000001D02` | I2C – Bus | **hid** |
| `0004013000001E02` | MCU – Microcontroller | **i2c** |
| `0004013000001F02` | PDN – Power/clocks | **mcu** |
| `0004013000002102` | PS – Cryptography | **pdn** |
| `0004013000002302` | CAM – Camera | **spi** |
| `0004013000002402` | CSND – Sound | **ac** |
| `0004013000002702` | DSP – Audio processor | **csnd** |
| `0004013000002902` | HID – Buttons/touch | **http** |
| `0004013000003102` | BOSS – SpotPass | **ps** |
| `0004013000003402` | L2B – Video conversion | **boss** |
| `0004013000003502` | MVD – Video decoder | **news** |

The existing O3DS `*_friendly.sym` files are named after the real module (`gsp_friendly.sym` sits in the old "GPIO" directory, `hid_friendly.sym` in the old "I2C" directory…),
so **the symbol content is correct; only the directory labels were wrong**. All directories have been renamed to
`Module-<REAL-NAME>-<English role>[-SafeMode]-<TitleID>` (full list in `o3ds/decrypted_binaries/RENAME_MAP.tsv` and `n3ds/decrypted_binaries/RENAME_MAP.tsv`).
Prose in the old Spanish documents that refers to e.g. "FS 1502" therefore refers to the module `am`.

English role words in the new names are conventional descriptions of the real module names (public 3dbrew naming), not derived from the binaries.
