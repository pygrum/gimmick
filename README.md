# Gimmick

A thread-safe, section-based payload obfuscation technique.

## How it works
Each section is treated as a shared resource by the application.
To access a section, it needs to be decrypted.

To decrypt a section, the following conditions are satisfied:
1. There are no other threads currently encrypting or decrypting the section simultaneously

To encrypt a section, the following conditions are satisfied:
1. There are no other threads currently encrypting or decrypting the section simultaneously
2. There are no 'references' to the section

## Extra features

- PIC (Position Independent Code) compatible library, with custom GetModuleHandle and GetProcAddress implementations

## Limitations
- 64-bit only (for now)
- Sections used by stdlib cannot be encrypted. Modify and compile with -nostdlib to have more standard section names available for use
- If the executable is to be loaded by the OS, only sections that are untouched by Windows loader can be used to store data. 
This technique is best used with an rDLL or Shellcode.
- All sections are marked as encrypted on initialisation.
Gimmick attempts to encrypt / decrypt any section referenced by the API, as there is no current implementation for
*initial* section encryption state detection. Only functions and variables marked with the `SEC` macro should be called,
provided that the section will be encrypted with `crypt.py`. This shouldn't be an issue **provided that you only target the
sections that you want to encrypt.**

## Run
An example multithreaded application is set up for POC purposes. It is compiled with MinGW gcc.
1. `make build`
2. `./gimmick.exe`

### Output
```
--- Starting threads
[*][.vmp0] attempting to decrypt section
[*][.vmp0] decrypting section
[+][.vmp0] done! releasing mutex and restoring protection.
[+][.vmp0] data is now available for use.
[*][00007ff6963e9000] -- executing callee function
[*][.rodata] attempting to decrypt section
[*][.rodata] decrypting section
[*][.vmp0] attempting to decrypt section
[!][.vmp0] section is already decrypted
[*][00007ff6963e9000] -- executing callee function
[+][.rodata] done! releasing mutex and restoring protection.
[+][.rodata] data is now available for use.
[*][.rodata] attempting to decrypt section
[!][.rodata] section is already decrypted
[*][.rodata] attempting to re-encrypt section
[!][.rodata] section is in use - no re-encryption was performed
[*][00007ff6963e9000] -- exited with code 0xdead
[*][.vmp0] attempting to re-encrypt section
[!][.vmp0] section is in use - no re-encryption was performed
[*][.rodata] attempting to re-encrypt section
[*][.rodata] re-encrypting section
[+][.rodata] successfully re-encrypted section
[*][00007ff6963e9000] -- exited with code 0xdead
[*][.vmp0] attempting to re-encrypt section
[*][.vmp0] re-encrypting section
[+][.vmp0] successfully re-encrypted section
```

## Usage
1. Add `gimmick.c`, `gimmick.h` and `ntdll.h` to your project
2. Assign objects to desired sections with the `SEC` macro, separating different types (e.g. functions and variables)
3. Initialise Gimmick context (`GkInitCtx`)
4. Use `GkGet` (+`GkRelease`), `GkRun`, or `GkRunEx` to run functions or access variables assigned to encrypted sections
5. Compile the file
6. Choose sections that contain data accessed with Gimmick to encrypt (`crypt.py`) and encrypt them with the same key used
for Gimmick's context (edit in script)
7. Run your executable
