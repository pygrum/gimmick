# Gimmick

A thread-safe, section-based payload obfuscation technique.

## How it works
This technique allows safe, on-demand access to compile-time encrypted global variables and functions.
How? Gimmick provides an API to allow sections to be dynamically decrypted and accessed at runtime in a thread-safe way.
It also re-encrypts sections when no threads are using them.
Depending on its usage, this technique introduces just a small window for your payload to exist fully decrypted in memory.


To **decrypt** a section, Gimmick checks for the following conditions:
1. There are no other threads currently encrypting or decrypting the section simultaneously

To **encrypt** a section, Gimmick checks for the following conditions:
1. There are no other threads currently encrypting or decrypting the section simultaneously
2. There are no 'references' to the section


## Extra features

- PIC (Position Independent Code) compatible library, with custom GetModuleHandle and GetProcAddress implementations
- Dynamically loaded functions and modules that can be passed to a global instance at runtime.
- Inbuilt RC4 implementation

## Limitations
- 64-bit only (for now)
- Sections used by stdlib cannot be encrypted. Modify and compile with -nostdlib to have more standard section names available for use
- If the executable is to be loaded by the OS, only sections that are untouched by Windows loader can be used to store data. 
This technique is best used with an rDLL or Shellcode.
- All sections are marked as encrypted on initialisation, as Gimmick has no awareness of section states before they have been accessed.
It will attempt to encrypt / decrypt any section referenced by the API. Only functions and variables designated a section with the `SEC`
macro should be called, provided that the section will also be encrypted with `crypt.py` after. This really shouldn't be an issue 
**provided that you only target the sections that you want to encrypt.**
- For sections containing executable code, there will

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
3. Initialise Gimmick context with `GkInitContext`, and free with `GkFreeSectionContext`
4. Use `GkGet` (+`GkRelease`), `GkRun`, or `GkRunEx` to run functions or access variables assigned to encrypted sections
5. Compile the file
6. Choose sections that contain data accessed with Gimmick to encrypt (`crypt.py`) and encrypt them with the same key used
for Gimmick's context (edit in script)
7. Run your executable
