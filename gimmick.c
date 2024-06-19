#include "gimmick.h"
#include <windows.h>
#ifdef DEBUG
    #define PRINTF( ... )  Context->printf( __VA_ARGS__ );
#else
    #define PRINTF( ... )
#endif

NTSTATUS GkInitContext( PGK_CONTEXT Context, LPVOID BaseAddress, PUCHAR Key, DWORD KeySize )
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_FILE_HEADER FileHeader = NULL;
    PGK_SECTION_CONTEXT SectionContext, LastSectionContext = NULL;
    LPVOID Section = NULL;

    // Initialize encryption key
    Context->EncryptionKey.Length = KeySize;
    Context->EncryptionKey.MaximumLength = KeySize;
    Context->EncryptionKey.Buffer = Key;

    // load dependencies
    Context->Ntdll = GkGetModuleHandle(HASH_NTDLL);
    Context->Kernel32 = GkGetModuleHandle(HASH_KERNEL32);
    WIN_PROC(Context, Ntdll, LdrGetProcedureAddressForCaller, HASH_LDRGETPROCEDUREADDRESSFORCALLER);
    WIN_PROC(Context, Ntdll, RtlAnsiStringToUnicodeString, HASH_RTLANSISTRINGTOUNICODESTRING);
    WIN_PROC(Context, Ntdll, LdrLoadDll, HASH_LDRLOADDLL);
    WIN_PROC(Context, Kernel32, CreateMutexA, HASH_CREATEMUTEXA);
    WIN_PROC(Context, Kernel32, ReleaseMutex, HASH_RELEASEMUTEX);
    WIN_PROC(Context, Kernel32, VirtualAlloc, HASH_VIRTUALALLOC);
    WIN_PROC(Context, Kernel32, VirtualProtect, HASH_VIRTUALPROTECT);
    WIN_PROC(Context, Kernel32, VirtualFree, HASH_VIRTUALFREE);
    WIN_PROC(Context, Kernel32, WaitForSingleObject, HASH_WAITFORSINGLEOBJECT);
    WIN_PROC(Context, Kernel32, CreateThread, HASH_CREATETHREAD);

#ifdef DEBUG
    CHAR Msvcrt[] = { 'm', 's', 'v', 'c', 'r', 't', '\0'};
    ANSI_STRING MsvcrtAnsi = { .Buffer = Msvcrt, .Length = 6, .MaximumLength = 7 };
    UNICODE_STRING MsvcrtUnicode = {};
    if (Context->RtlAnsiStringToUnicodeString(&MsvcrtUnicode, &MsvcrtAnsi, TRUE) != STATUS_SUCCESS)
        return STATUS_UNSUCCESSFUL;
    Context->LdrLoadDll(NULL, 0, &MsvcrtUnicode, &Context->Msvcrt);
    WIN_PROC(Context, Msvcrt, printf, HASH_PRINTF);
#endif


    NtHeaders = (PIMAGE_NT_HEADERS)((CHAR*)BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return STATUS_INVALID_SIGNATURE;

    FileHeader = &NtHeaders->FileHeader;
    // get first section
    Section = (CHAR*)&NtHeaders->OptionalHeader + FileHeader->SizeOfOptionalHeader;

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER SectionHeader = Section;

        SectionContext = (PGK_SECTION_CONTEXT)Context->VirtualAlloc(
            NULL,
            sizeof(GK_SECTION_CONTEXT),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
            );
        if (SectionContext == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        SectionContext->Section.Buffer = (PUCHAR)BaseAddress + SectionHeader->VirtualAddress; // assumes sections are loaded correctly in memory
        SectionContext->Section.Length = SectionHeader->Misc.VirtualSize;
        SectionContext->Section.MaximumLength = SectionContext->Section.Length;
        SectionContext->Encrypted = TRUE; // (prod: TRUE) we assume it has been encrypted statically
        SectionContext->Mutex = Context->CreateMutexA(NULL, FALSE, NULL);
        SectionContext->Name = SectionHeader->Name;
        SectionContext->Next = NULL;

        // Attach to linked list
        if (LastSectionContext)
            LastSectionContext->Next = SectionContext;
        else // otherwise, set as first section in section context list
            Context->SectionContexts = SectionContext;
        LastSectionContext = SectionContext;
        // set to next section header
        Section = (CHAR*)Section + sizeof(IMAGE_SECTION_HEADER);
    }
    return STATUS_SUCCESS;
}

NTSTATUS GkFreeSectionContext( PGK_CONTEXT Context )
{
    DWORD status = STATUS_SUCCESS;
    PGK_SECTION_CONTEXT SectionContext = Context->SectionContexts;
    do
    {
        PGK_SECTION_CONTEXT Next = SectionContext->Next;
        if (!Context->VirtualFree(SectionContext, 0, MEM_RELEASE))
            status = STATUS_UNSUCCESSFUL;
        SectionContext = Next;
    } while (SectionContext != NULL);
    return status;
}

NTSTATUS GkGet( PGK_CONTEXT Context, PVOID Data)
{
    // find section that data lives in
    PGK_SECTION_CONTEXT SectionContext = NULL;
    for (SectionContext = Context->SectionContexts; SectionContext != NULL; SectionContext = SectionContext->Next) {
        PBUFFER Section = &SectionContext->Section;
        // if it is within the range of the section
        if ((DWORD_PTR)Data >= (DWORD_PTR)Section->Buffer &&
            (DWORD_PTR)Data <= (DWORD_PTR)Section->Buffer + Section->Length) {
            /*wait for in-progress crypt*/
            Context->WaitForSingleObject(SectionContext->Mutex, INFINITE);

            /* if encryption just happened, then hold mutex and:
             * 1. Make RW
             * 2. Decrypt
             * 3. Restore protection
             * 4. Update encryption status
             * 5. Release mutex
             */

            PRINTF("[*][%s] attempting to decrypt section\n", SectionContext->Name);
            if (SectionContext->Encrypted) {

                PRINTF("[*][%s] decrypting section\n", SectionContext->Name);

                // rw
                Context->VirtualProtect(Section->Buffer, Section->Length, PAGE_READWRITE, &SectionContext->OriginalProtect);
                // decrypt
                GkRC4(Context->EncryptionKey.Buffer,
                    Context->EncryptionKey.Length,
                    SectionContext->Section.Buffer,
                    SectionContext->Section.Length,
                    SectionContext->Section.Buffer);
                PRINTF("[+][%s] done! releasing mutex and restoring protection.\n", SectionContext->Name);

                // original
                DWORD op;
                Context->VirtualProtect(Section->Buffer, Section->Length, SectionContext->OriginalProtect, &op);
                // notify
                SectionContext->Encrypted = FALSE;
                PRINTF("[+][%s] data is now available for use.\n", SectionContext->Name);
            }
            else {
                PRINTF("[!][%s] section is already decrypted\n", SectionContext->Name);
            }

            // update before release so that encryptor knows that there's now an accessor
            SectionContext->Accessors += 1;
            Context->ReleaseMutex(SectionContext->Mutex);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_SECTION_NOT_IMAGE;
}

NTSTATUS GkRelease( PGK_CONTEXT Context, PVOID Data )
{
    // find section that data lives in
    PGK_SECTION_CONTEXT SectionContext = NULL;
    for (SectionContext = Context->SectionContexts; SectionContext != NULL; SectionContext = SectionContext->Next) {
        PBUFFER Section = &SectionContext->Section;
        // if it is within the range of the section
        if ((DWORD_PTR)Data >= (DWORD_PTR)Section->Buffer &&
            (DWORD_PTR)Data <= (DWORD_PTR)Section->Buffer + Section->Length) {
            // acquire before checking accessors, effectively wait for an accessor to register themselves
            Context->WaitForSingleObject(SectionContext->Mutex, INFINITE);
            SectionContext->Accessors -= 1; // decrement before acquiry in case another thread acquires and checks for accessors before us

            PRINTF("[*][%s] attempting to re-encrypt section\n", SectionContext->Name);
            if (!SectionContext->Accessors) {
                /*
                 * 1. Acquire mutex
                 * 2. Make RW
                 * 3. Encrypt
                 * 4. Restore original protection
                 * 5. Update encryption status
                 */
                // rw

            PRINTF("[*][%s] re-encrypting section\n", SectionContext->Name);

                Context->VirtualProtect(Section->Buffer, Section->Length, PAGE_READWRITE, &SectionContext->OriginalProtect);
                // encrypt
                GkRC4(Context->EncryptionKey.Buffer,
                    Context->EncryptionKey.Length,
                    SectionContext->Section.Buffer,
                    SectionContext->Section.Length,
                    SectionContext->Section.Buffer);
                // original
                DWORD op; // discard rx
                Context->VirtualProtect(Section->Buffer, Section->Length, SectionContext->OriginalProtect, &op);
                // notify
                SectionContext->Encrypted = TRUE;

                PRINTF("[+][%s] successfully re-encrypted section\n", SectionContext->Name);
            }
            else {
                PRINTF("[!][%s] section is in use - no re-encryption was performed\n", SectionContext->Name);
            }
            // release after notify so that decryptor has the correct encryption bool
            Context->ReleaseMutex(SectionContext->Mutex);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_SECTION_NOT_IMAGE;
}

DWORD WINAPI GkRunEx( LPVOID Args )
{
    PGK_ARGS GkArgs = Args;
    return GkRun(GkArgs->Context, GkArgs->Function, GkArgs->Args, &GkArgs->ReturnValue);
}

NTSTATUS GkRun( PGK_CONTEXT Context, LPGK_ROUTINE Function, LPVOID Args, PDWORD ReturnValue )
{

    typedef struct {
        PCHAR greeting;
    } greet, *pgreet;
    NTSTATUS Status = STATUS_SUCCESS;
    if ((Status = GkGet(Context, Function)) != STATUS_SUCCESS)
        return Status;


    PRINTF("[*][%p] -- executing callee function\n", Function);

    *ReturnValue = Function(Context, Args);

    PRINTF("[*][%p] -- exited with code 0x%.4x\n", Function, *ReturnValue);

    if ((Status = GkRelease(Context, Function)) != STATUS_SUCCESS)
        return Status;
    return Status;
}

SIZE_T StrLenA(PCHAR String )
{
    SIZE_T length = 0;
    while (*String++) {
        length++;
    }
    return length;
}

HANDLE GkGetModuleHandle( DWORD Hash )
{
    PPEB Peb = NtCurrentPeb();
    HANDLE hModule = NULL;
    LIST_ENTRY ModuleList;

    PPEB_LDR_DATA LdrData = Peb->Ldr;
    if (LdrData) {
        ModuleList = LdrData->InLoadOrderModuleList;

        PLDR_DATA_TABLE_ENTRY CurrentModule = *((PLDR_DATA_TABLE_ENTRY*)(&ModuleList));
        BOOL First = TRUE;
        for (;
            CurrentModule != NULL && CurrentModule->DllBase != NULL;
            CurrentModule = (PLDR_DATA_TABLE_ENTRY)CurrentModule->InLoadOrderLinks.Flink
            ) {
            if (First && Hash == 0) {
                // first module is always the base of current process
                hModule = CurrentModule->DllBase;
                break;
            }
            First = FALSE;
            if (CurrentModule->BaseDllName.Buffer == NULL)
                continue;
            if (HASH_CMPW(CurrentModule->BaseDllName, Hash)) {
                hModule = CurrentModule->DllBase;
                break;
            }
        }
    }
    return hModule;
}

FARPROC GkGetProcAddress( PGK_CONTEXT Context, HANDLE hModule, DWORD Hash )
{
    if (BAD_MODULE(hModule))
        return NULL;

    PIMAGE_NT_HEADERS NtHeaders = NT_HEADERS_PTR(hModule);
    PIMAGE_DATA_DIRECTORY ExportDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDirectory == NULL)
        return NULL;
    // can simply offset from imagebase since image (including export section) is already loaded properly
    PIMAGE_EXPORT_DIRECTORY ExportData = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + ExportDirectory->VirtualAddress);

    if (ExportData) {
        // get absolutes from rva
        DWORD* NameTable = (DWORD*)((CHAR*)hModule + ExportData->AddressOfNames); // table of RVAs
        WORD* OrdinalTable = (WORD*)((CHAR*)hModule + ExportData->AddressOfNameOrdinals);
        DWORD* ProcTable = (DWORD*)((CHAR*)hModule + ExportData->AddressOfFunctions); // table of RVAs

        for (SIZE_T i = 0; i < ExportData->NumberOfNames; i++) {
            LPSTR CurrentName = (LPSTR)((BYTE*)hModule + NameTable[i]); // convert from RVA
            WORD Index = OrdinalTable[i];
            FARPROC ProcAddress = (FARPROC)((BYTE*)hModule + ProcTable[Index]); // convert from RVA

            if (HASH_CMPA(CurrentName, Hash)) {
                if (FORWARDER( ExportData , ExportDirectory->Size, ProcAddress )) {
                    ANSI_STRING String = { .Buffer = CurrentName, .Length = StrLenA(CurrentName) };
                    String.MaximumLength = String.Length + 1;
                    if (Context->LdrGetProcedureAddressForCaller) {
                        PVOID LdrProcAddress, CallbackAddress = NULL;
                        if ( NT_SUCCESS(Context->LdrGetProcedureAddressForCaller(
                            hModule,
                            &String,
                            0,
                            &LdrProcAddress,
                            0,
                            &CallbackAddress))) {
                            return LdrProcAddress;
                        }
                        return NULL;
                    }
                }
                return ProcAddress;
            }
        }
    }
    return NULL;
}

// RC4 implementation - modified https://gist.github.com/rverton/a44fc8ca67ab9ec32089 -----------------

void swap(PUCHAR a, PUCHAR b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

VOID KSA(PUCHAR Key, DWORD KeySize, PUCHAR S) {

    int j = 0;

    for(int i = 0; i < N; i++)
        S[i] = i;

    for(int i = 0; i < N; i++) {
        j = (j + S[i] + Key[i % KeySize]) % N;

        swap(&S[i], &S[j]);
    }
}

VOID PRGA(PUCHAR S, PUCHAR Plaintext, PUCHAR Ciphertext, DWORD TextSize) {

    int i = 0;
    int j = 0;

    for(size_t n = 0, len = TextSize; n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        Ciphertext[n] = rnd ^ Plaintext[n];

    }
}

VOID GkRC4(PUCHAR Key, DWORD KeySize, PUCHAR Plaintext, DWORD TextSize, PUCHAR Ciphertext) {

    UCHAR S[N];
    KSA(Key, KeySize, S);

    PRGA(S, Plaintext, Ciphertext, TextSize);
}
