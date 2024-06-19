
#ifndef GIMMICK_H
#define GIMMICK_H

#include <stdio.h>
#include "ntdll.h"

#define FORWARDER( ex, s, p ) (DWORD_PTR)p >= (DWORD_PTR)ex && \
(DWORD_PTR)p < (DWORD_PTR)ex + s
#define NT_HEADERS_PTR( x ) (PIMAGE_NT_HEADERS)((PCHAR)x + ((PIMAGE_DOS_HEADER)x)->e_lfanew)
#define BAD_MODULE( x ) ((PIMAGE_DOS_HEADER)x)->e_magic != IMAGE_DOS_SIGNATURE
#define TO_LOWERCASE(c) (c = (c <= 'Z' && c >= 'A') ? c + ' ': c)
#define WIN_FUNC( x ) __typeof__(x)*x;
#define WIN_PROC( c, m, f, h ) c->f = (__typeof__(c->f))GkGetProcAddress(c, c->m, h)

#define STATUS_INVALID_SIGNATURE 0xC000A000
#define STATUS_SECTION_NOT_IMAGE 0xC0000049

// RC4 Constant
#define N 256   // 2^8
/* MODULE HASHES -------------------------------------------------*/
#define HASH_KERNEL32 0x3bbc195
#define HASH_NTDLL 0x11c9b04d
/* PROC HASHES ---------------------------------------------------*/
#define HASH_LDRGETPROCEDUREADDRESSFORCALLER 0x2bdda210
#define HASH_RTLANSISTRINGTOUNICODESTRING 0x427c583a
#define HASH_VIRTUALALLOC 0x58dacbd7
#define HASH_VIRTUALPROTECT 0x8b9ebdcd
#define HASH_VIRTUALFREE 0x1238036e
#define HASH_CREATEMUTEXA 0xd8b1f26d
#define HASH_RELEASEMUTEX 0x790e3959
#define HASH_LDRLOADDLL 0x23a21f83
#define HASH_SYSTEMFUNCTION032 0xd3a21dc5
#define HASH_WAITFORSINGLEOBJECT 0xda18e23a
#define HASH_PRINTF 0x156b2bb8


#ifndef HASH
    #define HASH 5381
#endif

/*
 * djb2 hash for wstring, case insensitive modification: http://www.cse.yorku.ca/~oz/hash.html
 */
static DWORD DJB2W(LPWSTR String, DWORD Length)
{
    DWORD Hash = HASH;
    for (INT i = 0; i < Length; i++) {
        CHAR c = *((CHAR*)String + i);
        TO_LOWERCASE(c);
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

/*
 * djb2 hash, case insensitive modification: http://www.cse.yorku.ca/~oz/hash.html
 */
static DWORD DJB2A(LPSTR String)
{
    CHAR c;
    DWORD Hash = HASH;
    while ((c = *String++) != 0) {
        TO_LOWERCASE(c);
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

// Hash comparison for UNICODE_STRING
#define HASH_CMPW( x, h ) DJB2W((LPWSTR)x.Buffer, x.Length) == h
#define HASH_CMPA( x, h ) DJB2A((unsigned char*)x) == h



// buffer struct used for encryption in SystemFunction032.
typedef struct _BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} BUFFER, *PBUFFER;


// unexported win32 functions and symbols--------------------------------
NTSTATUS
SystemFunction032
(
    PBUFFER data,
    PBUFFER key
);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddressForCaller(
  IN HMODULE ModuleHandle,
  IN PANSI_STRING FunctionName OPTIONAL,
  IN WORD Oridinal OPTIONAL,
  OUT PVOID *FunctionAddress,
  IN BOOL bValue,
  IN PVOID *CallbackAddress
);
// ---------------------------------------------------------------------


/*
 * stores section context for syncronisation.
 * Implements buffer used for RC4 encryption by SystemFunction032.
 * 1. Allow access when section is unencrypted
 * 2. Do not encrypt if there are other threads accessing the section
 * 3. Do not access while a section is being encrypted or decrypted (mutex is used for insurance)
 * 4. Decrypt a section when access is required and it is encrypted (mutex is used for insurance)
 */
typedef struct _GK_SECTION_CONTEXT {
    BUFFER Section;
    DWORD OriginalProtect;
    PCHAR Name;
    DWORD Accessors;
    HANDLE Mutex; // held during encryption and decryption.
    BOOL Encrypted; // changed BEFORE crypt is done
    struct _GK_SECTION_CONTEXT* Next;
} GK_SECTION_CONTEXT, *PGK_SECTION_CONTEXT;

// Stores information about each section on initialisation, as well as helper functions
typedef struct _GK_CONTEXT {
    PGK_SECTION_CONTEXT SectionContexts;
    BUFFER EncryptionKey;
    HANDLE Ntdll;
    HANDLE Kernel32;

    WIN_FUNC( LdrGetProcedureAddressForCaller )
    WIN_FUNC( CreateMutexA )
    WIN_FUNC( ReleaseMutex )
    WIN_FUNC( VirtualAlloc )
    WIN_FUNC( VirtualProtect )
    WIN_FUNC( VirtualFree )
    WIN_FUNC( LdrLoadDll )
    WIN_FUNC( RtlAnsiStringToUnicodeString )
    WIN_FUNC( WaitForSingleObject )

#ifdef DEBUG
    HANDLE Msvcrt;
    WIN_FUNC( printf )
#endif

} GK_CONTEXT, *PGK_CONTEXT;

// Used to pass information to the GkRunner thread.
typedef struct _GK_ARGS {
    PGK_CONTEXT Context;
    LPVOID Function;
    PVOID Args;
    DWORD ReturnValue;
} GK_ARGS, *PGK_ARGS;

// Function signature for Gimmick callees. Context is passed in case a callee wants to access encrypted data.
typedef DWORD (__stdcall *LPGK_ROUTINE) (
    IN PGK_CONTEXT Context,
    IN LPVOID Args
);

// Initialises Gimmick context
NTSTATUS GkInitContext( PGK_CONTEXT Context, LPVOID BaseAddress, PUCHAR Key, DWORD KeySize );
// Frees Gimmick section context that was allocated with GkInitContext
NTSTATUS GkFreeSectionContext( PGK_CONTEXT Context );
// Retrieve handle to a module from PEB loader data
HANDLE GkGetModuleHandle( DWORD Hash );
// Get process address from loaded module data
FARPROC GkGetProcAddress( PGK_CONTEXT Context, HANDLE hModule, DWORD Hash );
// Request data from an encrypted section. Gimmick ensures the section is protected while the data is being used
NTSTATUS GkGet( PGK_CONTEXT Context, PVOID Data );
// Signal that data accessed by GkGet is no longer in use
NTSTATUS GkRelease( PGK_CONTEXT Context, HANDLE Data );
// Runs the function with the provided arguments (e.g. a struct pointer) and returns its return value. decrypting the section
// it exists in if necesssary
NTSTATUS GkRun( PGK_CONTEXT Context, LPGK_ROUTINE Function, PVOID Args, OUT PDWORD ReturnValue );
// Thread routine to run a function asyncronously. Pass a pointer to the GK_ARGS struct
DWORD WINAPI GkRunEx( LPVOID Args );
// Inbuilt RC4
VOID GkRC4(PUCHAR Key, DWORD KeySize, PUCHAR Plaintext, DWORD TextSize, PUCHAR Ciphertext);

#define SEC( s ) __attribute__( ( section("." #s ) ) )

#endif //GIMMICK_H
