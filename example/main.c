#include "../gimmick.h"

typedef struct {
    PCHAR greeting;
} greet, *pgreet;

// encrypted data. initialise strings with [] to prevent them from being moved

SEC( rodata ) CHAR hello[] = "hello from gimmick";
SEC( rodata ) CHAR goodbye[] = "goodbye from gimmick";
SEC( rodata ) CHAR user32[] = "user32";

SEC( xdata ) DWORD __stdcall Message(PGK_CONTEXT Context, PVOID Args)
{
    pgreet greet = Args;
    PCHAR greeting = greet->greeting;

    // get encrypted data
    GkGet( Context, greeting );
    GkGet( Context, user32 );

    UNICODE_STRING User32 = {};
    ANSI_STRING User32Ansi = { .Buffer = user32, .Length = 6, .MaximumLength = 7 };
    Context->RtlAnsiStringToUnicodeString(&User32, &User32Ansi, TRUE);

    DWORD hashMessageBoxA = 0xe3f74914;
    HANDLE hUser32 = NULL;
    Context->LdrLoadDll(NULL, 0, &User32, &hUser32);
    __typeof__(MessageBoxA)* MessageBoxAProc = (__typeof__(MessageBoxA)*)GkGetProcAddress(Context, hUser32, hashMessageBoxA);
    MessageBoxAProc(NULL, greeting, NULL, 0);

    // release data
    GkRelease( Context, user32 );
    GkRelease( Context, greeting );
    return 0xDEAD;
}

int WINAPI WinMain(
 IN HINSTANCE hInstance,
 IN OPTIONAL HINSTANCE hPrevInstance,
 IN LPSTR lpCmdLine,
 IN int nShowCmd
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    GK_CONTEXT Context = {};
    DWORD ThreadId = 0;
    UCHAR Key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    if ((Status = GkInitContext(&Context, GkGetModuleHandle(0), Key, 16)) != STATUS_SUCCESS) {
        return Status;
    }
    greet greetH = { .greeting = hello };
    greet greetG = { .greeting = goodbye };

    // gkrun arguments
    GK_ARGS ArgsHello = { .Context = &Context, .Function = Message, .Args = &greetH };
    GK_ARGS ArgsGoodbye = { .Context = &Context, .Function = Message, .Args = &greetG };
#ifdef DEBUG
    Context.printf("--- Starting threads\n");
#endif
    HANDLE ThreadH = Context.CreateThread(NULL, 0, GkRunEx, &ArgsHello, 0, &ThreadId);
    HANDLE ThreadG = Context.CreateThread(NULL, 0, GkRunEx, &ArgsGoodbye, 0, &ThreadId);

    Context.WaitForSingleObject(ThreadH, INFINITE);
    Context.WaitForSingleObject(ThreadG, INFINITE);

    return GkFreeSectionContext(&Context);
}