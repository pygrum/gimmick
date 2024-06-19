#include "../gimmick.h"

typedef struct {
    PCHAR greeting;
} greet, *pgreet;

// encrypted data. initialise strings with [] to prevent them from being moved

SEC( rodata ) CHAR hello[] = "hello from gimmick";
SEC( rodata ) CHAR goodbye[] = "goodbye from gimmick";


SEC( vmp0 ) DWORD __stdcall Message(PGK_CONTEXT Context, PVOID Args)
{
    pgreet greet = Args;
    PCHAR greeting = greet->greeting;

    // get encrypted data
    GkGet( Context, greeting );

    MessageBoxA(NULL, greeting, NULL, 0);

    // release data
    GkRelease( Context, greeting );
    return 0xDEAD;
}

int main()
{
    NTSTATUS Status = STATUS_SUCCESS;
    GK_CONTEXT Context = {};
    DWORD ThreadId = 0;
    UCHAR Key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    if ((Status = GkInitContext(GkGetModuleHandle(0), &Context, Key)) != STATUS_SUCCESS) {
        return Status;
    }
    greet greetH = { .greeting = hello };
    greet greetG = { .greeting = goodbye };

    // gkrun arguments
    GK_ARGS ArgsHello = { .Context = &Context, .Function = Message, .Args = &greetH };
    GK_ARGS ArgsGoodbye = { .Context = &Context, .Function = Message, .Args = &greetG };

#ifdef DEBUG
    printf("--- Starting threads\n");
#endif
    HANDLE ThreadH = CreateThread(NULL, 0, GkRunEx, &ArgsHello, 0, &ThreadId);
    HANDLE ThreadG = CreateThread(NULL, 0, GkRunEx, &ArgsGoodbye, 0, &ThreadId);

    WaitForSingleObject(ThreadH, INFINITE);
    WaitForSingleObject(ThreadG, INFINITE);

    return GkFreeSectionContext(&Context);
}