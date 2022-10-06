#include "Inject.h"
#include "apc.h"
#include "Image.h"
#include "Process.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS WINAPI InjectOneThread(_In_ PCLIENT_ID Cid, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    //   只注入一次。  经观察：5就是线程的等待状态，具体的定义没有找到。THREAD_ALERT == 4
    //   注意：ApcState，Alerted，Alertable这几个成员的不同。
    //if (5 == psti->ThreadState && (g_b == 1)) 
    {
        //注意，这里插入了，何时运行还未知：快的需要几秒，慢的需要及分钟，甚至几十分钟，
        //更深的几个小时或者几天几夜，甚至永远不会运行，如：不触发或者线程的状态不符合。
        QueueApcThread(Cid);
    }

    return STATUS_UNSUCCESSFUL;//继续遍历。
}


NTSTATUS InjectAllThread(__in HANDLE UniqueProcessId)
/*
注入前的注意事项：
1.能不能打开进程。
2.进程有没有用户空间。
3.在X64下要先区分是不是WOW64进程。
4.对于.net和java等程序要不要注入。
5.这里不处理WSL下的linux进程。
*/
{
    EnumThread(UniqueProcessId, InjectOneThread, NULL);

    return STATUS_SUCCESS;
}


NTSTATUS InjectDllByCreateUserThread(_In_ HANDLE Process,
                                     _Inout_ PHANDLE ThreadHandleReturn,
                                     _Inout_ PCLIENT_ID ClientId,
                                     _Inout_ PVOID * UserAddress
)
/*

注意：WOW64的处理。
"\\SystemRoot\\System32\\kernel32.dll"
"\\SystemRoot\\SysWOW64\\kernel32.dll"

感叹！
多么的巧合。
PUSER_THREAD_START_ROUTINE和LoadLibraryW的原型竟然一致。
所以，这省去了在应用层申请可执行内存的操作。
当然更多的是复制代码（可以不是shellcode，当然要支持WOW64）到应用层的操作。
更不用说shellcode了。

注意：WOW64的参数的大小，如：指针和size_t等。

DllPullPath所在的内存是应用层的。

只管注入，不管多余的事。
*/
{
    NTSTATUS Status = STATUS_SUCCESS;    

    LPCWSTR DllPullPath = SetDllFullPath(Process);
    if (!DllPullPath) {
        return STATUS_UNSUCCESSFUL;
    }

    PUSER_THREAD_START_ROUTINE LoadLibraryW = NULL;//LoadLibraryW的地址。
    if (IsWow64Process(Process)) {
        LoadLibraryW = (PUSER_THREAD_START_ROUTINE)LoadLibraryWWow64Fn;
    } else {
        LoadLibraryW = (PUSER_THREAD_START_ROUTINE)LoadLibraryWFn;
    }

    if (!LoadLibraryW) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "pid:%d", HandleToUlong(ClientId->UniqueProcess));
        return STATUS_UNSUCCESSFUL;
    }

    if (!IsLoadKernel32(Process)) {
        return STATUS_UNSUCCESSFUL;
    }
    
    //Status = CreateUserThread(Process, LoadLibraryW, (PVOID)DllPullPath, ThreadHandleReturn, ClientId);
    Status = CreateUserThreadEx(Process, LoadLibraryW, (PVOID)DllPullPath, ThreadHandleReturn, ClientId);
    if (NT_SUCCESS(Status)) {
        *UserAddress = (PVOID)DllPullPath;
    }

    return Status;
}


NTSTATUS WINAPI InjectOneProcess(_In_ HANDLE UniqueProcessId, _In_opt_ PVOID Context)
{
    PEPROCESS Process = NULL;
    NTSTATUS  status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Context);

    status = PsLookupProcessByProcessId(UniqueProcessId, &Process);
    if (!NT_SUCCESS(status)) {

        return status;
    }

    __try {
        if (0 == UniqueProcessId) {

            __leave;
        }

        if (PsGetProcessId(PsInitialSystemProcess) == UniqueProcessId) {

            __leave;
        }

        //if (PsIsSystemProcess(Process)) {//这个太多。
        //    Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "SystemProcess:%d, %s",
        //          HandleToUlong(UniqueProcessId), PsGetProcessImageFileName(Process));
        //    __leave;
        //}

        if (PsIsProtectedProcess(Process)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "ProtectedProcess:%d, %s",
                  HandleToUlong(UniqueProcessId), PsGetProcessImageFileName(Process));
            __leave;
        }

        //IsSecureProcess

        HANDLE ThreadHandleReturn = NULL;
        CLIENT_ID ClientId = {0};
        PVOID UserAddress = NULL;

        //InjectAllThread(UniqueProcessId);
        status = InjectDllByCreateUserThread(UniqueProcessId, &ThreadHandleReturn, &ClientId, &UserAddress);
        if (NT_SUCCESS(status)) {
            PROCESS_CONTEXT Temp = {0};
            Temp.Pid = UniqueProcessId;
            Temp.IsInjected = TRUE;
            Temp.InjectThreadId = ClientId.UniqueThread;
            Temp.UniqueProcess = ClientId.UniqueProcess;
            Temp.UserAddress = UserAddress;
            UpdateProcessContext(&Temp);
        }
    } __finally {
        ObDereferenceObject(Process);
    }

    return STATUS_UNSUCCESSFUL;//继续遍历。
}


NTSTATUS WINAPI InjectProcess(_In_ HANDLE UniqueProcessId, _In_opt_ PVOID Context)
{
    PPROCESS_CONTEXT Temp = GetProcessContext(UniqueProcessId);
    if (!Temp) {
        PPROCESS_CONTEXT ProcessContext = (PPROCESS_CONTEXT)ExAllocatePoolWithTag(PagedPool, sizeof(PROCESS_CONTEXT), TAG);
        if (!ProcessContext) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag Fail");
            return STATUS_SUCCESS;
        }

        RtlZeroMemory(ProcessContext, sizeof(PROCESS_CONTEXT));
        ProcessContext->Pid = UniqueProcessId;
        InsertProcessContext(ProcessContext);
    }

    return InjectOneProcess(UniqueProcessId, Context);
}


NTSTATUS InjectAllProcess(VOID)
{
    return EnumProcess(InjectProcess, NULL);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
