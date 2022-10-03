#include "apc.h"
#include "test.h"
#include "Resource.h"
#include "Image.h"


SIZE_T ApcStateOffset;

ZwTestAlertT ZwTestAlert;
ZwQueueApcThreadT g_ZwQueueApcThread;
ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;



//#define CopyCode       //复制代码的方式。
#define UseUserFun   //直接用用户从的API方式（LoadLibraryExW）。


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL IsExcludeProcess(PCLIENT_ID ClientId)
/*
排除不需要注入的进程。
*/
{
    if (ClientId->UniqueProcess == 0 || PsGetProcessId(PsInitialSystemProcess) == ClientId->UniqueProcess) {
        return TRUE;
    }

    /*
    获取内核句柄。
    */
    PEPROCESS  Process = 0;
    NTSTATUS status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &Process);
    if (!NT_SUCCESS(status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", status);
        return TRUE;
    }
    ObDereferenceObject(Process); //微软建议加上。
    HANDLE  KernelProcessHandle = NULL;
    status = ObOpenObjectByPointer(Process,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_READ,
                                   *PsProcessType,
                                   KernelMode,
                                   &KernelProcessHandle);
    if (!NT_SUCCESS(status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", status);
        return TRUE;
    }

    BOOLEAN SecureProcess = FALSE;
    NTSTATUS Status = IsSecureProcess(KernelProcessHandle, &SecureProcess);
    if (SecureProcess) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "SecureProcess:%p", ClientId->UniqueProcess);
        ZwClose(KernelProcessHandle);
        return TRUE;// STATUS_NOT_SUPPORTED;
    }

#ifdef _WIN64
    //if (PsIsProtectedProcess(Process)) {
    //    Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "ProtectedProcess:%p", ClientId->UniqueProcess);
    //    ZwClose(KernelProcessHandle);
    //    return TRUE;
    //}
#endif

    BOOLEAN ProtectedProcess = FALSE;
    Status = IsProtectedProcess(KernelProcessHandle, &ProtectedProcess);
    if (SecureProcess) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "ProtectedProcess:%p", ClientId->UniqueProcess);
        ZwClose(KernelProcessHandle);
        return TRUE;
    }

    ZwClose(KernelProcessHandle);

    return FALSE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef CopyCode


void ApcCallback(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
/*
要复制给用户态的代码。

建议这里释放驱动中申请的用户态内存。

如果：编译器不支持/guard (Enable Control Flow Guard)。
这个函数运行没问题。
如果编译器支持/guard，一定要use /guard:cf-.
否则，这个函数里的函数调用会变成（IDA查看）：call    cs:__guard_dispatch_icall_fptr
这个经调试跟踪是一个无效的内存。
如果关闭后，会变为（IDA查看）：call    qword ptr [rax+XXh]
这才是符合需求的。

注意：这个函数要支持X86，X64和WOW64.
*/
{
    PPassToUser pa2 = (PPassToUser)SystemArgument2;
    SIZE_T  RegionSize = pa2->RegionSize;

    //__debugbreak();

    pa2->LoadLibraryW((LPCTSTR)pa2->FullDllPathName);
    pa2->NtFreeVirtualMemory(NtCurrentProcess(), &SystemArgument2, &RegionSize, MEM_RELEASE);
}
void ApcCallbackEnd()
{

}


VOID InitialUserRoutine(PCLIENT_ID ClientId, PSIZE_T UserApcCallbackAddr)
/*
申请用户态的内存，并把代码复制过去。

有时在想，用户层的内存也不用申请，
找一片应用层不用的且可写的内存，直接写过去，并记住这个内存，让后当参数传递过去即可。
*/
{
    PEPROCESS    Process;
    NTSTATUS status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &Process);
    ASSERT(NT_SUCCESS(status));

    HANDLE  Handle = 0;
    status = ObOpenObjectByPointer(Process,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_ALL,
                                   *PsProcessType,
                                   KernelMode,
                                   &Handle);
    ASSERT(NT_SUCCESS(status));

    SIZE_T size = 0;

    if (((SIZE_T)ApcCallbackEnd - (SIZE_T)ApcCallback) > 0) {
        size = (SIZE_T)ApcCallbackEnd - (SIZE_T)ApcCallback;
    } else {
        size = (SIZE_T)ApcCallback - (SIZE_T)ApcCallbackEnd;
    }

    SIZE_T CodeSize = size;

    PVOID BaseAddress = 0;//必须制定为0，否则返回参数错误。 
    status = ZwAllocateVirtualMemory(Handle  /*NtCurrentProcess()*/,
                                     &BaseAddress,
                                     0,
                                     &size,
                                     MEM_COMMIT,
                                     PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", status);
        ObDereferenceObject(Process);
        ZwClose(Handle);
        return;
    }

    KAPC_STATE   ApcState;
    KeStackAttachProcess(Process, &ApcState);
    __try {
        RtlZeroMemory(BaseAddress, CodeSize);
        RtlCopyMemory(BaseAddress, ApcCallback, CodeSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdBreakPoint();
    }
    KeUnstackDetachProcess(&ApcState);

    *UserApcCallbackAddr = (SIZE_T)BaseAddress;

    ObDereferenceObject(Process);
    ZwClose(Handle);
}


VOID InitialUserArgument(HANDLE UniqueProcess, PSIZE_T UserArgument)
/*

注释：
smss.exe只有ntll.dll和自身，没有kernel32.dll，这是个native程序。
*/
{
    PEPROCESS    Process;
    NTSTATUS status = PsLookupProcessByProcessId(UniqueProcess, &Process);
    ASSERT(NT_SUCCESS(status));

    HANDLE  Handle = 0;
    status = ObOpenObjectByPointer(Process,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_ALL,
                                   *PsProcessType,
                                   KernelMode,
                                   &Handle);
    ASSERT(NT_SUCCESS(status));

    SIZE_T size = sizeof(PassToUser);
    SIZE_T CodeSize = size;

    PVOID BaseAddress = 0;//必须制定为0，否则返回参数错误。  
    status = ZwAllocateVirtualMemory(Handle, &BaseAddress, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", status);
        ObDereferenceObject(Process);
        ZwClose(Handle);
        return;
    }

    KAPC_STATE   ApcState;
    KeStackAttachProcess(Process, &ApcState); //附加当前线程到目标进程空间内   

    __try {//注意：处理过程中，进程可能会退出。
        RtlZeroMemory(BaseAddress, CodeSize);
        PPassToUser pUserData = (PPassToUser)BaseAddress;
        pUserData->RegionSize = size;

        PPEB ppeb = PsGetProcessPeb(Process);//注意：IDLE和system这两个应该获取不到。
        if (ppeb && ppeb->Ldr) {//进程启动时，Ldr为空。
            PLDR_DATA_TABLE_ENTRY pldte;
            UNICODE_STRING ntdll = RTL_CONSTANT_STRING(L"ntdll.dll");
            UNICODE_STRING kernel32 = RTL_CONSTANT_STRING(L"kernel32.dll");
            UNICODE_STRING KernelBase = RTL_CONSTANT_STRING(L"KernelBase.dll");

            PLIST_ENTRY le1 = ppeb->Ldr->InMemoryOrderModuleList.Flink;
            PLIST_ENTRY le2 = le1;

            do {
                pldte = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(le1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (pldte->FullDllName.Length) //过滤掉最后一个，多余的。
                {
                    //KdPrint(("FullDllName:%wZ \n", &pldte->FullDllName));
                    //"C:\WINDOWS\system32\USER32.dll"，因为这里是完整路径，另一个思路是获取系统路径再组合。

                    PUNICODE_STRING pus = (PUNICODE_STRING)&pldte->Reserved4;
                    //if (RtlCompareUnicodeString(&pldte->FullDllName, &user32, TRUE) == 0)

                    if (RtlCompareUnicodeString(pus, &ntdll, TRUE) == 0) {
                        ANSI_STRING NtFreeVirtualMemory = RTL_CONSTANT_STRING("NtFreeVirtualMemory");

                        pUserData->ntdll = pldte->DllBase;

                        pUserData->NtFreeVirtualMemory = MiFindExportedRoutineByName(pldte->DllBase, &NtFreeVirtualMemory);
                        ASSERT(pUserData->NtFreeVirtualMemory);
                    }

                    if (RtlCompareUnicodeString(pus, &kernel32, TRUE) == 0) {
                        ANSI_STRING LoadLibraryW = RTL_CONSTANT_STRING("LoadLibraryW");
                        ANSI_STRING GetProcAddress = RTL_CONSTANT_STRING("GetProcAddress");

                        pUserData->kernel32 = pldte->DllBase;

                        pUserData->LoadLibraryW = MiFindExportedRoutineByName(pldte->DllBase, &LoadLibraryW);
                        ASSERT(pUserData->LoadLibraryW);

                        pUserData->GetProcAddress = MiFindExportedRoutineByName(pldte->DllBase, &GetProcAddress);
                        ASSERT(pUserData->GetProcAddress);
                    }
                }

                le1 = le1->Flink;
            } while (le1 != le2);
        }

        if (IsProcessPe64(UniqueProcess)) {
            RtlCopyMemory(pUserData->FullDllPathName, g_us_FullDllPathName.Buffer, g_us_FullDllPathName.Length);
        } else {

        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    KeUnstackDetachProcess(&ApcState);//解除附加

    *UserArgument = (SIZE_T)BaseAddress;

    ObDereferenceObject(Process);
    ZwClose(Handle);
}


NTSTATUS QueueApcThread(PCLIENT_ID ClientId)
/*
64位下要处理WOW64进程。

在win8下要关闭SMEP。
*/
{
    if (IsExcludeProcess(ClientId)) {
        return STATUS_UNSUCCESSFUL;
    }

    SIZE_T Argument = 0;
    InitialUserArgument(ClientId->UniqueProcess, &Argument);
    if (!Argument) {
        return STATUS_UNSUCCESSFUL;
    }

    SIZE_T UserRoutine;
    InitialUserRoutine(ClientId, &UserRoutine);
    ASSERT(UserRoutine != 0);

    NTSTATUS Status = ZwTestAlert();
    ASSERT(NT_SUCCESS(Status));

    Status = NtQueueApcThreadEx(ClientId->UniqueThread,
                                (PPS_APC_ROUTINE)UserRoutine,
                                NULL,
                                NULL,
                                (PVOID)Argument);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, pid:%p", Status, ClientId->UniqueProcess);
    }

    return Status;
}


#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef UseUserFun


PVOID GetLoadLibraryExWAddress(HANDLE UniqueProcess)
/*
功能：获取LoadLibraryExW的地址。

注意：支持X64，X86，以及WOW64(\Windows\SysWOW64\kernel32.dll).

你发现没？APC的用户态回调函数和LoadLibraryEx的参数个数一样，都是三个。
所以把APC的用户态回调函数直接设置为LoadLibraryExA/W不是更好吗？
这样，也不用shellcode,更不用自己在驱动申请内存再复制代码（或者shellcode）了。
注意函数的参数的调用方式。
但，这样做有一个缺点，无法进行别的操作，如：释放内存。
*/
{
    PVOID LoadLibraryExWAddress = NULL;
    PEPROCESS    Process;
    BOOL IsProcess64 = IsProcessPe64(UniqueProcess);
    NTSTATUS status = PsLookupProcessByProcessId(UniqueProcess, &Process);
    ASSERT(NT_SUCCESS(status));

    KAPC_STATE   ApcState;
    KeStackAttachProcess(Process, &ApcState);

    __try {//注意：处理过程中，进程可能会退出。
        PPEB ppeb = PsGetProcessPeb(Process);//注意：IDLE和system这两个应该获取不到。
        if (ppeb && ppeb->Ldr) {//进程启动时，Ldr为空。
            PLDR_DATA_TABLE_ENTRY pldte;
            UNICODE_STRING kernel32 = RTL_CONSTANT_STRING(L"kernel32.dll");

            PLIST_ENTRY le1 = ppeb->Ldr->InMemoryOrderModuleList.Flink;
            PLIST_ENTRY le2 = le1;

            do {
                pldte = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(le1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (pldte->FullDllName.Length) //过滤掉最后一个，多余的。
                {
                    //KdPrint(("FullDllName:%wZ \n", &pldte->FullDllName));
                    //"C:\WINDOWS\system32\USER32.dll"，因为这里是完整路径，另一个思路是获取系统路径再组合。

                    PUNICODE_STRING pus = (PUNICODE_STRING)&pldte->Reserved4;
                    //if (RtlCompareUnicodeString(&pldte->FullDllName, &user32, TRUE) == 0)

                    ANSI_STRING LoadLibraryExW = RTL_CONSTANT_STRING("LoadLibraryExW");

#ifdef _WIN64
                    if (IsProcessPe64) {
                        if (RtlCompareUnicodeString(pus, &kernel32, TRUE) == 0) {
                            LoadLibraryExWAddress = MiFindExportedRoutineByName(pldte->DllBase, &LoadLibraryExW);
                            break;
                        }
                    } else {//WOW64.
                        if (RtlCompareUnicodeString(pus, &kernel32, TRUE) == 0) {
                            LoadLibraryExWAddress = MiFindExportedRoutineByName(pldte->DllBase, &LoadLibraryExW);
                            break;
                        }
                    }
#else
                    if (RtlCompareUnicodeString(pus, &kernel32, TRUE) == 0) {
                        LoadLibraryExWAddress = MiFindExportedRoutineByName(pldte->DllBase, &LoadLibraryExW);
                        break;
                    }
#endif
                }

                le1 = le1->Flink;
            } while (le1 != le2);
        }

    #if defined(_WIN64)
        //如果是WOW64进程需要执行下面的代码，所以要添加判断WOW64的代码。
        //ZwQueryInformationProcess +　ProcessWow64Information
        //PWOW64_PROCESS pwp = (PWOW64_PROCESS)PsGetProcessWow64Process(Process);
        //if (NULL != pwp) {
        //    EnumWow64Module(pwp, CallBack, Context);
        //}
    #endif
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(Process);

    return LoadLibraryExWAddress;
}


PVOID SetDllFullPath(HANDLE UniqueProcess)
/*
功能：再目标进程中申请一块内存用户存储DLL的路径。

注意：支持X64，X86，以及WOW64.
*/
{
    BOOL IsProcess64 = IsProcessPe64(UniqueProcess);
    PEPROCESS Process = NULL;
    HANDLE  Handle = 0;
    PVOID DllFullPath = NULL;//必须制定为0，否则返回参数错误。 

    __try {
        NTSTATUS status = PsLookupProcessByProcessId(UniqueProcess, &Process);
        if (!NT_SUCCESS(status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x, pid:%d", status, HandleToULong(UniqueProcess));
            __leave;
        }

        status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &Handle);
        if (!NT_SUCCESS(status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x, pid:%d", status, HandleToULong(UniqueProcess));
            __leave;
        }

        SIZE_T size = 0;
    #ifdef _WIN64
        if (IsProcess64) {
            size = g_us_FullDllPathName.Length;
        } else {//WOW64.
            size = g_us_FullDllPathNameWow64.Length;
        }
    #else
        size = g_us_FullDllPathName.Length;
    #endif
         
        status = ZwAllocateVirtualMemory(Handle, &DllFullPath, 0, &size, MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {//如果是PAGE_EXECUTE_READWRITE会出现STATUS_DYNAMIC_CODE_BLOCKED.
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x, pid:%d, size:%lld",
                  status, HandleToULong(UniqueProcess), size);
            __leave;
        }

        KAPC_STATE   ApcState;
        KeStackAttachProcess(Process, &ApcState);

        __try {
        #ifdef _WIN64
            if (IsProcess64) {
                RtlCopyMemory(DllFullPath, g_us_FullDllPathName.Buffer, g_us_FullDllPathName.Length);
            } else {//WOW64.
                RtlCopyMemory(DllFullPath, g_us_FullDllPathNameWow64.Buffer, g_us_FullDllPathNameWow64.Length);
            }
        #else
            RtlCopyMemory(DllFullPath, g_us_FullDllPathName.Buffer, g_us_FullDllPathName.Length);
        #endif
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
        }

        KeUnstackDetachProcess(&ApcState);//解除附加
    } __finally {
        if (Process) {
            ObDereferenceObject(Process);
        }

        if (Handle) {
            ZwClose(Handle);
        }
    }

    return DllFullPath;
}


NTSTATUS NTAPI ZwQueueApcThreadEx(__in HANDLE ThreadHandle,
                                  __in PPS_APC_ROUTINE ApcRoutine,
                                  __in_opt PVOID ApcArgument1,
                                  __in_opt PVOID ApcArgument2,
                                  __in_opt PVOID ApcArgument3
)
/*
对NtQueueApcThread的封装。

第一个参数，是用户态的句柄，其实是tid.
*/
{
    PETHREAD Thread;
    NTSTATUS Status = PsLookupThreadByThreadId(ThreadHandle, &Thread);
    if (NT_SUCCESS(Status)) {
        if (PsIsSystemThread(Thread)) {
            Status = STATUS_INVALID_HANDLE;
        } else {
            HANDLE KernelHandle;
            Status = ObOpenObjectByPointer(Thread,
                                           OBJ_KERNEL_HANDLE,
                                           NULL,
                                           THREAD_ALERT,
                                           *PsThreadType,
                                           KernelMode,
                                           &KernelHandle);
            if (NT_SUCCESS(Status)) {
                Status = g_ZwQueueApcThread(KernelHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
                if (!NT_SUCCESS(Status)) {
                    PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
                }

                ZwClose(KernelHandle);
            }
        }

        ObDereferenceObject(Thread);
    }

    return Status;
}


NTSTATUS QueueApcThread(PCLIENT_ID ClientId)
/*
64位下要处理WOW64进程。

在win8下要关闭SMEP。
*/
{
    //if (IsExcludeProcess(ClientId)) {
    //    return STATUS_UNSUCCESSFUL;
    //}

    PVOID Argument = SetDllFullPath(ClientId->UniqueProcess);
    if (!Argument) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "pid:%d", HandleToUlong(ClientId->UniqueProcess));
        return STATUS_UNSUCCESSFUL;
    }

    //PPS_APC_ROUTINE UserRoutine = GetLoadLibraryExWAddress(ClientId->UniqueProcess);

    PPS_APC_ROUTINE UserRoutine = NULL;
    if (IsWow64Process(ClientId->UniqueProcess)) {
        UserRoutine = (PPS_APC_ROUTINE)LoadLibraryExWWow64Fn;
    } else {
        UserRoutine = (PPS_APC_ROUTINE)LoadLibraryExWFn;
    }  

    if (!UserRoutine) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "pid:%d", HandleToUlong(ClientId->UniqueProcess));
        return STATUS_UNSUCCESSFUL;
    }

    if (!IsLoadKernel32(ClientId->UniqueProcess)) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS Status = ZwTestAlert();
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x, pid:%d, tid:%d",
              Status, HandleToULong(ClientId->UniqueProcess), HandleToULong(ClientId->UniqueThread));
    }

    if (g_ZwQueueApcThread) {//优先使用系统的。
        Status = ZwQueueApcThreadEx(ClientId->UniqueThread, UserRoutine, Argument, NULL, NULL);
    } else {
        Status = NtQueueApcThreadEx(ClientId->UniqueThread, UserRoutine, Argument, NULL, NULL);        
    }

    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, pid:%d, tid:%d",
              Status, HandleToULong(ClientId->UniqueProcess), HandleToULong(ClientId->UniqueThread));
    }

    return Status;
}


#endif // UseUserFun


//////////////////////////////////////////////////////////////////////////////////////////////////
