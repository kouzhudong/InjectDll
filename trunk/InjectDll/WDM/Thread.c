#include "Thread.h"
#include "Process.h"
#include "Resource.h"


VOID FreeUserMemory(_In_ PPROCESS_CONTEXT Context)
{
    PEPROCESS Process = NULL;
    HANDLE  Handle = 0;
    PVOID DllFullPath = NULL;//必须制定为0，否则返回参数错误。 

    __try {
        if (!Context) {
            __leave;
        }

        NTSTATUS status = PsLookupProcessByProcessId(Context->UniqueProcess, &Process);
        if (!NT_SUCCESS(status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x, pid:%d", status, HandleToULong(Context->UniqueProcess));
            __leave;
        }

        status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &Handle);
        if (!NT_SUCCESS(status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x, pid:%d", status, HandleToULong(Context->UniqueProcess));
            __leave;
        }

        SIZE_T Size = 0;
        if (IsWow64Process(Context->UniqueProcess)) {
            Size = g_DllDosFullPathWow64.Length;
        } else {
            Size = g_DllDosFullPath.Length;
        }
        if (!Size) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "pid:%d", HandleToULong(Context->UniqueProcess));
            __leave;
        }

        status = ZwFreeVirtualMemory(Handle, &Context->UserAddress, &Size, MEM_DECOMMIT);
        if (!NT_SUCCESS(status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x, pid:%d, Size:%lld",
                  status, HandleToULong(Context->UniqueProcess), (long long)Size);
            __leave;
        }
    } __finally {
        if (Process) {
            ObDereferenceObject(Process);
        }

        if (Handle) {
            ZwClose(Handle);
        }
    }
}


VOID ThreadNotifyRoutine(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
/*
目的：注入的线程结束时，释放申请的应用层的内存。
*/
{
    PPROCESS_CONTEXT Context = GetProcessContext(ProcessId);
    if (!Context) {
        
        return;
    }

    if (Context->InjectThreadId != ThreadId) {
        return;
    }

    if (Create) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Info: 注入的线程%p启动", ThreadId);//这个没触发？

        PROCESS_CONTEXT Temp = {0};
        Temp.Pid = ProcessId;
        Temp.IsInjected = TRUE;
        UpdateProcessContext(&Temp);
    } else {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Info: 注入的线程%d结束", HandleToUlong(ThreadId));

        FreeUserMemory(Context);

        PROCESS_CONTEXT Temp = {0};
        Temp.Pid = ProcessId;
        Temp.UserAddress = NULL;
        UpdateProcessContext(&Temp);
    }
}
