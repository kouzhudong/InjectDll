#include "test.h"
#include "apc.h"
#include "Resource.h"
#include "Inject.h"
#include "Process.h"
#include "Thread.h"
#include "Image.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID GetSomeSystemRoutineAddress()
{
    ZwTestAlert = (ZwTestAlertT)GetZwRoutineAddress("ZwTestAlert");
    g_ZwQueueApcThread = (ZwQueueApcThreadT)GetZwRoutineAddress("ZwQueueApcThread");

    ZwQueryVirtualMemoryFn = (ZwQueryVirtualMemory_PFN)GetZwRoutineAddress("ZwQueryVirtualMemory");
    SetZwQueryVirtualMemoryAddress(ZwQueryVirtualMemoryFn);

    UNICODE_STRING Temp;
    RtlCreateUserThreadFn RtlCreateUserThread;
    RtlInitUnicodeString(&Temp, L"RtlCreateUserThread");
    RtlCreateUserThread = (RtlCreateUserThreadFn)MmGetSystemRoutineAddress(&Temp);
    SetRtlCreateUserThreadAddress(RtlCreateUserThread);

    ZwCreateThreadEx = (ZwCreateThreadExFn)GetZwRoutineAddress("ZwCreateThreadEx");
    SetZwCreateThreadExAddress(ZwCreateThreadEx);
}


void init()
{
    DisSmep();

    GetApcStateOffset(&ApcStateOffset);

    GetKernel32FullPath();

    GetSomeSystemRoutineAddress();    

    GetLoadLibraryExWAddressByEnum();

    InitProcessContextList();

    BuildDLL();
}


DRIVER_UNLOAD Unload;
VOID Unload(__in PDRIVER_OBJECT DriverObject)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Status = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", Status);
    }

    Status = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
    }

    Status = PsRemoveLoadImageNotifyRoutine(ImageNotifyRoutine);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", Status);
    }

    RemoveProcessContextList();

    FreeUnicodeString(&g_DllDosFullPath);
    FreeUnicodeString(&g_DllDosFullPathWow64);

    FreeUnicodeString(&g_Ntkernel32Path);
    FreeUnicodeString(&g_DosKernel32Path);

    FreeUnicodeString(&g_NtkernelWow64Path);
    FreeUnicodeString(&g_DosKernelWow64Path);
}


DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(__in struct _DRIVER_OBJECT * DriverObject, __in PUNICODE_STRING  RegistryPath)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();//__debugbreak();
    }

    UseNoExecuteMemory();

    //  Default to NonPagedPoolNx for non paged pool allocations where supported.   
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    DriverObject->DriverUnload = Unload;

    init();

    __try {
        Status = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            __leave;
        }        

        Status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            __leave;
        }

        Status = PsSetLoadImageNotifyRoutine(ImageNotifyRoutine);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        InjectAllProcess();//不建议检查返回值。
    } __finally {
        if (!NT_SUCCESS(Status)) {
            Unload(DriverObject);
        }
    }

    return Status;
}
