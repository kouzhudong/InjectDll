#include "test.h"
#include "apc.h"
#include "Resource.h"
#include "Inject.h"
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
}


void init()
{
    DisSmep();

    GetApcStateOffset(&ApcStateOffset);

    GetKernel32FullPath();

    GetSomeSystemRoutineAddress();    

    GetLoadLibraryExWAddressByEnum();

    BuildDLL();
}


VOID CreateProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);
#pragma alloc_text(PAGE, CreateProcessNotify)
VOID CreateProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
/*
此时不建议注入DLL，因为PEB为空，很多DLL还没加载。
*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ParentId);

    if (Create) {
        //InjectAllThread(ProcessId);
    }
}


DRIVER_UNLOAD Unload;
VOID Unload(__in PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    //status = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
    status = PsRemoveLoadImageNotifyRoutine(ImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", status);
    }
}


DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(__in struct _DRIVER_OBJECT * DriverObject, __in PUNICODE_STRING  RegistryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();//__debugbreak();
    }

    //  Default to NonPagedPoolNx for non paged pool allocations where supported.   
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    g_RegistryPath = RegistryPath;

#if DBG 
    DriverObject->DriverUnload = Unload;//禁止卸载。
#endif

    init();

    //status = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
    status = PsSetLoadImageNotifyRoutine(ImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "status:%#x", status);
        return status;
    }

    status = InjectAllProcess();

    return STATUS_SUCCESS;
}
