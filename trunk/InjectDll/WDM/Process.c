#include "Process.h"


LIST_ENTRY g_ProcessContextList;//用于存储注册表上下文的链表。
ERESOURCE g_ProcessContextListResource;
BOOL g_IsInitProcessContextList;


//////////////////////////////////////////////////////////////////////////////////////////////////


//\Windows-driver-samples\filesys\miniFilter\avscan\filter\utility.h
//FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
AcquireResourceExclusive(_Inout_ _Acquires_exclusive_lock_(*Resource) PERESOURCE Resource)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) || !ExIsResourceAcquiredSharedLite(Resource));

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);
}


//\Windows-driver-samples\filesys\miniFilter\avscan\filter\utility.h
//FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
AcquireResourceShared(_Inout_ _Acquires_shared_lock_(*Resource) PERESOURCE Resource)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceSharedLite(Resource, TRUE);
}


//\Windows-driver-samples\filesys\miniFilter\avscan\filter\utility.h
//FORCEINLINE
VOID
_Releases_lock_(_Global_critical_region_)
_Requires_lock_held_(_Global_critical_region_)
ReleaseResource(_Inout_ _Requires_lock_held_(*Resource) _Releases_lock_(*Resource) PERESOURCE Resource)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) || ExIsResourceAcquiredSharedLite(Resource));

    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}


//////////////////////////////////////////////////////////////////////////////////////////////////
/*
进程上下文。
*/


void InitProcessContextList()
/*
调用时机：驱动入口。
*/
{
    InitializeListHead(&g_ProcessContextList);
    ExInitializeResourceLite(&g_ProcessContextListResource);
    g_IsInitProcessContextList = TRUE;
}


void InsertProcessContext(PPROCESS_CONTEXT Context)
/*
调用时机：所有CmSetCallbackObjectContext调用成功的地方。
*/
{
    AcquireResourceExclusive(&g_ProcessContextListResource);
    InsertTailList(&g_ProcessContextList, &Context->ListEntry);
    ReleaseResource(&g_ProcessContextListResource);
}


VOID RemoveProcessContext(PPROCESS_CONTEXT Context)
/*
调用时机：RegNtCallbackObjectContextCleanup。
*/
{
    AcquireResourceExclusive(&g_ProcessContextListResource);
    RemoveEntryList(&Context->ListEntry);
    ReleaseResource(&g_ProcessContextListResource);

    ExFreePoolWithTag(Context, TAG);
}


PPROCESS_CONTEXT GetProcessContext(HANDLE Pid)
/*
功能：释放（所有的）注册表的上下文。

调用时机：驱动卸载。
*/
{
    PPROCESS_CONTEXT ret = NULL;
    PLIST_ENTRY listEntry = NULL;
    PLIST_ENTRY List = &g_ProcessContextList;

    if (g_IsInitProcessContextList) {
        AcquireResourceExclusive(&g_ProcessContextListResource);
        for (listEntry = List->Flink; listEntry != List; listEntry = listEntry->Flink) {
            PPROCESS_CONTEXT node = CONTAINING_RECORD(listEntry, PROCESS_CONTEXT, ListEntry);
            if (node->Pid == Pid) {
                ret = node;
                break;
            }            
        }
        ReleaseResource(&g_ProcessContextListResource);
    }

    return ret;
}


VOID UpdateProcessContext(PPROCESS_CONTEXT ProcessContext)
/*

*/
{
    PLIST_ENTRY listEntry = NULL;
    PLIST_ENTRY List = &g_ProcessContextList;

    if (g_IsInitProcessContextList) {
        AcquireResourceExclusive(&g_ProcessContextListResource);
        for (listEntry = List->Flink; listEntry != List; listEntry = listEntry->Flink) {
            PPROCESS_CONTEXT node = CONTAINING_RECORD(listEntry, PROCESS_CONTEXT, ListEntry);
            if (node->Pid == ProcessContext->Pid) {
                if (ProcessContext->IsCanInject) {
                    node->IsCanInject = ProcessContext->IsCanInject;
                }

                if (ProcessContext->IsInjected) {
                    node->IsInjected = ProcessContext->IsInjected;
                }

                if (ProcessContext->InjectThreadId) {
                    node->InjectThreadId = ProcessContext->InjectThreadId;
                }

                if (ProcessContext->UserAddress) {
                    node->UserAddress = ProcessContext->UserAddress;
                }

                if (ProcessContext->UniqueProcess) {
                    node->UniqueProcess = ProcessContext->UniqueProcess;
                }

                break;
            }
        }
        ReleaseResource(&g_ProcessContextListResource);
    }
}


VOID RemoveProcessContextList()
/*
功能：释放（所有的）注册表的上下文。

调用时机：驱动卸载。
*/
{
    if (g_IsInitProcessContextList) {
        AcquireResourceExclusive(&g_ProcessContextListResource);
        while (!IsListEmpty(&g_ProcessContextList)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_ProcessContextList);
            PPROCESS_CONTEXT Context = CONTAINING_RECORD(entry, PROCESS_CONTEXT, ListEntry);

            ReleaseResource(&g_ProcessContextListResource);
            ExFreePoolWithTag(Context, TAG);
            AcquireResourceExclusive(&g_ProcessContextListResource);
        }
        ReleaseResource(&g_ProcessContextListResource);

        ExDeleteResourceLite(&g_ProcessContextListResource);
        g_IsInitProcessContextList = FALSE;
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID ProcessNotifyRoutine(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
    PAGED_CODE();

    if (Create) {
        PPROCESS_CONTEXT Context = (PPROCESS_CONTEXT)ExAllocatePoolWithTag(PagedPool, sizeof(PROCESS_CONTEXT), TAG);
        if (Context) {
            RtlZeroMemory(Context, sizeof(PROCESS_CONTEXT));
            Context->Pid = ProcessId;
            InsertProcessContext(Context);
        } else {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag Fail");
        }
    } else {
        PPROCESS_CONTEXT Context = GetProcessContext(ProcessId);
        if (Context) {
            RemoveProcessContext(Context);
        }
    }
}
