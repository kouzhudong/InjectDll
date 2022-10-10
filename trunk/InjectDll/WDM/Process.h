#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _PROCESS_CONTEXT {
    LIST_ENTRY  ListEntry;

    HANDLE Pid;//链表中的唯一标识。即KEY。

    ULONG Tids;//线程的个数。

    HANDLE MainThreadId;
    BOOLEAN IsCanInject;//可注入吗？即相应的kernel32.dll加载了吗？
    BOOLEAN IsInjected;//已经成功注入了吗？
    HANDLE InjectThreadId;//注入的线程的ID。用于线程退出时，释放应用层的内存。
    HANDLE UniqueProcess;

    PVOID UserAddress;

} PROCESS_CONTEXT, * PPROCESS_CONTEXT;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern PAGED_LOOKASIDE_LIST g_ProcessContextLookasideList;


VOID ProcessNotifyRoutine(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);

void InitProcessContextList();
VOID RemoveProcessContextList();
PPROCESS_CONTEXT GetProcessContext(HANDLE Pid);
BOOL UpdateProcessContext(PPROCESS_CONTEXT ProcessContext);
void InsertProcessContext(PPROCESS_CONTEXT Context);
