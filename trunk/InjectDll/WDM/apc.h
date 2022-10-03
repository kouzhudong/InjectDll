#pragma once


#include "pch.h"


typedef
VOID
(*PKNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );

typedef
VOID
(*PKKERNEL_ROUTINE) (
    IN struct _KAPC * Apc,
    IN OUT PKNORMAL_ROUTINE * NormalRoutine,
    IN OUT PVOID * NormalContext,
    IN OUT PVOID * SystemArgument1,
    IN OUT PVOID * SystemArgument2
    );

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
    IN struct _KAPC * Apc
    );

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI
VOID
KeInitializeApc(
    __out PRKAPC Apc,
    __in PRKTHREAD Thread,
    __in KAPC_ENVIRONMENT Environment,
    __in PKKERNEL_ROUTINE KernelRoutine,
    __in_opt PKRUNDOWN_ROUTINE RundownRoutine,
    __in_opt PKNORMAL_ROUTINE NormalRoutine,
    __in_opt KPROCESSOR_MODE ProcessorMode,
    __in_opt PVOID NormalContext
);

typedef
PLIST_ENTRY
(*KeFlushQueueApcT) (//XP 未导出。
                     __inout PKTHREAD Thread,
                     __in KPROCESSOR_MODE ProcessorMode
                     );

NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
    __inout PRKAPC Apc,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2,
    __in KPRIORITY Increment
);

typedef
BOOLEAN
(*KeRemoveQueueApcT) (//XP 未导出。
                      __inout PKAPC Apc
                      );


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef
NTSYSAPI
NTSTATUS
(NTAPI *
 ZwTestAlertT) (//XP 内核没有导出。
                VOID
                );


NTSYSAPI
NTSTATUS
NTAPI
ZwAlertThread(//XP 内核导出。
              __in HANDLE ThreadHandle
);

typedef
NTSYSAPI
NTSTATUS
(NTAPI *
 ZwSuspendThreadT) (//XP 内核没有导出
                    __in HANDLE ThreadHandle,
                    __out_opt PULONG PreviousSuspendCount
                    );

typedef
NTSYSAPI
NTSTATUS
(NTAPI *
 ZwResumeThreadT) (//XP 内核没有导出
                   __in HANDLE ThreadHandle,
                   __out_opt PULONG PreviousSuspendCount
                   );

typedef
NTSYSAPI
NTSTATUS
(NTAPI *
 ZwAlertResumeThreadT) (//XP 内核没有导出
                        __in HANDLE ThreadHandle,
                        __out_opt PULONG PreviousSuspendCount
                        );

typedef
NTSTATUS(NTAPI * ZwQueueApcThreadT)(__in HANDLE ThreadHandle,
                                    __in PPS_APC_ROUTINE ApcRoutine,
                                    __in_opt PVOID ApcArgument1,
                                    __in_opt PVOID ApcArgument2,
                                    __in_opt PVOID ApcArgument3);


//////////////////////////////////////////////////////////////////////////////////////////////////


extern SIZE_T ApcStateOffset;

extern ZwTestAlertT ZwTestAlert;
extern ZwQueueApcThreadT g_ZwQueueApcThread;
extern ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;

EXTERN_C BOOL NTAPI PsIsProtectedProcess(PEPROCESS Process);
EXTERN_C BOOL NTAPI PsIsProtectedProcessLight(PEPROCESS Process);
EXTERN_C BOOL NTAPI PsIsSystemProcess(PEPROCESS Process);
EXTERN_C PVOID /*EWOW64PROCESS*/ NTAPI PsGetProcessWow64Process(PEPROCESS Process);//返回值非NULL即为Wow64Process。
EXTERN_C PUCHAR PsGetProcessImageFileName(PEPROCESS Process); //未公开的函数。

NTSTATUS QueueApcThread(PCLIENT_ID ClientId);
PVOID SetDllFullPath(HANDLE UniqueProcess);
