/*
功能：在驱动中用APC注入一段代码到某个进程中运行。

做法：倒是很简单就一个函数，如：NtQueueApcThread，但是这个函数没有导出，但可以动态获取。而且还有导出的KeInsertQueueApc之类的函数实现类似的功能。

进程，要排除IDLE，SYSTEM。smss.exe最好也排除，除非只用NTDLL.DLL的函数，但是加载其他DLL也可以的。

对于X64及X64中的WOW64需要再做改进/修改。
既然是注入DLL，第一次注入成功了，以后再注入的后果你是知道的。

插入了，何时运行还未知：快的需要几秒，慢的需要及分钟，甚至几十分钟，更深的几个小时或者几天几夜，甚至永远不会运行，如：不触发或者线程的状态不符合。

类似的办法还有：
1.IMAGE回调。
2.KernelCallbackTable = apfnDispatch
3.自己手动创建线程，要考虑X86，X64/WOW64等。

APC应该是一个不会取消的功能，因为：
1.引用层有：QueueUserAPC。
2.内核的DPC函数倒是公开了，如：KeInitializeDpc/KeInsertQueueDpc/KeRemoveQueueDpc。

本文是测试代码，尽管尽量规范的去写，但是还有一些BUG，如卸载等。

参考：
1.WRK
2.http://www.microsoft.com/msj/0799/nerd/nerd0799.aspx
3.http://www.rohitab.com/discuss/topic/40737-inject-dll-from-kernel-mode/
还有一份俄国的，写的也不错。

made by correy
made at 2015.12.25
http://correy.webs.com
*/

#include "pch.h"

typedef
int (NTAPI * MessageBoxT)(
    HWND hWnd,
    LPCTSTR lpText,
    LPCTSTR lpCaption,
    UINT uType
    );

#pragma warning(disable:4700)//使用了未初始化的局部变量“UserRoutine”


/*
摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx
*/
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


/*
摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\inc\ps.h
此函数在XP 32上就已经导出，应该可以放心使用。
或者ZwQueryInformationProcess 的 ProcessBasicInformation.
*/
NTKERNELAPI
PPEB
PsGetProcessPeb(
    __in PEPROCESS Process
);



//摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx
typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


//http://msdn.microsoft.com/en-us/library/windows/desktop/aa813741(v=vs.85).aspx
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


//摘自：Winternl.h。
typedef
VOID
(NTAPI * PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );


#ifdef _X86_
typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    BYTE                          Reserved4[104];
    PVOID                         Reserved5[52];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved6[128];
    PVOID                         Reserved7[1];
    ULONG                         SessionId;
} PEB, * PPEB;
#endif
//上下的结构定义，摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
#if defined(_WIN64)
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA Ldr;//LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB;
#endif 


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef
HMODULE(WINAPI * LoadLibraryT)(
    __in          LPCTSTR lpFileName
    );

typedef NTSTATUS(WINAPI * ZwFreeVirtualMemoryT)(
    __in HANDLE  ProcessHandle,
    __inout PVOID * BaseAddress,
    __inout PSIZE_T  RegionSize,
    __in ULONG  FreeType
    );

typedef struct _PassToUser {
    PVOID ntdll;
    PVOID kernel32;
    PVOID KernelBase;

    LoadLibraryT LoadLibraryW;
    PVOID GetProcAddress;
    PVOID LdrLoadDll;
    ZwFreeVirtualMemoryT NtFreeVirtualMemory;

    wchar_t FullDllPathName[MAX_PATH];
    wchar_t OtherData[MAX_PATH];

    SIZE_T RegionSize;

    BOOLEAN done;
} PassToUser, * PPassToUser;
