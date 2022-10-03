#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


extern UNICODE_STRING g_DosKernel32Path;
extern UNICODE_STRING g_Ntkernel32Path;
extern UNICODE_STRING g_DosKernelWow64Path;
extern UNICODE_STRING g_NtkernelWow64Path;

extern SIZE_T LoadLibraryExWFn; 
#ifdef _WIN64
extern SIZE_T LoadLibraryExWWow64Fn; 
#endif

extern SIZE_T LoadLibraryWFn;
#ifdef _WIN64
extern SIZE_T LoadLibraryWWow64Fn;
#endif

void GetKernel32FullPath();
BOOL IsLoadKernel32(HANDLE UniqueProcess);
NTSTATUS GetLoadLibraryExWAddressByEnum();
VOID ImageNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
