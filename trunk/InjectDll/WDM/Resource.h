#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


extern UNICODE_STRING g_DllDosFullPath;
extern UNICODE_STRING g_DllDosFullPathWow64;

extern PUNICODE_STRING g_RegistryPath;


void BuildDLL();
