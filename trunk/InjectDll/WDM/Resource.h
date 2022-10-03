#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


extern UNICODE_STRING g_us_FullDllPathName;
extern UNICODE_STRING g_us_FullDllPathNameWow64;

extern PUNICODE_STRING g_RegistryPath;


void BuildDLL();
