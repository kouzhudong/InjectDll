#pragma once

#include "pch.h"

NTSTATUS WINAPI InjectOneProcess(_In_ HANDLE UniqueProcessId, _In_opt_ PVOID Context);
NTSTATUS InjectAllProcess(VOID);
