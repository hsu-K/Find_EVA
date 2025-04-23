#pragma once

#include <Windows.h>
#include <winternl.h>
#include "communication.h"
#include "Mutation.hpp"
#include <iostream>

// 盽计﹚竡
#define MAX_TRACE_DEPTH 32
#define TARGET_DLL "mut_DLL.dll"

// 办跑计羘
extern HANDLE hPipe;
extern DWORD dwTlsIndex;
extern volatile ULONG TimeShift;
extern double dFreq;
extern BYTE* TargetBase;
extern BYTE* TargetEnd;
extern UINT64 ImageBase;

// ㄧ计羘
BOOL SkipActivity(UINT64* Hash, UINT64* ret_addr=nullptr);
BOOL* EnterHook();
int GetKeyNameFromHandle(HANDLE key, wchar_t* dest, PULONG size);
int GetFileNameFromHandle(HANDLE file, wchar_t* dest, PULONG size);
int RecordCall(Call c, ContextType type, ContextValue* value, UINT64 hash);
int RecordCall(Call c, ContextType type, ContextValue* value, UINT64 hash, UINT64 ret_addr);
Mutation* FindMutation(Mutation* start, ContextType ctxType, ContextValue* ctxValue, UINT64 origin = 0);