#pragma once
#include <windows.h>
#include "communication.h"
#define MAX_CTX_LEN 260

enum ContextType {
	CTX_NONE,
	CTX_STR,
	CTX_NUM,
	CTX_SUB // special case for preventive experiment
};

union ContextValue {
	// all considered contexts can be represented as a string or integer
	wchar_t szCtx[MAX_CTX_LEN];
	DWORD dwCtx;
};

// 魁琌ぐ或ㄧ计のㄤ把计
class Recording {
public:
	Call call;
	ContextType type;
	ContextValue value;
	UINT64 origin;
	UINT64 ret_addr = 0;
};

