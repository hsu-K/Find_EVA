#pragma once
#include <windows.h>
#include "Recording.hpp"

class RecordingController
{
public:
	// 比較2個呼叫是否是相同的，如果是相同的，就返回TRUE
	// 比較2個呼叫的type和其ctx
	static BOOL IsRecordingIdentical(Recording* src, Recording* cmp)
	{
		if (cmp == nullptr) {
			return false;
		}

		if (src->call == cmp->call) {
			if (src->type == cmp->type) { // always true probably
				if (src->type == CTX_NONE) {
					return true;
				}
				else if (src->type == CTX_NUM) {
					// context match
					return src->value.dwCtx == cmp->value.dwCtx;
				}
				else if (src->type == CTX_STR) {
					// context match
					return (wcsncmp(src->value.szCtx, cmp->value.szCtx, MAX_CTX_LEN) == 0);
				}
			}
		}
		return false;
	}

};

