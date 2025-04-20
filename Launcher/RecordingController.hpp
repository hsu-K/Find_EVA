#pragma once
#include <windows.h>
#include "Recording.hpp"

class RecordingController
{
public:
	// ���2�өI�s�O�_�O�ۦP���A�p�G�O�ۦP���A�N��^TRUE
	// ���2�өI�s��type�M��ctx
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

