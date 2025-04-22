#include "pch.h"
#include "CoreUtil.hpp"

// 用於判斷是否要跳過某個活動的記錄，主要用於 Hook 機制中，並返回一個布林值和一個 Hash 值
BOOL SkipActivity(UINT64* Hash)
{
	BOOL* flag;
	// 判斷當前線程索引是否已經有創建TLS，如果沒有就直接返回FALSE
	flag = (BOOL*)TlsGetValue(dwTlsIndex);
	if (flag == NULL) {
		// TLS not created yet for this thread
		return FALSE;
	}
	// 如果當前已經在Hook中，返回TRUE以免重複紀錄
	if (*flag == TRUE) {
		// we are already in a hook.
		// no sub-activity will be recorded.
		// no need to calculate hash.
		return TRUE;
	}
	else {
		// 不在Hook中，但是已經有創建了TLS
		// we are not in a hook
		// but we may originate from a new worker thread
		// stack trace will confirm our origin
		// Quote from Microsoft Documentation: You can capture up to MAXUSHORT frames (65534).

		BOOL allforeign = TRUE;
		PVOID trace[MAX_TRACE_DEPTH];
		(*Hash) = 0; // init
		// 獲取當前執行緒的呼叫堆疊追蹤
		WORD cap = RtlCaptureStackBackTrace(1, MAX_TRACE_DEPTH, trace, NULL); // no hash
		for (WORD i = 0; i < cap; i++) {
			// 計算在目標程式範圍內的呼叫的Hash值
			if (trace[i] >= TargetBase && trace[i] <= TargetEnd) {
				(*Hash) += (UINT32)trace[i];
				allforeign = FALSE;
			}
		}
		return allforeign; // skip unless the backtrace validates domestic
	}
	return FALSE;
}

// 讓TLS不為空，並且設置為TRUE，表示在Hook內
BOOL* EnterHook()
{
	BOOL* flag;
	// 從對應的線程索引取得flag，判斷是否已經有為TLS分配空間，如果沒有就分配空間給他；如果有就設置flag為TRUE
	flag = (BOOL*)TlsGetValue(dwTlsIndex);
	if (flag == NULL) {
		// make sure the TLS value exists
		flag = (BOOL*)LocalAlloc(LPTR, sizeof(BOOL));
		if (flag == NULL)
			return NULL;
		if (!TlsSetValue(dwTlsIndex, flag))
			return NULL;
	}
	*flag = TRUE;
	return flag;
}




// 紀錄Call的狀態資訊，並使用hash作為Call來源，最後寫入pipe傳回主程式
int RecordCall(Call c, ContextType type, ContextValue* value, UINT64 hash) {
	Recording rec;
	rec.call = c;
	rec.type = type;

	if (type != CTX_NONE && value != NULL) {
		rec.value = *value;
	}

	// 紀錄origin為hash，利用呼叫堆疊來當作來源判斷
	rec.origin = hash;

	DWORD dwWritten;
	// 寫入pipe
	WriteFile(hPipe, (void*)&rec, sizeof(rec), &dwWritten, NULL);
	return 1;
}

// find a mutation in the list for a specific call, starting from a specific start point
// 依照CTX的內容，找到對應的Mutation
Mutation* FindMutation(Mutation* start, ContextType ctxType, ContextValue* ctxValue)
{
	// we need to match the context to find whether there is a mutation.
	// the context is found in the call hook, and then sent here, we loop through the mutations to match.
	// should be max one full walk of the list.

	// we need to know the context type s.t. we can compare the right type (num/str)

	// TODO: if Recording CTX == "*", any context match will do.
	// are there any calls that can have both NUM & STR context? Currently not considered!
	// ^ only findresource() does this but it is not mutated.

	Mutation* loop = start;
	//cout << "ctxType: " << ctxType << endl;

	if (start == NULL) {
		return NULL;
	}
	printf("---------------------------------------------\n");
	printf("正在判斷Mutation: %d", start->rec.call);

	if (ctxType == CTX_NUM) {
		while (loop != NULL) {
			if (loop->rec.value.dwCtx == ctxValue->dwCtx) {
				// context match
				break;
				return loop;
			}
			loop = loop->next;
		}
	}
	else if (ctxType == CTX_STR) {
		/* experiment stage: preventive substring mutations */
		// the call ID are already matched through the per-call Mutation lists
		// if the recording CTX is substring, is it artificially created, and should match substring.
		while (loop != NULL) {
			if (loop->rec.type == CTX_SUB) {
				// assumes substring target ctx is lower case !
				wchar_t tempBuffer[MAX_CTX_LEN];
				wcscpy_s(tempBuffer, MAX_CTX_LEN, ctxValue->szCtx);
				_wcslwr_s(tempBuffer, MAX_CTX_LEN);
				if (wcsstr(tempBuffer, loop->rec.value.szCtx) != NULL) { // is target a substring of ctx?
					// context match
					break;
					return loop;
				}
			}
			else { // CTX_STR
				// new: case insensitive comparison
				//cout << "loop->rec.value.szCtx: " << loop->rec.value.szCtx << " ctxValue->szCtx: " << ctxValue->szCtx << endl;
				if (wcsncmp(loop->rec.value.szCtx, ctxValue->szCtx, MAX_CTX_LEN) == 0) {
					// context match
					break;
					return loop;
				}
			}
			loop = loop->next;
		}
	}
	if (loop != NULL) {
		printf(" / 找到Mutation\n");
	}
	else {
		printf(" / 沒找到Mutation\n");
	}
	printf("---------------------------------------------\n");

	return loop;
}
