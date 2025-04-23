#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"

HWND WINAPI HookFindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
	HWND ret;
	// Mutation types: MUT_FAIL
	// maybe also include GetWindowText

	BOOL* flag = NULL;
	if (lpWindowName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = strlen(lpWindowName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpWindowName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowA, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowA(lpClassName, lpWindowName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookFindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName)
{
	HWND ret;
	// Mutation types: MUT_FAIL

	BOOL* flag = NULL;
	if (lpWindowName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpWindowName);
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			wcsncpy(ctxVal.szCtx, lpWindowName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowW, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowW(lpClassName, lpWindowName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookFindWindowExA(HWND hWndParent, HWND hWndChildAfter, LPCSTR lpszClass, LPCSTR lpszWindow)
{
	HWND ret;
	// Mutation types: MUT_FAIL
	// BOOL* flag = NULL;

	BOOL* flag = NULL;
	if (lpszWindow != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = strlen(lpszWindow) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpszWindow, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowExA, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowExA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowExA(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookFindWindowExW(HWND hWndParent, HWND hWndChildAfter, LPCWSTR lpszClass, LPCWSTR lpszWindow)
{
	HWND ret;
	// Mutation types: MUT_FAIL
	// BOOL* flag = NULL;

	BOOL* flag = NULL;
	if (lpszWindow != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpszWindow);
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			wcsncpy(ctxVal.szCtx, lpszWindow, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowExW, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowExW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowExW(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookGetWindowRect(HWND hWnd, LPRECT lpRect)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	// BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetWindowRect, CTX_NONE, NULL, Hash);
	}
	ret = OgGetWindowRect(hWnd, lpRect);
	return ret;
}

BOOL WINAPI HookGetMonitorInfoA(HMONITOR hMonitor, LPMONITORINFO lpmi)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	// BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetMonitorInfoA, CTX_NONE, NULL, Hash);
	}
	ret = OgGetMonitorInfoA(hMonitor, lpmi);
	return ret;
}

BOOL WINAPI HookGetMonitorInfoW(HMONITOR hMonitor, LPMONITORINFO lpmi)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	// BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetMonitorInfoW, CTX_NONE, NULL, Hash);
	}
	ret = OgGetMonitorInfoW(hMonitor, lpmi);
	return ret;
}

int WINAPI HookGetSystemMetrics(int nIndex)
{
	int ret;
	// Mutation types: MUT_ALT_TUP
	BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = nIndex;
		RecordCall(Call::cGetSystemMetrics, CTX_NUM, &ctxVal, Hash);

		// mut fail: return 0
		/*Mutation* mut = FindMutation(mutGetSystemMetrics, CTX_NUM, &ctxVal);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return 0;
			}
		}*/
	}
	ret = OgGetSystemMetrics(nIndex);
	return ret;
}

BOOL WINAPI HookSystemParametersInfoA(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = uiAction;
		RecordCall(Call::cSystemParametersInfoA, CTX_NUM, &ctxVal, Hash);
		/*
		Mutation* mut = FindMutation(mutSystemParametersInfoA, CTX_NUM, &ctxVal);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return 0;
			}
		}*/
	}
	ret = OgSystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
	return ret;
}

BOOL WINAPI HookSystemParametersInfoW(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = uiAction;
		RecordCall(Call::cSystemParametersInfoW, CTX_NUM, &ctxVal, Hash);
		/*
		Mutation* mut = FindMutation(mutSystemParametersInfoW, CTX_NUM, &ctxVal);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return 0;
			}
		}*/
	}
	ret = OgSystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
	return ret;
}

HWND WINAPI HookGetForegroundWindow()
{
	HWND ret;
	// Mutation types: MUT_RND_NUM (random window)

	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetForegroundWindow, CTX_NONE, NULL, Hash);

		if (mutGetForegroundWindow != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
			printf("Applying GetForegroundWindow mutation!\n");
#endif
			if (mutGetForegroundWindow->mutType == MUT_RND_NUM) {
				HWND window = GetTopWindow(GetDesktopWindow());
				if (window == NULL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
				HWND nextwin = NULL;
				int cnt = rand() % 4 + 1; // 1 2 3 4
				while (cnt > 0) {
					nextwin = GetWindow(window, GW_HWNDNEXT);
					if (nextwin == NULL) {
						break;
					}
					window = nextwin;
					if (!IsWindowVisible(window))
						continue;
					cnt--;
				}
				if (flag) (*flag) = FALSE;
				return window;
			}
		}
	}

	ret = OgGetForegroundWindow();
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookGetCursorPos(LPPOINT lpPoint)
{
	// MUT_TEST #1
	BOOL ret;
	// Mutation types: MUT_ALT_TUP, MUT_RND_TUP
	BOOL* flag = NULL;
	//printf("GetCursorPos Return Addr: %p\n", _ReturnAddress());

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetCursorPos, CTX_NONE, NULL, Hash);

		if (mutGetCursorPos != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
			printf("Applying GetCursorPos mutation!\n");
#endif
			if (mutGetCursorPos->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return (BOOL)mutGetCursorPos->mutValue.nValue;
			}
			else if (mutGetCursorPos->mutType == MUT_ALT_TUP) {
				// there are alternative values
				ret = OgGetCursorPos(lpPoint);
				if (ret) {
					lpPoint->x = (LONG)mutGetCursorPos->mutValue.tupValue[0];
					lpPoint->y = (LONG)mutGetCursorPos->mutValue.tupValue[1];
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
			else if (mutGetCursorPos->mutType == MUT_RND_TUP) {
				// generate alternative values
				ret = OgGetCursorPos(lpPoint);
				if (ret) {
					lpPoint->x = (LONG)rand() % 1920;
					lpPoint->y = (LONG)rand() % 1080;
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
	}

	ret = OgGetCursorPos(lpPoint);
	if (flag) (*flag) = FALSE;
	return ret;
}

SHORT WINAPI HookGetAsyncKeyState(int vKey)
{
	SHORT ret;
	// Mutation types: MUT_SUCCEED
	BOOL* flag = NULL;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetAsyncKeyState, CTX_NONE, NULL, Hash);

		if (mutGetAsyncKeyState != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
			printf("Applying GetAsyncKeyState mutation!\n");
#endif
			if (mutGetAsyncKeyState->mutType == MUT_SUCCEED) {
				if (flag) (*flag) = FALSE;
				return (SHORT)0x8001;
			}
		}
	}

	ret = OgGetAsyncKeyState(vKey);
	if (flag) (*flag) = FALSE;
	return ret;
}


int WINAPI HookMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;

	// �ˬd�O�_�ݭn�O�����ե�
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();

		// �O���եθ�T
		ContextValue ctxVal;
		// �O����ܮؼ��D
		size_t capLen = wcslen(lpCaption);
		if (capLen >= MAX_CTX_LEN - 1) {
			capLen = MAX_CTX_LEN - 10;  // �O�d�@�ǪŶ����奻���e
		}
		wcsncpy(ctxVal.szCtx, lpCaption, capLen);
		ctxVal.szCtx[capLen] = L':';

		// �l�[��ܮؤ奻���e�X�Ӧr��
		size_t textLen = wcslen(lpText);
		size_t remainLen = MAX_CTX_LEN - capLen - 2;  // �������D+�_��������
		if (textLen > remainLen) {
			textLen = remainLen;
		}
		wcsncpy(ctxVal.szCtx + capLen + 1, lpText, textLen);
		ctxVal.szCtx[capLen + 1 + textLen] = L'\0';

		// �O���ե�
		RecordCall(Call::cMessageBoxW, CTX_STR, &ctxVal, Hash, RetAddr);

#ifdef __DEBUG_PRINT
		printf("MessageBoxW detected: %ws - %ws\n", lpCaption, lpText);
#endif
		// ��������Mutation
		Mutation* mut = FindMutation(mutMessageBoxW, CTX_STR, &ctxVal, Hash);
		if (mut != NULL) {
			if (mut->mutType == MUT_ALT_NUM) {
#ifdef __DEBUG_PRINT
				printf("Applying MUT_FAIL mutation to NtOpenKey.\n");
#endif
				if (flag) { (*flag) = FALSE; }
				//std::cout << "�j����ܡA��m: 0x" << std::hex << Call_from << std::dec << std::endl;
				// �j�����ƪ��^�ǭ�
				return (NTSTATUS)mut->mutValue.nValue;
			}
		}

		// �b�o�̧ڭ̥i�H�ߧY��^�@�ӵ��G�A�Ӥ������ܹ�ܮ�
		// �����Τ��ܤF�u�T�w�v���s (IDOK = 1)
		//if (flag) (*flag) = FALSE;
		ret = OgMessageBoxW(hWnd, lpText, lpCaption, uType);
		//cout << *flag << endl;
		if (flag) (*flag) = FALSE;
		return ret;
		//return IDOK;
	}

	// �p�G���ݭnhook�h�����l���
	ret = OgMessageBoxW(hWnd, lpText, lpCaption, uType);
	if (flag) (*flag) = FALSE;
	return ret;
}

int WINAPI HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;

	// �ˬd�O�_�ݭn�O�����ե�
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();

		// �O���եθ�T
		ContextValue ctxVal;

		// ���N ANSI �r���ഫ���e�r�šA�H�K�Τ@�B�z
		// �O����ܮؼ��D
		size_t capLen = strlen(lpCaption);
		if (capLen >= MAX_CTX_LEN - 1) {
			capLen = MAX_CTX_LEN - 10;  // �O�d�@�ǪŶ����奻���e
		}

		// �ഫ���D�q ANSI ��e�r��
		size_t convertedChars = 0;
		mbstowcs_s(&convertedChars, ctxVal.szCtx, MAX_CTX_LEN, lpCaption, capLen);
		ctxVal.szCtx[capLen] = L':';

		// �l�[��ܮؤ奻���e�X�Ӧr��
		size_t textLen = strlen(lpText);
		size_t remainLen = MAX_CTX_LEN - capLen - 2;  // �������D+�_��������
		if (textLen > remainLen) {
			textLen = remainLen;
		}

		// �ഫ�奻�q ANSI ��e�r�šA�ñ��b�_���᭱
		mbstowcs_s(&convertedChars, ctxVal.szCtx + capLen + 1,
			MAX_CTX_LEN - capLen - 1, lpText, textLen);

		// �T�O�r�Ŧ꥿�T�פ�
		ctxVal.szCtx[MAX_CTX_LEN - 1] = L'\0';

		// �O���ե�
		RecordCall(Call::cMessageBoxA, CTX_STR, &ctxVal, Hash);

#ifdef __DEBUG_PRINT
		printf("MessageBoxA detected: %s - %s\n", lpCaption, lpText);
#endif
		// ��������Mutation
		Mutation* mut = FindMutation(mutMessageBoxA, CTX_STR, &ctxVal);
		if (mut != NULL) {
			if (mut->mutType == MUT_ALT_NUM) {
#ifdef __DEBUG_PRINT
				printf("Applying MUT_ALT_NUM mutation to MessageBoxA.\n");
#endif
				if (flag) { (*flag) = FALSE; }
				// �j�����ƪ��^�ǭ�
				return (int)mut->mutValue.nValue;
			}
		}

		// �����l���
		ret = OgMessageBoxA(hWnd, lpText, lpCaption, uType);
		if (flag) (*flag) = FALSE;
		return ret;
	}

	// �p�G���ݭnhook�h�����l���
	ret = OgMessageBoxA(hWnd, lpText, lpCaption, uType);
	if (flag) (*flag) = FALSE;
	return ret;
}

int WINAPI HookMessageBoxExW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType, WORD wLanguageId)
{
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;

	// �ˬd�O�_�ݭn�O�����ե�
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();

		// �O���եθ�T
		ContextValue ctxVal;
		// �O����ܮؼ��D
		size_t capLen = wcslen(lpCaption);
		if (capLen >= MAX_CTX_LEN - 1) {
			capLen = MAX_CTX_LEN - 10;  // �O�d�@�ǪŶ����奻���e
		}
		wcsncpy(ctxVal.szCtx, lpCaption, capLen);
		ctxVal.szCtx[capLen] = L':';

		// �l�[��ܮؤ奻���e�X�Ӧr��
		size_t textLen = wcslen(lpText);
		size_t remainLen = MAX_CTX_LEN - capLen - 2;  // �������D+�_��������
		if (textLen > remainLen) {
			textLen = remainLen;
		}
		wcsncpy(ctxVal.szCtx + capLen + 1, lpText, textLen);
		ctxVal.szCtx[capLen + 1 + textLen] = L'\0';

		// �O���ե�
		RecordCall(Call::cMessageBoxExW, CTX_STR, &ctxVal, Hash);

#ifdef __DEBUG_PRINT
		printf("MessageBoxExW detected: %ws - %ws (language: %d)\n", lpCaption, lpText, wLanguageId);
#endif
		// ��������Mutation
		Mutation* mut = FindMutation(mutMessageBoxExW, CTX_STR, &ctxVal);
		if (mut != NULL) {
			if (mut->mutType == MUT_ALT_NUM) {
#ifdef __DEBUG_PRINT
				printf("Applying MUT_ALT_NUM mutation to MessageBoxExW.\n");
#endif
				if (flag) { (*flag) = FALSE; }
				// �j�����ƪ��^�ǭ�
				return (int)mut->mutValue.nValue;
			}
		}

		// �����l���
		ret = OgMessageBoxExW(hWnd, lpText, lpCaption, uType, wLanguageId);
		if (flag) (*flag) = FALSE;
		return ret;
	}

	// �p�G���ݭnhook�h�����l���
	ret = OgMessageBoxExW(hWnd, lpText, lpCaption, uType, wLanguageId);
	if (flag) (*flag) = FALSE;
	return ret;
}

int WINAPI HookMessageBoxExA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId)
{
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;

	// �ˬd�O�_�ݭn�O�����ե�
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();

		// �O���եθ�T
		ContextValue ctxVal;

		// ���N ANSI �r���ഫ���e�r�šA�H�K�Τ@�B�z
		// �O����ܮؼ��D
		size_t capLen = strlen(lpCaption);
		if (capLen >= MAX_CTX_LEN - 1) {
			capLen = MAX_CTX_LEN - 10;  // �O�d�@�ǪŶ����奻���e
		}

		// �ഫ���D�q ANSI ��e�r��
		size_t convertedChars = 0;
		mbstowcs_s(&convertedChars, ctxVal.szCtx, MAX_CTX_LEN, lpCaption, capLen);
		ctxVal.szCtx[capLen] = L':';

		// �l�[��ܮؤ奻���e�X�Ӧr��
		size_t textLen = strlen(lpText);
		size_t remainLen = MAX_CTX_LEN - capLen - 2;  // �������D+�_��������
		if (textLen > remainLen) {
			textLen = remainLen;
		}

		// �ഫ�奻�q ANSI ��e�r�šA�ñ��b�_���᭱
		mbstowcs_s(&convertedChars, ctxVal.szCtx + capLen + 1,
			MAX_CTX_LEN - capLen - 1, lpText, textLen);

		// �T�O�r�Ŧ꥿�T�פ�
		ctxVal.szCtx[MAX_CTX_LEN - 1] = L'\0';

		// �O���ե�
		RecordCall(Call::cMessageBoxExA, CTX_STR, &ctxVal, Hash);

#ifdef __DEBUG_PRINT
		printf("MessageBoxExA detected: %s - %s (language: %d)\n", lpCaption, lpText, wLanguageId);
#endif
		// ��������Mutation
		Mutation* mut = FindMutation(mutMessageBoxExA, CTX_STR, &ctxVal);
		if (mut != NULL) {
			if (mut->mutType == MUT_ALT_NUM) {
#ifdef __DEBUG_PRINT
				printf("Applying MUT_ALT_NUM mutation to MessageBoxExA.\n");
#endif
				if (flag) { (*flag) = FALSE; }
				// �j�����ƪ��^�ǭ�
				return (int)mut->mutValue.nValue;
			}
		}

		// �����l���
		ret = OgMessageBoxExA(hWnd, lpText, lpCaption, uType, wLanguageId);
		if (flag) (*flag) = FALSE;
		return ret;
	}

	// �p�G���ݭnhook�h�����l���
	ret = OgMessageBoxExA(hWnd, lpText, lpCaption, uType, wLanguageId);
	if (flag) (*flag) = FALSE;
	return ret;
}