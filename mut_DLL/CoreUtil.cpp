#include "pch.h"
#include "CoreUtil.hpp"

// �Ω�P�_�O�_�n���L�Y�Ӭ��ʪ��O���A�D�n�Ω� Hook ����A�ê�^�@�ӥ��L�ȩM�@�� Hash ��
BOOL SkipActivity(UINT64* Hash)
{
	BOOL* flag;
	// �P�_��e�u�{���ެO�_�w�g���Ы�TLS�A�p�G�S���N������^FALSE
	flag = (BOOL*)TlsGetValue(dwTlsIndex);
	if (flag == NULL) {
		// TLS not created yet for this thread
		return FALSE;
	}
	// �p�G��e�w�g�bHook���A��^TRUE�H�K���Ƭ���
	if (*flag == TRUE) {
		// we are already in a hook.
		// no sub-activity will be recorded.
		// no need to calculate hash.
		return TRUE;
	}
	else {
		// ���bHook���A���O�w�g���ЫؤFTLS
		// we are not in a hook
		// but we may originate from a new worker thread
		// stack trace will confirm our origin
		// Quote from Microsoft Documentation: You can capture up to MAXUSHORT frames (65534).

		BOOL allforeign = TRUE;
		PVOID trace[MAX_TRACE_DEPTH];
		(*Hash) = 0; // init
		// �����e��������I�s���|�l��
		WORD cap = RtlCaptureStackBackTrace(1, MAX_TRACE_DEPTH, trace, NULL); // no hash
		for (WORD i = 0; i < cap; i++) {
			// �p��b�ؼе{���d�򤺪��I�s��Hash��
			if (trace[i] >= TargetBase && trace[i] <= TargetEnd) {
				(*Hash) += (UINT32)trace[i];
				allforeign = FALSE;
			}
		}
		return allforeign; // skip unless the backtrace validates domestic
	}
	return FALSE;
}

// ��TLS�����šA�åB�]�m��TRUE�A��ܦbHook��
BOOL* EnterHook()
{
	BOOL* flag;
	// �q�������u�{���ި��oflag�A�P�_�O�_�w�g����TLS���t�Ŷ��A�p�G�S���N���t�Ŷ����L�F�p�G���N�]�mflag��TRUE
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




// ����Call�����A��T�A�èϥ�hash�@��Call�ӷ��A�̫�g�Jpipe�Ǧ^�D�{��
int RecordCall(Call c, ContextType type, ContextValue* value, UINT64 hash) {
	Recording rec;
	rec.call = c;
	rec.type = type;

	if (type != CTX_NONE && value != NULL) {
		rec.value = *value;
	}

	// ����origin��hash�A�Q�ΩI�s���|�ӷ�@�ӷ��P�_
	rec.origin = hash;

	DWORD dwWritten;
	// �g�Jpipe
	WriteFile(hPipe, (void*)&rec, sizeof(rec), &dwWritten, NULL);
	return 1;
}

// find a mutation in the list for a specific call, starting from a specific start point
// �̷�CTX�����e�A��������Mutation
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
	printf("���b�P�_Mutation: %d", start->rec.call);

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
		printf(" / ���Mutation\n");
	}
	else {
		printf(" / �S���Mutation\n");
	}
	printf("---------------------------------------------\n");

	return loop;
}
