#pragma once  
#include "Execution.hpp"
#include "communication.h"
#include <shlwapi.h>
#include <iostream>

#define MAX_PATH 260
#define LOG_PAHT "output/LOG_"

namespace LogUtil  
{  
BOOL IsPrintable(wchar_t* str) {
	size_t len = wcslen(str);
	for (size_t i = 0; i < len; i++) {
		if (!iswprint(str[i]) || str[i] >= 191) {
			return FALSE;
		}
	}
	return TRUE;
}

void PrintCallCounts(Execution* exec) {  
	ULONG tot = 0;
	printf("---------------------- \"Coverage\" ------------------------\n");
	for (long c = 0; c < CALL_END; c++) {
		if (exec->CallCounts[c] > 0) {
			printf("CallCount %s = %ld\n", DebugCallNames[c], exec->CallCounts[c]);
			tot += exec->CallCounts[c];
		}
	}
	printf("TotalAct: %lu\n", tot);
	std::cout << "----------------------------------------------------------" << std::endl;
} 

// 輸出Mutation到輸出文件
void PrintMutation(Mutation* mut, FILE* fp)
{
	fprintf(fp, "> %s\t", DebugCallNames[mut->rec.call]);
	if (mut->rec.type == CTX_NUM) {
		fprintf(fp, "%lu\n", mut->rec.value.dwCtx);
		switch (mut->mutType) {
		case MUT_FAIL: { fprintf(fp, "\t-> FORCEFAIL\n"); } break;
		case MUT_ALT_NUM: { fprintf(fp, "\t-> %d\n", mut->mutValue.nValue); } break;
		case MUT_RND_NUM: { fprintf(fp, "\t-> RANDOM\n"); } break;
		case MUT_HIDE: { fprintf(fp, "\t-> HIDE\n"); } break;
		}
	}
	else if (mut->rec.type == CTX_STR) {
		fprintf(fp, "%ws\n", mut->rec.value.szCtx);
		switch (mut->mutType) {
		case MUT_FAIL: { fprintf(fp, "\t-> FORCEFAIL\n"); } break;
		case MUT_ALT_STR: { fprintf(fp, "\t-> ALT: %ws\n", mut->mutValue.szValue); } break;
		case MUT_HIDE: { fprintf(fp, "\t-> HIDE\n"); } break;
		case MUT_SUCCEED: { fprintf(fp, "\t-> SUCCEED\n"); } break;
		case MUT_ALT_NUM: { fprintf(fp, "\t-> ALT: %lu\n", mut->mutValue.nValue); } break;
		}
	}
	else {
		fprintf(fp, "{NoCtx}\n");
		switch (mut->mutType) {
		case MUT_FAIL: { fprintf(fp, "\t-> FORCEFAIL\n"); } break;
		case MUT_SUCCEED: { fprintf(fp, "\t-> SUCCEED\n"); } break;
		case MUT_HIDE: { fprintf(fp, "\t-> HIDE\n"); } break;
		case MUT_RND_TUP: { fprintf(fp, "\t-> RANDOM_TUP\n"); } break;
		case MUT_RND_NUM: { fprintf(fp, "\t-> RANDOM_NUM\n"); } break;
		case MUT_ALT_NUM: { fprintf(fp, "\t-> ALT: %lu\n", mut->mutValue.nValue); } break;
		}
	}
	fprintf(fp, "\t-> RetAddr: 0x%llx\n", mut->rec.ret_addr);
}

// 輸出Recording到輸出文件
void PrintRecording(Recording* rec, FILE* fp)
{
	switch (rec->type) {
	case CTX_NONE:
		fprintf(fp, "[R#%llx]\t%s\t{None}\n", rec->origin, DebugCallNames[(UINT)rec->call]);
		break;
	case CTX_STR:
		if (IsPrintable(rec->value.szCtx))
			fprintf(fp, "[R#%llx]\t%s\t%ws\n", rec->origin, DebugCallNames[(UINT)rec->call], rec->value.szCtx);
		else
			fprintf(fp, "[R#%llx]\t%s\t{NP}\n", rec->origin, DebugCallNames[(UINT)rec->call]);
		break;
	case CTX_NUM:
		fprintf(fp, "[R#%llx]\t%s\t%lu\n", rec->origin, DebugCallNames[(UINT)rec->call], rec->value.dwCtx);
		break;
	}
}

void PrintRecordList(Execution* exec, LONG index)
{
	printf("\n**** System Call Recordings ****\n");

	RecordList* loop = exec->recordings[index].recHead;
	while (loop != NULL) {
		switch (loop->rec.type) {
		case CTX_NONE:
			printf("[Recording] CALL %s (%llx) CTX {None}\n", DebugCallNames[(UINT)loop->rec.call], loop->rec.origin);
			break;
		case CTX_STR:
			printf("[Recording] CALL %s (%llx) CTX %ws\n", DebugCallNames[(UINT)loop->rec.call], loop->rec.origin, loop->rec.value.szCtx);
			break;
		case CTX_NUM:
			printf("[Recording] CALL %s (%llx) CTX %lu\n", DebugCallNames[(UINT)loop->rec.call], loop->rec.origin, loop->rec.value.dwCtx);
			break;
		}
		loop = loop->next;
	}
}

int OutputExperiment(Execution* base, Execution* last, char* path, ULONG cycles, int exit, ULONG volapplied){
	char FileName[MAX_PATH];
	strcpy_s(FileName, LOG_PAHT);
	char* target = PathFindFileNameA(path);
	strcat_s(FileName, target);
	strcat_s(FileName, ".txt");
	FILE* fp;
	if (fopen_s(&fp, FileName, "w+") != 0) {
		fprintf(stderr, "Could not create output effects file.\n");
		return -1;
	}
	if (fp == NULL) return -1;
	fprintf(fp, "### Experiment Output ###\n");
	fflush(fp);

	
	fprintf(fp, "MutationCount\t%d\n", GlobalState::GetInst()->get_frameBest()->dwMutationCount);
	fprintf(fp, "VolatileCount\t%lu\n", volapplied);
	fprintf(fp, "CycleCount\t%lu\n", cycles);
	fprintf(fp, "LoopExitCode\t%d\n", exit);
	fflush(fp);

	ULONG BaseRecordingCnt = 0;
	fprintf(fp, "\n--RecordingBaseline(Last-To-First):--:\n");
	for (LONG p = 0; p <= base->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = base->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			BaseRecordingCnt++;
			bentry = bentry->next;
		}
	}
	fprintf(fp, "BaseRecordingCnt\t%lu\n", BaseRecordingCnt);

	ULONG LastRecordingCnt = 0;
	fprintf(fp, "\n--RecordingLast(Last-To-First):--\n");
	for (LONG p = 0; p <= last->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = last->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			LastRecordingCnt++;
			bentry = bentry->next;
		}
	}
	fprintf(fp, "LastRecordingCnt\t%lu\n", LastRecordingCnt);

	fprintf(fp, "\nFinalMutationSet:\n");
	Mutation* mutLoop = GlobalState::GetInst()->get_frameBest()->mutHead;
	while (mutLoop != NULL) {
		PrintMutation(mutLoop, fp);
		mutLoop = mutLoop->next;
	}
	fflush(fp);

	fclose(fp);
	return 1;
}

}