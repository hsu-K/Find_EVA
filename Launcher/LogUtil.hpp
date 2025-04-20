#pragma once  
#include "Execution.hpp"
#include "communication.h"
#include <iostream>

namespace LogUtil  
{  
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
}