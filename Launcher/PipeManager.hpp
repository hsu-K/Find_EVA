#pragma once
#include <windows.h>
#include <stdio.h>
#include "Mutation.hpp"
#include "GlobalState.hpp"
class PipeManager
{
public:
	static int TransferMutations(HANDLE pipe)
	{
		DWORD dwWritten;
		BOOL ret;

		// 將突變計數傳送到pipe
		ret = WriteFile(pipe, &GlobalState::GetInst()->get_frameCurr()->dwMutationCount, sizeof(GlobalState::GetInst()->get_frameCurr()->dwMutationCount), &dwWritten, NULL);
		if (!ret) {
			printf("Transfer Handshake Failed\n");
			return -1;
		}

		// 遍歷frameCurr的所有突變，並將其傳送到pipe
		Mutation* loop = GlobalState::GetInst()->get_frameCurr()->mutHead;
		while (loop != nullptr) {
			ret = WriteFile(pipe, loop, sizeof(Mutation), &dwWritten, NULL);
			if (!ret) {
				printf("Transfer Mutation Failed\n");
				return -1;
			}
			loop = loop->next;
		}

		return 1;
	}

	static int AddRecordToList(Execution* exec, Recording* rec, LONG index) {
		// if initail recHead is nullptr
		// recHead always be the newest RecordList
		RecordList* newRec = new RecordList();
		if (newRec == nullptr) {
			printf("Failed to allocate memory for RecordList\n");
			return -1;
		}
		newRec->next = exec->recordings[index].recHead;
		exec->recordings[index].recHead = newRec;
		exec->recordings[index].recHead->rec = *rec;

		//std::cout << exec->recordings[index].recHead->next << std::endl;
		return 1;
	}
};

