#pragma once
#include "Recording.hpp"
#include "Mutation.hpp"
#include "communication.h"


class RecordList {
public:
	RecordList() : rec(), next(nullptr) {}
	Recording rec;
	RecordList* next;
};

// per-instance recording (1 per connecting process)
// 管理每個處理程序的本地記錄
class LocalRecording {
public:
	// NOTE: this list grows backwards, the last call is the head.(記錄列表是反向增長的(最後的呼叫在頭部))
	RecordList* recHead = nullptr;		// 記錄列表的頭部
	RecordList* recCurr = nullptr;		// 當前記錄
};

// 追蹤 API 呼叫的來源
class Origins {
public:
	UINT64 origin;
	Origins* next;
};


#define __DEBUG
class Execution
{
public:
	Execution(Execution* prev, Execution* next, BOOL skip) {
		this->RecIndex = (LONG)-1;	// 設定索引紀錄為-1

		// 清空呼叫計數和來源陣列
		memset((void*)this->CallCounts, 0, sizeof(this->CallCounts));
		memset((void*)this->CallOrigins, 0, sizeof(this->CallOrigins));

		for (int i = 0; i < MAX_CHILD; i++) {
			this->recordings[i].recHead = nullptr;	// 設定記錄列表的頭部為空
			this->recordings[i].recCurr = nullptr;	// 設定當前記錄為空
		}

		this->mutStore = nullptr;
		this->prev = prev;	// 設定前一個執行的指標
		if (prev != nullptr && !skip) {
			prev->next = this;
		}
		this->next = next;	// 設定下一個執行的指標

	}


	~Execution() {
#ifdef __DEBUG
		std::cout << "Execution is destructed" << std::endl;
#endif
	}

	LocalRecording recordings[MAX_CHILD];	// 本地函數呼叫記錄陣列

	// volatile 告訴編譯器這個變數的值可能會在程式碼外被改變，可能是用於多執行緒環境或是需要與硬體互動的場景
	volatile LONG RecIndex;			// 記錄索引		

	// stack trace origin + unique counts
	// CALL_END的大小等於所有可能的 API 呼叫類型數量
	LONG CallCounts[CALL_END] = { 0 };		// API 呼叫計數
	Origins* CallOrigins[CALL_END];	// API 呼叫來源

	// pointer to last previous mutation
	Mutation* mutStore;			// 最後一次變異的指標

	// doubly linked list
	Execution* prev;
	Execution* next;
};

