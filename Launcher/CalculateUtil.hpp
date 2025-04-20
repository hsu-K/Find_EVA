#pragma once
#include <iostream>
#include <windows.h>
#include "Execution.hpp"
#include <map>
class CalculateUtil
{
public:
	// check if the origin is already in the list
	// if it is new, add it to the CallOrigins[call]
	static BOOL EvaluateOrigin(Execution* exec, int call, UINT64 origin)
	{
		Origins* loop = exec->CallOrigins[call];
		while (loop != nullptr) {
			if (loop->origin == origin) {
				return FALSE;
			}
			loop = loop->next;
		}
		// Origin not found, make it the new head.
		Origins* newOrigin = new Origins();
		if (newOrigin == nullptr) {
			return FALSE;
		}
		newOrigin->origin = origin;
		newOrigin->next = exec->CallOrigins[call];
		exec->CallOrigins[call] = newOrigin;
		return TRUE;
	}

	// Calculate the UniqueCallcounts and increase the CallCounts[call]
	static BOOL GenerateUniqueCallcounts(Execution* exec)
	{
		// at least one client connected
		if (exec->RecIndex >= 0) {
			for (LONG i = 0; i <= exec->RecIndex; i++) {
				RecordList* entry = exec->recordings[i].recHead;
				while (entry != nullptr) {
					// Check the Record is new origin
					if (EvaluateOrigin(exec, entry->rec.call, entry->rec.origin)) {
						// new origin stored. increment unique count 
						exec->CallCounts[entry->rec.call]++;
					}
					entry = entry->next;
				}
			}
			return TRUE;
		}
		return FALSE;
	}

	static void chooseBestCallCounts(std::shared_ptr<Frame> currFrame, Execution* base1, Execution* base2, Execution* base3)
	{
		std::map<int, int> AllCallCounts{ { 0, 0 }, {1, 0}, {2, 0} };
		for (int c = 0; c < CALL_END; c++)
		{
			AllCallCounts[0] += base1->CallCounts[c];
			AllCallCounts[1] += base2->CallCounts[c];
			AllCallCounts[2] += base3->CallCounts[c];
		}
		int maxKey = 0;
		int maxValue = AllCallCounts[0];
		for (const auto& pair : AllCallCounts)
		{
			if (pair.second > maxValue)
			{
				maxValue = pair.second;
				maxKey = pair.first;
			}
		}
		switch (maxKey) {
		case 0:
			currFrame->currExec = base1;
			break;
		case 1:
			currFrame->currExec = base2;
			break;
		case 2:
			currFrame->currExec = base3;
			break;
		}
	}

	// 計算活動增益
	static LONG CalculateActivityGain(Execution* exec) {
		if (exec->prev == nullptr) {
			return -1;
		}

		Execution* prev = exec->prev;

		LONG AccumulatedGain = 0;
		LONG gain = 0;

		// 當前exec和上一個exec的CallCounts相減，得到增益，計算總合
		for (long c = 0; c < CALL_END; c++) {
			gain = exec->CallCounts[c] - prev->CallCounts[c];
#ifdef POSITIVE_GAIN_ONLY		
			if (gain > 0)
#endif		
			{
				AccumulatedGain += gain;
			}
		}

		return AccumulatedGain;
	}
};

