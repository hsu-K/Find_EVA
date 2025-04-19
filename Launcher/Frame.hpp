#pragma once
#include "Execution.hpp"
#include "Mutation.hpp"

class test {
public:
	test() : count(0) {}
	~test() { std::cout << "test is destructed" << std::endl; }
	int count;
};

class Frame
{
public:
	Frame()
		: firstExec(nullptr), currExec(nullptr), mutHead(nullptr), mutCurr(nullptr), dwMutationCount(0), skip(nullptr), act(0) { }

	~Frame() {
#ifdef __DEBUG
		std::cout << "Frame is destructed" << std::endl;
#endif
	}

	//std::unique_ptr<test> testObj;	// 測試物件

	Execution* firstExec; 	// 指向第一次執行的指標
	Execution* currExec;		// 指向當前執行的指標
	Mutation* mutHead;		// 變異列表的頭部
	Mutation* mutCurr;		// 當前變異
	DWORD dwMutationCount;		// 變異計數


	// list of mutations to avoid due to backtracking
	Mutation* skip;			// 要跳過的變異

	// callcount sum (avoid recalc)
	LONG act;						// 活動計數
};

