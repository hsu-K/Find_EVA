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

	//std::unique_ptr<test> testObj;	// ���ժ���

	Execution* firstExec; 	// ���V�Ĥ@�����檺����
	Execution* currExec;		// ���V��e���檺����
	Mutation* mutHead;		// �ܲ��C���Y��
	Mutation* mutCurr;		// ��e�ܲ�
	DWORD dwMutationCount;		// �ܲ��p��


	// list of mutations to avoid due to backtracking
	Mutation* skip;			// �n���L���ܲ�

	// callcount sum (avoid recalc)
	LONG act;						// ���ʭp��
};

