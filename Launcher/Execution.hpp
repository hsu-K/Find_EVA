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
// �޲z�C�ӳB�z�{�Ǫ����a�O��
class LocalRecording {
public:
	// NOTE: this list grows backwards, the last call is the head.(�O���C��O�ϦV�W����(�̫᪺�I�s�b�Y��))
	RecordList* recHead = nullptr;		// �O���C���Y��
	RecordList* recCurr = nullptr;		// ��e�O��
};

// �l�� API �I�s���ӷ�
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
		this->RecIndex = (LONG)-1;	// �]�w���ެ�����-1

		// �M�ũI�s�p�ƩM�ӷ��}�C
		memset((void*)this->CallCounts, 0, sizeof(this->CallCounts));
		memset((void*)this->CallOrigins, 0, sizeof(this->CallOrigins));

		for (int i = 0; i < MAX_CHILD; i++) {
			this->recordings[i].recHead = nullptr;	// �]�w�O���C���Y������
			this->recordings[i].recCurr = nullptr;	// �]�w��e�O������
		}

		this->mutStore = nullptr;
		this->prev = prev;	// �]�w�e�@�Ӱ��檺����
		if (prev != nullptr && !skip) {
			prev->next = this;
		}
		this->next = next;	// �]�w�U�@�Ӱ��檺����

	}


	~Execution() {
#ifdef __DEBUG
		std::cout << "Execution is destructed" << std::endl;
#endif
	}

	LocalRecording recordings[MAX_CHILD];	// ���a��ƩI�s�O���}�C

	// volatile �i�D�sĶ���o���ܼƪ��ȥi��|�b�{���X�~�Q���ܡA�i��O�Ω�h��������ҩάO�ݭn�P�w�餬�ʪ�����
	volatile LONG RecIndex;			// �O������		

	// stack trace origin + unique counts
	// CALL_END���j�p����Ҧ��i�઺ API �I�s�����ƶq
	LONG CallCounts[CALL_END] = { 0 };		// API �I�s�p��
	Origins* CallOrigins[CALL_END];	// API �I�s�ӷ�

	// pointer to last previous mutation
	Mutation* mutStore;			// �̫�@���ܲ�������

	// doubly linked list
	Execution* prev;
	Execution* next;
};

