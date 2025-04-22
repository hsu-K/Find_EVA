#pragma once
#include <iostream>
#include <vector>
#include <mutex>
#include "Frame.hpp"

class GlobalState
{
private:
	GlobalState() : frameCurr(nullptr), frameBest(nullptr), SyncEvent(nullptr), pidptr(0) {
		
	}
	GlobalState(const GlobalState&) = delete;
	GlobalState& operator = (const GlobalState&) = delete;
public:
	~GlobalState() {
#ifdef __DEBUG_PRINT
		std::cout << "GlobalState is destructed" << std::endl;
#endif

	}

	static std::shared_ptr<GlobalState> GetInst() {
		static std::once_flag _onceFlag;
		std::call_once(_onceFlag, []() {
			_instance = std::shared_ptr<GlobalState>(new GlobalState());
			// make_shared�L�k�X�ݨp���غc�l
			//_instance = std::make_shared<Single2OnceFlag>();
			});
		return _instance;
	}

	std::shared_ptr<Frame> get_frameCurr() { return frameCurr; }
	void set_frameCurr(std::shared_ptr<Frame> frame) { frameCurr = frame; }

	std::shared_ptr<Frame> get_frameBest() { return frameBest; }
	void set_frameBest(std::shared_ptr<Frame> frame) { frameBest = frame; }

	std::shared_ptr<HANDLE> get_SyncEvent() { return SyncEvent; }
	void set_SyncEvent(std::shared_ptr<HANDLE> event) {
		if (SyncEvent == nullptr) {
			SyncEvent = event;
		}
		else {
			std::cout << "SyncEvent is already set!" << std::endl;
		}
	}

	DWORD get_pidptr() { return pidptr; }
	void set_pidptr(DWORD pid) { pidptr = pid; }

	DWORD* get_pids() { return pids; }
	void set_pids(DWORD pid, DWORD ctx) { pids[pid] = ctx; }


	void addThread(std::shared_ptr<std::thread> thread);

	// �ھگ��޲����u�{
	bool removeThread(size_t index);

	// ����u�{���j�p
	size_t getThreadPoolSize();

	// ����u�{����ͥy�`
	HANDLE getThreadNativeHandle(size_t index);

	// �����u�{���P�B I/O �ާ@
	bool cancelThreadIO(size_t index);

private:
	static std::shared_ptr<GlobalState> _instance;
	std::shared_ptr<Frame> frameCurr;
	std::shared_ptr<Frame> frameBest;
	std::shared_ptr<HANDLE> SyncEvent;
	DWORD pidptr = 0;
	DWORD pids[MAX_CHILD] = { 0 };

	std::vector<std::shared_ptr<std::thread>> threadPool;
	std::vector<HANDLE> threadNativeHandles;  // �s�x�u�{����ͥy�`
	// �O�@�u�{����������
	std::mutex threadPoolMutex;
};

