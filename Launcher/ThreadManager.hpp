#pragma once
#include <iostream>
#include <thread>
#include <windows.h>
#include "GlobalState.hpp"
class ThreadManager
{
public:
	void startListenerThread();

	void stopListenerThread();
private:
	DWORD WINAPI ListenerThreadEntry();

	DWORD WINAPI ResponderThreadEntry(HANDLE pipe);

	bool stopListener = false;
	std::shared_ptr<std::thread> _listenerThread;

	std::atomic<bool> shouldTerminate{ false };
};

