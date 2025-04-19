#include "GlobalState.hpp"

std::shared_ptr<GlobalState> GlobalState::_instance = nullptr;

void GlobalState::addThread(std::shared_ptr<std::thread> thread)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	threadPool.push_back(thread);
}

bool GlobalState::removeThread(size_t index)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	if (index < threadPool.size()) {
		if (threadPool[index]->joinable()) {
			threadPool[index]->join();
		}
		threadPool.erase(threadPool.begin() + index);
		return true;
	}
	return false;
}

size_t GlobalState::getThreadPoolSize()
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	return threadPool.size();
}
