// Launcher.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>

#include "GlobalState.hpp"
#include "ThreadManager.hpp"
#include "CoreUtil.hpp"





int main(int argc, char* argv[])
{
	char* path = NULL;
	std::string strPath = "C:\\Program_Code\\Find_Anti\\Final_Mut\\Debug\\test.exe";
	if (argc < 2) {
		//fprintf(stderr, "Usage: EnviralLauncher.exe <target application>\n");
		//return -1;
		path = &strPath[0];
	}
	else {
		path = argv[1];
	}
	printf("[Enviral Launcher] Init: %s\n", path);
	
	GlobalState::GetInst()->set_frameCurr(std::make_shared<Frame>());

	// 設置當前最佳Frame為frameCurr
	GlobalState::GetInst()->set_frameBest(GlobalState::GetInst()->get_frameCurr());

	// 首次執行，初始化baseExec並設置為當前Frame的currExec
	std::shared_ptr<Execution> baseExec = std::make_shared<Execution>(nullptr, nullptr, false);
	GlobalState::GetInst()->get_frameCurr()->currExec = baseExec.get();

	GlobalState::GetInst()->set_SyncEvent(std::make_shared<HANDLE>(CreateEventW(NULL, FALSE, FALSE, L"StopThreads")));


	ThreadManager threadManager;
	threadManager.startListenerThread();

	//LONG LcalRecIndex = InterlockedIncrement(&(GlobalState::GetInst()->get_frameCurr()->currExec->RecIndex));
	//std::cout << LcalRecIndex << std::endl;
	//std::cout << baseExec->RecIndex << std::endl;

	CoreUtil::LaunchTarget(path);

	system("pause");
	threadManager.stopListenerThread();
}
