// Launcher.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>

#include "GlobalState.hpp"
#include "ThreadManager.hpp"
#include "CoreUtil.hpp"
#include "CalculateUtil.hpp"
#include "LogUtil.hpp"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Winmm.lib")


#define __EXPERIMENT


int main(int argc, char* argv[])
{
	char* path = NULL;
	//std::string strPath = "C:\\Program_Code\\Find_Anti\\WTF\\Debug\\test.exe";
	//std::string strPath = "C:\\Program_Code\\Find_Anti\\Final_Mut\\Debug\\megbox_test.exe";
	std::string strPath = "C:\\Program_Code\\Find_Anti\\Launcher\\Debug\\OpKey_check.exe";
	if (argc < 2) {
		//fprintf(stderr, "Usage: EnviralLauncher.exe <target application>\n");
		//return -1;
		path = &strPath[0];
	}
	else {
		path = argv[1];
	}
	printf("[Enviral Launcher] Init: %s\n", path);
	
	// create new Frame, and it is the frameCurr
	GlobalState::GetInst()->set_frameCurr(std::make_shared<Frame>());

	// set the frameBest now is the frameCurr
	GlobalState::GetInst()->set_frameBest(GlobalState::GetInst()->get_frameCurr());

	// 首次執行，初始化baseExec並設置為當前Frame的currExec
	std::shared_ptr<Execution> baseExec = std::make_shared<Execution>(nullptr, nullptr, false);
	GlobalState::GetInst()->get_frameCurr()->currExec = baseExec.get();

	GlobalState::GetInst()->set_SyncEvent(std::make_shared<HANDLE>(CreateEventW(NULL, FALSE, FALSE, L"StopThreads")));

	ThreadManager threadManager;
	threadManager.startListenerThread();

	printf("[Enviral Launcher] Run: base1\n");
	CoreUtil::LaunchTarget(path);
	CalculateUtil::GenerateUniqueCallcounts(GlobalState::GetInst()->get_frameCurr()->currExec);

# ifdef __DEBUG
	LogUtil::PrintCallCounts(GlobalState::GetInst()->get_frameCurr()->currExec);
#endif

	// run Execution base2
	std::shared_ptr<Execution> base2 = std::make_shared<Execution>(nullptr, nullptr, false);
	if (base2 == nullptr) { return -1; }
	GlobalState::GetInst()->get_frameCurr()->currExec = base2.get();
	printf("[Enviral Launcher] Run: base2\n");
	CoreUtil::LaunchTarget(path);
	CalculateUtil::GenerateUniqueCallcounts(GlobalState::GetInst()->get_frameCurr()->currExec);

	// run Execution base3
	std::shared_ptr<Execution> base3 = std::make_shared<Execution>(nullptr, nullptr, false);
	if (base3 == nullptr) { return -1; }
	GlobalState::GetInst()->get_frameCurr()->currExec = base3.get();
	printf("[Enviral Launcher] Run: base3\n");
	CoreUtil::LaunchTarget(path);
	CalculateUtil::GenerateUniqueCallcounts(GlobalState::GetInst()->get_frameCurr()->currExec);

	// choose the best baseExec as the frameCurr
	CalculateUtil::chooseBestCallCounts(GlobalState::GetInst()->get_frameCurr(), base2.get(), base3.get(), base3.get());
	Execution* base = GlobalState::GetInst()->get_frameCurr()->currExec;

#ifdef __EXPERIMENT
	printf("----------------------__EXPERIMENT------------------------\n");
#endif

	ULONG cycles = 0;
	ULONG volapplied = 0;

	int exit = CoreUtil::RunExploration(path, GlobalState::GetInst()->get_frameCurr()->currExec, &cycles, &volapplied);

	LogUtil::OutputExperiment(base, GlobalState::GetInst()->get_frameBest()->currExec, path, cycles, exit, volapplied);

	threadManager.stopListenerThread();
	return 0;
}
