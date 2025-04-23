#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "GlobalState.hpp"
#include "Launcher_MiscUtil.hpp"
#include "LogUtil.hpp"
#include "CalculateUtil.hpp"
#include "MutationController.hpp"
#include "RecordingController.hpp"

#define LAUNCH_TIME_LIMIT 2500 // 2.5 seconds
#define MUTATE_TIME_LIMIT 50000 // 50 seconds
#define GAIN_THRESHOLD 1

class CoreUtil
{
public:
	// �Ω�פ�l�i�{
	static void NukeChildren(DWORD pid)
	{
		DWORD i;

		// �Ыضi�{�ַ�
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return;

		// ��l�ƶi�{�ַӵ��c�A�Ω�i�{�T�|
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, &pe32))
			return;

		do {
			for (i = 0; i < GlobalState::GetInst()->get_pidptr() ; i++) {
				// �p�G���l�i�{��PID�A�h�פ�l�i�{
				if (pe32.th32ProcessID == GlobalState::GetInst()->get_pids()[i]) {
#ifdef __DEBUG_PRINT
					printf("[MATCH]: Child Process Recorded PID: %u\n", pids[i]);
#endif
					// ��OpenProcess��o�l�i�{�������v��
					HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
					if (hProc != NULL) {
						// terminate
#ifdef __DEBUG_PRINT
						BOOL kill = TerminateProcess(hProc, 66);
						printf("Kill %u result: %d\n", pids[i], kill);
#else
						TerminateProcess(hProc, 0);
#endif
					}
#ifdef __DEBUG_PRINT
					else {
						printf("it appears we do not have sufficient access to terminate the process.\n");
					}
#endif
				}
			}

		} while (Process32Next(hProcessSnap, &pe32));
	}

	// �Ұʥؼжi�{�ê`�JDLL
	static int LaunchTarget(char* target, bool* time_out = nullptr)
	{
		// �NSyncEvent�]�w�����]�m�A�H�K���u�{�~��B��
		// threads will loop
		// ����ƥ�y�`
		HANDLE syncEventHandle = *(GlobalState::GetInst()->get_SyncEvent().get());

		// ���m�ƥ�
		if (!ResetEvent(syncEventHandle)) {
			fprintf(stderr, "�L�k���m�ƥ�: %d\n", GetLastError());
			return -1;
		}

		STARTUPINFOA si;		// �i�{�ҰʰT�����c
		PROCESS_INFORMATION pi;	// �i�{�T�����c
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));

		// start process in suspended mode
		// �H�Ȱ��Ҧ��Ұʥؼжi�{
		if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		{
			fprintf(stderr, "Could not create target process\n");
			return -1;
		}

		
		// problem
		// DLL�`�J�A�`�NDLL�����|(�s�bTARGET_DLL)
		// allocate memory for dll name(���t�O���鵹dll���|)
		size_t lendll = sizeof(TARGET_DLL); //strlen(TARGET_DLL);
		LPVOID dllname = VirtualAllocEx(pi.hProcess, NULL, lendll + 1, MEM_COMMIT, PAGE_READWRITE);
		if (dllname == NULL)
		{
			fprintf(stderr, "Could not allocate memory in target for dll name\n");
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		
		// write dll name in target memory(�g�Jdll���|��O����)
		if (!WriteProcessMemory(pi.hProcess, dllname, TARGET_DLL, lendll, NULL))
		{
			fprintf(stderr, "Could not write to target process memory for dll name\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		// ���LoadLibraryA����Ʀa�}�A�qkernel32.dll���o
		// get the kernel32 DLL module
		HMODULE k32 = GetModuleHandleA("kernel32.dll");
		if (k32 == NULL)
		{
			fprintf(stderr, "Could not obtain kernel32.dll handle\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		// obtain pointer to LoadLibraryA()
		LPVOID pLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");
		if (pLoadLibraryA == NULL)
		{
			fprintf(stderr, "Could not get address of LoadLibraryA\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}


		// call LoadLibraryA() in the target process
		// �b�ؼжi�{�Ыؤ@�ӷs���u�{�A�æb�ӽu�{���ե�LoadLibraryA()�ӥ[��dll
		HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllname, NULL, NULL);
		if (hThread == NULL)
		{
			fprintf(stderr, "Could not create thread in target process\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		// wait for the new loader thread to finish
		// ���ݷs���[���u�{����
		DWORD wait = WaitForSingleObject(hThread, INFINITE); // INFINITE?
		if (wait == WAIT_FAILED)
		{
			fprintf(stderr, "Could not wait for loader thread\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}
		

		// resume the original suspended target process (primary thread)
		// ��_�ؼжi�{���D�u�{����
		DWORD resume = ResumeThread(pi.hThread);
		if (resume == (DWORD)-1)
		{
			fprintf(stderr, "Could not resume execution of target process\n");
			return -1;
		}

		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);

		// wait for target process to finish(���ݥؼжi�{����)
		//WaitForSingleObject(pi.hProcess, LAUNCH_TIME_LIMIT);
		//DWORD wait = WaitForSingleObject(pi.hProcess, INFINITE);

		// �ʱ�CPU�ϥβv�ӧP�_�{���O�_�Q�d��
		FILETIME prevSysTime = { 0 }, prevProcKernelTime = { 0 }, prevProcUserTime = { 0 };
		int suspend_time = 0;
		while (WaitForSingleObject(pi.hProcess, 1000) == WAIT_TIMEOUT) { // �C���ˬd�@��
			double cpuUsage = Launcher_MiscUtil::CalculateCPUUsage(pi.hProcess, prevSysTime, prevProcKernelTime, prevProcUserTime);
			if (cpuUsage == 0) {
				printf("[Enviral Launcher] Target is Blocking, CUP Usage is 0\n");
				suspend_time++;
				if (suspend_time * 1000 >= LAUNCH_TIME_LIMIT) {
					printf("[Enviral Launcher] Target Suspen Out Of Time, LAUNCH_TIME_LIMIT: %d\n", LAUNCH_TIME_LIMIT);
					if (time_out) {
						*time_out = true; // ��s time_out ����
					}
					break;
				}
			}
			else if (cpuUsage > 0) {
				suspend_time = 0;
#ifdef __DEBUG_PRINT
				std::cout << "CPU Usage: " << cpuUsage << "%" << std::endl;
#endif
			}
			else {
				std::cerr << "Failed to calculate CPU usage." << std::endl;
			}
		}



		printf("[Enviral Launcher] Tager End...\n");
		// cease responder threads
		// �]�m�u�{�P�B���
		SetEvent(syncEventHandle);

		// ����u�{���j�p
		size_t threadCount = GlobalState::GetInst()->getThreadPoolSize();

		// �������Ҧ��u�{���P�B I/O �ާ@
		for (int i = static_cast<int>(threadCount) - 1; i >= 0; i--) {
			try {
				// �����P�B I/O �ާ@
				if (!GlobalState::GetInst()->cancelThreadIO(i)) {
					std::cerr << "�L�k�����u�{���P�B I/O �ާ@: " << i << std::endl;
				}
			}
			catch (const std::exception& e) {
				std::cerr << "�����P�B I/O �ɵo�Ϳ��~: " << e.what() << std::endl;
			}
		}

		// �����Ҧ��u�{
		for (int i = static_cast<int>(threadCount) - 1; i >= 0; i--) {
			try {
				if (!GlobalState::GetInst()->removeThread(i)) {
					std::cerr << "�L�k�q�u�{�������u�{: " << i << std::endl;
				}
			}
			catch (const std::exception& e) {
				std::cerr << "�����u�{�ɵo�Ϳ��~: " << e.what() << std::endl;
			}
		}

		// �T�{�Ҧ��u�{�w�g�Q����
		if (GlobalState::GetInst()->getThreadPoolSize() > 0) {
			std::cerr << "ĵ�i: ���� " << GlobalState::GetInst()->getThreadPoolSize() << " �ӽu�{���Q����" << std::endl;
		}

		// The SyncEvent will cancel the pipe communication, however the target process may still be running.
		TerminateProcess(pi.hProcess, 0);

		// �����ҥH���l�i�{
		NukeChildren(pi.dwProcessId);

		if (time_out && *time_out != true) {
			*time_out = false; // �p�G���W�ɡA�]�m�� false
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	static int RunExploration(char* path, Execution* baseExec, ULONG* cycle, ULONG* volapplied) {
		BOOL getMut = FALSE;
		LONG recindex = 0;
		RecordList* vol = nullptr;
		LONG gain = 0;
		std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
		// �]�m�ɶ�����
		DWORD CurTime = timeGetTime(); // milliseconds
		DWORD EndTime = CurTime + MUTATE_TIME_LIMIT; // s * 1000 (30)
		int exit = 0;

		
		// to store newExec
		//std::vector<std::shared_ptr<Execution>> executions;
		std::vector<std::shared_ptr<Execution>>& executions = GlobalState::GetInst()->get_executions();
		std::shared_ptr<Execution> newExec = nullptr;
		while (CurTime < EndTime) {
			getMut = FALSE;
			printf("PH3: Cycle %d\n", *cycle);
			//�����C��������A��K�i��^��
			// �p�G��e������O�Ĥ@������A�h�N�Ĥ@������]�m����e����A�åB��l�Ʈ�base->next ���|�Q�]�m
			if (frameCurr->currExec == baseExec) {
				newExec = std::make_shared<Execution>(baseExec, nullptr, TRUE);
				frameCurr->firstExec = newExec.get();
			}
			else {
				newExec = std::make_shared<Execution>(frameCurr->currExec, nullptr, FALSE);
			}
			//GlobalState::GetInst()->push_executions(newExec);
			//std::cout << newExec.get() << std::endl;
			executions.push_back(newExec);
			frameCurr->currExec = newExec.get();
			
			printf("[Enviral Launcher] Launching target.\n");

			// Run next execution
			bool time_out = false;
			LaunchTarget(path, &time_out);

			// Generate the equalized call counts
			CalculateUtil::GenerateUniqueCallcounts(frameCurr->currExec);

			// ��X�Ҧ�Recording 
			LogUtil::PrintRecordList(frameCurr->currExec, 0);


			// �P�_�O�_���W�ɡA�u���ų̰�
			if (time_out) {
				printf("Target process time out, try generate BlockingMutation\n");
				if (MutationController::GenerateBlockingMutation(frameCurr->currExec)) {
					printf("Generate BlockingMutation success!\n");
					// ���\����ܲ�
					getMut = TRUE;
					// ���srecindex
					recindex = 0;
				}
			}

			if (!getMut && vol) {
				if (MutationController::GenerateResponsiveMutationsAll(frameCurr->currExec)) {

					// �p�G�o��Volatile���ܥi�HĲ�o�s��Mutation�A�h��ܬO���Ī��A�ݭn�O�d
					// �åB���L�U�@�Ӵ`�������ܥͦ��A�]���w�g�����F
					getMut = TRUE;
					recindex = 0;
					vol = nullptr;
					(*volapplied)++;
#ifdef __DEBUG_PRINT
					printf("[new!!] Volatile mutation resulted in stable gain. Keep.\n");
#endif
				}
				else {
					// �Y�S�����ͷs��Responsive Muatation�A�h�p��䬡�ʼW�q
					gain = CalculateUtil::CalculateActivityGain(frameCurr->currExec); // IsActivityGainExtended
					// �p�G�j��֭ȴN�O�d�A�_�h���
					if (gain >= GAIN_THRESHOLD) {
						recindex = 0;
						vol = NULL;
						(*volapplied)++;
#ifdef __DEBUG_PRINT
						printf("Gainful volatile mutation. Keep.\n");
#endif
					}
					else {
#ifdef __DEBUG_PRINT
						printf("Gainless volatile mutation. Discard/Reset.\n");
#endif
						// �^����W�@��Exec�A�p�G���{�b�N�OfirstExec�N�^�_baseExec
						if (frameCurr->currExec == frameCurr->firstExec) {
							// the first exec has no prev.
							//GlobalState::GetInst()->pop_executions();
							executions.pop_back();
							frameCurr->currExec = baseExec;
							frameCurr->firstExec = nullptr;
						}
						else {
							// reset currExec back to prev
							//GlobalState::GetInst()->pop_executions();
							executions.pop_back();
							//frameCurr->currExec = GlobalState::GetInst()->get_executions().back().get();
							frameCurr->currExec = executions.back().get();
							frameCurr->currExec->next = nullptr;
						}

						// reset mutation list ���s���ܦC��
						if (frameCurr->currExec->mutStore == nullptr) {
							// no previous mutations, empty mutation list.
							// �S���W�@�Ӭ��ܡA�M�Ŭ��ܦC��
#ifdef __DEBUG_PRINT
							printf("No previous mutations. Destroy mutation list.\n");
#endif
							MutationController::DestroyMutationList();
							frameCurr->mutHead = nullptr;
							frameCurr->mutCurr = nullptr;
							frameCurr->dwMutationCount = 0;
						}
						else {
							// reset the mutations to what is stored in currExec
#ifdef __DEBUG_PRINT
							printf("Reset mutations to past mutStore.\n");
#endif
							// �NFrame�x�s��Mutation�^��W�@��Exec��Mutation�����A
							frameCurr->mutCurr = frameCurr->currExec->mutStore;

							// remove unwanted mutations
							Mutation* del = frameCurr->mutCurr->next;
							Mutation* tmp = nullptr;
							while (del != nullptr) {
								tmp = del->next;
								delete del;
								del = tmp;
								frameCurr->dwMutationCount--;
							}

							// reset the end of the mutations
							frameCurr->mutCurr->next = nullptr;
						}

						// ���ܲ����ī�A�M��U�@�ӥi�Ϊ��ܲ��I(���^�䤧�e�I�s�L����ơA�]���O�ϦV���w)
						BOOL NoCallsLeftToMutate = FALSE;
						RecordList* nextStart = vol->next;
						if (nextStart != nullptr) {
							// �ˬd�O�_���ۦP�I�s�A�קK��ۦP�������I�s�����ܲ�
							while (RecordingController::IsRecordingIdentical(&vol->rec, &nextStart->rec)) {
#ifdef __DEBUG_PRINT
								printf("Finding Next Entry Point: %s is identical (skip!)\n", DebugCallNames[nextStart->rec.call]);
#endif
								// �o�{�o��Recording�O�ۦP���N�A�~�򩹦^��A�����줣�P���άO�䤣��(�J��NULL)
								nextStart = nextStart->next;
								if (nextStart == nullptr) {
#ifdef __DEBUG_PRINT
									printf("The next entry point is NULL so that aint great\n");
#endif
									NoCallsLeftToMutate = TRUE;
									break;
								}
							}
						}
						else {
							// nextStart is NULL, no next call in this process
							NoCallsLeftToMutate = TRUE;
						}


						// if no calls can be found, we increase the RecIndex, as long as it is in bounds for RecIndex.
						// �p�G�S�����i�ܲ����I�s�A�N�h�M��U�@�Ӷi�{(�bRecIndex���d�򤺤��\)
						if (NoCallsLeftToMutate) {
#ifdef __DEBUG_PRINT
							printf("There are no calls left to mutate in the current RecIndex.\n");
#endif
							if (recindex + 1 > frameCurr->currExec->RecIndex) {
								// nothing left to mutate
#ifdef __DEBUG_PRINT
								printf("There are no other process recordings left to mutate. Exit loop.\n");
#endif
								exit = 2;
								// �p�G�䤣��N���}����˴�
								break;
							}
							recindex++;
						}

						// starting point for next search (can be NULL)
						vol = nextStart;

					}
				}
			}

			if (!getMut) {
				if (MutationController::GenerateResponsiveMutationsAll(frameCurr->currExec)) {
#ifdef __DEBUG_PRINT
					printf("There are stable mutations to apply.\n");
#endif
					getMut = TRUE;
					recindex = 0;
				}
				else {
#ifdef __DEBUG_PRINT
					printf("No (new) stable mutations, try volatile.\n");
#endif
					// ���եͦ��s��Volatile���ܡA�p�G���ͦ��N��^
					vol = MutationController::GenerateResponsiveVolatileMutation(frameCurr->currExec, vol, &recindex);
					if (vol == nullptr) {
						// no volatile mutations to create - exit
#ifdef __DEBUG_PRINT
						printf("No volatile mutations to create. Exit loop.\n");
#endif
						exit = 1;
						break;
					}
					else {
#ifdef __DEBUG_PRINT
						printf("�ͦ�Volatile mutation: %s\n", DebugCallNames[vol->rec.call]);
#endif
					}
				}
			}

			(*cycle)++;
			CurTime = timeGetTime();

		}
		return 1;
	}
};

