#pragma once
#include <iostream>
#include <windows.h>

class Launcher_MiscUtil
{
public:
    static double CalculateCPUUsage(HANDLE hProcess, FILETIME& prevSysTime, FILETIME& prevProcKernelTime, FILETIME& prevProcUserTime) {
        FILETIME sysIdleTime, sysKernelTime, sysUserTime;
        FILETIME procCreationTime, procExitTime, procKernelTime, procUserTime;

        // ����t�ήɶ�
        if (!GetSystemTimes(&sysIdleTime, &sysKernelTime, &sysUserTime)) {
            return -1.0; // �L�k����t�ήɶ�
        }

        // ����i�{�ɶ�
        if (!GetProcessTimes(hProcess, &procCreationTime, &procExitTime, &procKernelTime, &procUserTime)) {
            return -1.0; // �L�k����i�{�ɶ�
        }

        // �p��t�ήɶ����W�q
        ULONGLONG sysKernelDiff = (*(ULONGLONG*)&sysKernelTime - *(ULONGLONG*)&prevSysTime);
        ULONGLONG sysUserDiff = (*(ULONGLONG*)&sysUserTime - *(ULONGLONG*)&prevSysTime);

        // �p��i�{�ɶ����W�q
        ULONGLONG procKernelDiff = (*(ULONGLONG*)&procKernelTime - *(ULONGLONG*)&prevProcKernelTime);
        ULONGLONG procUserDiff = (*(ULONGLONG*)&procUserTime - *(ULONGLONG*)&prevProcUserTime);

        // ��s�e�@�����ɶ�
        prevSysTime = sysKernelTime;
        prevProcKernelTime = procKernelTime;
        prevProcUserTime = procUserTime;

        // �p�� CPU �ϥβv
        ULONGLONG totalSysTime = sysKernelDiff + sysUserDiff;
        ULONGLONG totalProcTime = procKernelDiff + procUserDiff;

        if (totalSysTime == 0) {
            return 0.0; // �קK���H�s
        }

        return (double)(totalProcTime * 100) / totalSysTime;
    }
};

