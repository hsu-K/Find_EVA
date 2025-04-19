#pragma once
#include <iostream>
#include <windows.h>

class Launcher_MiscUtil
{
public:
    static double CalculateCPUUsage(HANDLE hProcess, FILETIME& prevSysTime, FILETIME& prevProcKernelTime, FILETIME& prevProcUserTime) {
        FILETIME sysIdleTime, sysKernelTime, sysUserTime;
        FILETIME procCreationTime, procExitTime, procKernelTime, procUserTime;

        // 獲取系統時間
        if (!GetSystemTimes(&sysIdleTime, &sysKernelTime, &sysUserTime)) {
            return -1.0; // 無法獲取系統時間
        }

        // 獲取進程時間
        if (!GetProcessTimes(hProcess, &procCreationTime, &procExitTime, &procKernelTime, &procUserTime)) {
            return -1.0; // 無法獲取進程時間
        }

        // 計算系統時間的增量
        ULONGLONG sysKernelDiff = (*(ULONGLONG*)&sysKernelTime - *(ULONGLONG*)&prevSysTime);
        ULONGLONG sysUserDiff = (*(ULONGLONG*)&sysUserTime - *(ULONGLONG*)&prevSysTime);

        // 計算進程時間的增量
        ULONGLONG procKernelDiff = (*(ULONGLONG*)&procKernelTime - *(ULONGLONG*)&prevProcKernelTime);
        ULONGLONG procUserDiff = (*(ULONGLONG*)&procUserTime - *(ULONGLONG*)&prevProcUserTime);

        // 更新前一次的時間
        prevSysTime = sysKernelTime;
        prevProcKernelTime = procKernelTime;
        prevProcUserTime = procUserTime;

        // 計算 CPU 使用率
        ULONGLONG totalSysTime = sysKernelDiff + sysUserDiff;
        ULONGLONG totalProcTime = procKernelDiff + procUserDiff;

        if (totalSysTime == 0) {
            return 0.0; // 避免除以零
        }

        return (double)(totalProcTime * 100) / totalSysTime;
    }
};

