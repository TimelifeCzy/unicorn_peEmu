#pragma once


class EmuOsWindows
{
public:
	EmuOsWindows();
	~EmuOsWindows();
public:
	static void EmuGetSystemTimeAsFileTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuGetCurrentThreadId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuGetCurrentProcessId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuQueryPerformanceCounter(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuLoadLibraryExW(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuLoadLibraryA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuGetProcAddress(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuGetModuleHandleA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuInitializeCriticalSectionAndSpinCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuInitializeCriticalSectionEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuTlsSetValue(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuTlsFree(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuDeleteCriticalSection(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuLocalAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuRtlIsProcessorFeaturePresent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuNtProtectVirtualMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
	static void EmuGetProcessAffinityMask(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);


private:

};