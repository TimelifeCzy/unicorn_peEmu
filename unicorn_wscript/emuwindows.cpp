#include "../unicorn/include/unicorn/unicorn.h"

#include "emuwindows.h"

#include <winternl.h>
#include "nativestructs.h"


EmuOsWindows::EmuOsWindows()
{

}

EmuOsWindows::~EmuOsWindows()
{

}

void EmuOsWindows::EmuGetSystemTimeAsFileTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	FILETIME ft;
	RtlSecureZeroMemory(&ft, sizeof(FILETIME));

	GetSystemTimeAsFileTime(&ft);

	err = uc_mem_write(uc, rcx, &ft, sizeof(FILETIME));
}

void EmuOsWindows::EmuGetCurrentThreadId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	DWORD ThreadId = 8888;
	uc_reg_write(uc, UC_X86_REG_EAX, &ThreadId);
}

void EmuOsWindows::EmuGetCurrentProcessId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	DWORD ProcessId = 6666;
	uc_reg_write(uc, UC_X86_REG_EAX, &ProcessId);
}

void EmuOsWindows::EmuQueryPerformanceCounter(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	LARGE_INTEGER arge_inf;
	RtlSecureZeroMemory(&arge_inf, sizeof(LARGE_INTEGER));
	BOOL status = QueryPerformanceCounter(&arge_inf);

	// write rcx
	uc_mem_write(uc, rcx, &arge_inf, sizeof(LARGE_INTEGER));

	// ret
	uc_reg_write(uc, UC_X86_REG_EAX, &status);
}

void EmuOsWindows::EmuLoadLibraryExW(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	/*
	    _In_ LPCWSTR lpLibFileName,
		_Reserved_ HANDLE hFile,
		_In_ DWORD dwFlags

		//  return ModBaseaddr(Map)
	*/

}

void EmuOsWindows::EmuLoadLibraryA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{

}

void EmuOsWindows::EmuGetProcAddress(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	/*
	    _In_ HMODULE hModule,
		_In_ LPCSTR lpProcName
		
		// return funadr(Map)
	*/


}

void EmuOsWindows::EmuGetModuleHandleA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{

}

void EmuOsWindows::EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	// Error
	// but callback . Emu 
	// DWORD dwError = GetLastError();
	DWORD error = 0;
	uc_reg_write(uc, UC_X86_REG_RAX, &error);
}

void EmuOsWindows::EmuInitializeCriticalSectionAndSpinCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	RTL_CRITICAL_SECTION_64 CrtSection;
	CrtSection.DebugInfo = 0;
	CrtSection.LockCount = 0;
	CrtSection.LockSemaphore = 0;
	CrtSection.OwningThread = 0;
	CrtSection.RecursionCount = 0;
	CrtSection.SpinCount = edx;

	uc_mem_write(uc, rcx, &CrtSection, sizeof(RTL_CRITICAL_SECTION_64));

	uint32_t r = 1;

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);

}

void EmuOsWindows::EmuInitializeCriticalSectionEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	uint32_t r8d;
	err = uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	RTL_CRITICAL_SECTION_64 CrtSection;
	CrtSection.DebugInfo = 0;
	CrtSection.LockCount = 0;
	CrtSection.LockSemaphore = 0;
	CrtSection.OwningThread = 0;
	CrtSection.RecursionCount = 0;
	CrtSection.SpinCount = edx;

	uc_mem_write(uc, rcx, &CrtSection, sizeof(RTL_CRITICAL_SECTION_64));

	uint32_t r = 1;

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuOsWindows::EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuOsWindows::EmuTlsSetValue(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	uint64_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0)
	{
		uint64_t rdx;
		err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

		r = 1;

		//ctx->m_TlsValue = rdx;
	}

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuOsWindows::EmuTlsFree(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	uint64_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0)
	{
		r = 1;
	}

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuOsWindows::EmuDeleteCriticalSection(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	RTL_CRITICAL_SECTION_64 CrtSection;
	CrtSection.DebugInfo = 0;
	CrtSection.LockCount = 0;
	CrtSection.LockSemaphore = 0;
	CrtSection.OwningThread = 0;
	CrtSection.RecursionCount = 0;
	CrtSection.SpinCount = 0;

	uc_mem_write(uc, rcx, &CrtSection, sizeof(RTL_CRITICAL_SECTION_64));
}

void EmuOsWindows::EmuLocalAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
}

void EmuOsWindows::EmuRtlIsProcessorFeaturePresent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint8_t al = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0x1C)
	{
		al = 0;
	}
	else
	{
		al = IsProcessorFeaturePresent(ecx);
	}
	err = uc_reg_write(uc, UC_X86_REG_AL, &al);
}

void EmuOsWindows::EmuNtProtectVirtualMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint8_t al = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0x1C)
	{
		al = 0;
	}
	else
	{
		al = IsProcessorFeaturePresent(ecx);
	}
	err = uc_reg_write(uc, UC_X86_REG_AL, &al);
}

void EmuOsWindows::EmuGetProcessAffinityMask(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t eax = 0;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint64_t r8;
	err = uc_reg_read(uc, UC_X86_REG_R8, &r8);

	if (rcx == (uint64_t)-1)
	{
		eax = 1;

		DWORD_PTR ProcessAffinityMask = 0;
		DWORD_PTR SystemAffinityMask = 0;

		uc_mem_write(uc, rdx, &ProcessAffinityMask, sizeof(ProcessAffinityMask));
		uc_mem_write(uc, r8, &SystemAffinityMask, sizeof(SystemAffinityMask));
	}

	err = uc_reg_write(uc, UC_X86_REG_EAX, &eax);
}