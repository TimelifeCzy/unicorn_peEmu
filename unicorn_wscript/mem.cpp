#include "mem.h"

#include <Windows.h>
#include <list>
std::list<LPVOID> g_MemList;

// allocate mem
void* ExAllocMemory(const int len)
{
	if (len)
	{
		//if (m_pBuffer)
		//	VirtualFree(m_pBuffer, 0, MEM_RELEASE);
		auto m_pBuffer = VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_READWRITE);
		if (m_pBuffer)
			g_MemList.push_back(m_pBuffer);
		else
			return NULL;
		return m_pBuffer;
		// m_cbSize = len;
	}
	return NULL;
}

// allocate heap
void* ExAllocHeap(const int len)
{
	return HeapAlloc(NULL, PAGE_READWRITE, len);
}