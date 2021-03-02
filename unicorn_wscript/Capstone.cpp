#include "Capstone.h"
#include <Windows.h>

#include <iostream>
using std::cout; 
using std::endl;

Capstone::Capstone()
{

}

Capstone::~Capstone()
{

}

void Capstone::InitCapstone(
)
{
	OptMem.free = free;
	OptMem.calloc = calloc;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);
#ifdef _WIN64
	cs_open(CS_ARCH_X86, CS_MODE_64, &Handle);
#else
	cs_open(CS_ARCH_X86, CS_MODE_32, &Handle);
#endif
}

void Capstone::ShowAssembly(
	const __int64 mapexecripaddr,
	const void* pAddr, 
	int nLen
)
{
	BYTE* pOpCode = (BYTE *)malloc(nLen * 16);
	memset(pOpCode, 0, (sizeof(BYTE) * 16 * nLen) );
	SIZE_T read = 0;			

	cs_insn* ins = nullptr;

	RtlMoveMemory(pOpCode, pAddr, nLen * 16);
	// SIZE_T dwCount = 0;
	// ReadProcessMemory(NULL, pAddr, pOpCode, nLen * 16, &dwCount);

	int count = cs_disasm(Handle, (uint8_t*)pOpCode, nLen * 16, (uint64_t)pAddr, 0, &ins);

	for (int i = 0; i < nLen; ++i)
	{
		// printf("%08X\t", ins[i].address);
		printf("0x%I64X\t", mapexecripaddr);
		for (uint16_t j = 0; j < 16; ++j)
		{
			if (j < ins[i].size)
				printf("%02X", ins[i].bytes[j]);
			else
				printf(" ");
		}
		printf("\t");
		printf("%s  ", ins[i].mnemonic);
		cout << ins[i].op_str << endl;  
	}
	printf("\n");
	delete[] pOpCode;
	cs_free(ins, count);
}

void Capstone::Close(
)
{
	if (Handle)
		cs_close(&Handle);
}