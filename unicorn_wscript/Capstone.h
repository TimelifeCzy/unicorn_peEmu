#pragma once
#ifndef _CAPSTONE_H_
#define _CAPSTONE_H_
#include "../capstone/include/capstone.h"

#ifdef _WIN64
#pragma comment(lib,"..//capstone//lib//capstone_x64.lib")
#else
#pragma comment(lib,"capstone\\lib\\capstone_x86.lib")
#endif

class Capstone
{
public:
	Capstone();
	virtual ~Capstone();

public:

	void InitCapstone();
	void ShowAssembly(const __int64 mapexecripaddr, const void* pAddr, int nLen);
	void Close();

private:

	csh Handle;
	cs_err err;	
	cs_insn* pInsn; 
	cs_opt_mem OptMem;
};

#endif