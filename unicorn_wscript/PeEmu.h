#pragma once

#include <vector>
#include <map>
#include <vector>
#include <string>
#include <xstring>
#include <winternl.h>

using namespace std;

#include "puPEinfoData.h"

typedef struct _ModDLL
{
	string DllName;
	string DllPath;
	uint64_t peImageBase;
	uint64_t ImageSize;
	uint64_t MapImageBase;	// dll map uc mem : mapaddr
	uint64_t MapOep;
	map<uint64_t, string> dll_functionaddr_map;	// dll all iat_iet functionaddr : mapaddr + offset
}ModDLL, *PModDLL;

class PeEmu
{
public:
	PeEmu(wstring name);
	~PeEmu();

	bool puInitEmu() { return this->prInitEmu(); }
	bool puRun() { return this->prRun(); }
	bool puGetInitstatus() { return this->m_initerrorstatus; }

private:
	bool prInitEmu();
	bool prRun();

	bool InitGdtr();
	bool InitTibPeb_PebLdrdata();
	uint64_t InitSysDLL();
	bool MapInsertIat(
		IMAGE_IMPORT_DESCRIPTOR * pImportTabe,
		DWORD64 dwMoudle,
		uint64_t mapBase,
		ModDLL* mod
	);
	bool MapRelocation(
		uint64_t pDos,
		uint64_t mapBase
	);
	bool InitsampleIatRep();
	void InsertTailList(
		IN ULONG64 ListHeadAddress,
		IN ULONG64 EntryAddress);
	BOOL RepairReloCation(
		PIMAGE_DOS_HEADER m_studBase);
	void RepairTheIAT(
		IMAGE_IMPORT_DESCRIPTOR * pImportTabe,
		DWORD64 dwMoudle);

	bool SamplePeMapImage();

public:
	// DLL
	map<string, uint64_t> sys_dll_map;
	map<string, uint64_t> init_dlls_map;
	vector<ModDLL> current_dlls_map;
	uint64_t m_ppeb_ldrdata_addr;
	PEB_LDR_DATA m_ldrdata_struct;
	PPEB_LDR_DATA m_Mem_ldrdat_addr;
	
	// processos 
	uint64_t m_stackBaseaddr;
	uint64_t m_stackSize;
	uint64_t m_heapBaseaddr;
	uint64_t m_heapSize;
	uint64_t m_PebBase;
	uint64_t m_PebEnd;
	uint64_t m_TebBase;
	uint64_t m_TebEnd;

	

	// peinfo
	bool m_x86x64;
	wstring m_wsamplename;
	uint64_t m_fileBaseaddr;
	uint64_t m_oep;
	uint64_t m_ImageBase;
	uint64_t m_ImageEnd;
	uint64_t m_ImageSize;
	uint64_t m_ImportBaseAddr;

	// classobj
	uc_engine *m_uc;
	uc_x86_mmr gdtr;
	_CONTEXT m_InitReg;
	bool m_initerrorstatus;

};