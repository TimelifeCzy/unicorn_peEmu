#include "../unicorn/include/unicorn/unicorn.h"
#include "../unicorn/include/unicorn/x86.h"

#include "mem.h"
#include "PeEmu.h"
#include "nativestructs.h"

#define AlignSize(Size, Align) (Size+Align-1)/Align*Align
#define PAGE_SIZE 0x1000

extern wstring wSampleName;

typedef struct _Moduole_LdrData
{
	_LIST_ENTRY List;
	PLDR_DATA_TABLE_ENTRY_1 ldr_data_tab;
}Moduole_LdrData,*PModuole_LdrData;

PeEmu::PeEmu(
	wstring name
)
{
	m_uc = NULL; m_initerrorstatus = true;
	auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
	if (err)
	{
		printf("failed to uc_open %d\n", err);
		m_initerrorstatus = false;
	}

	// Load Analys samplefile
	PuPEInfo peinfo;
	if (name.size())
		m_wsamplename = name;
	
	// OpenFile
	peinfo.puOpenFileLoad(m_wsamplename.data());

	// x86 or x64
	m_x86x64 = peinfo.puGetx86x64();

	// Init Processos config
	if (m_x86x64)
	{
		// x64
		m_stackBaseaddr = 0x40000;
		m_stackSize = 0x10000;
		m_ImageEnd = m_stackBaseaddr + m_stackSize - 0x1000;
		m_heapBaseaddr = 0x10000000ull;
		m_heapSize = 0x1000000ull;
	}
	else
	{
		// x32
	}

	// init sys_dll_list
	sys_dll_map["ntdll.dll"] = 0;
	sys_dll_map["kernel32.dll"] = 0;
	init_dlls_map["ntdll.dll"] = 0;
	init_dlls_map["kernel32.dll"] = 0;
	init_dlls_map["user32.dll"] = 0;

	m_InitReg = { 0, };
	gdtr = { 0, };
}

PeEmu::~PeEmu(
)
{
	// clear
	if (m_uc)
		uc_close(m_uc);

	// Free MemList
}

// Map Sample
bool PeEmu::SamplePeMapImage()
{
	if (m_wsamplename.size() <= 0)
		return false;
	uint64_t MapBaseaddr = 0;

	HANDLE hfile = CreateFileW(
		m_wsamplename.c_str(), FILE_GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, 0, NULL
	);

	if (!hfile)
		return false;

	DWORD dwDllSize = GetFileSize(hfile, NULL);
	if (0 >= dwDllSize)
		return false;

	MapBaseaddr = (uint64_t)ExAllocMemory(dwDllSize);
	if (!MapBaseaddr)
		return false;
	RtlSecureZeroMemory((PVOID)MapBaseaddr, dwDllSize);
	DWORD rdSize = 0;
	ReadFile(hfile, (LPVOID)MapBaseaddr, dwDllSize, &rdSize, NULL);
	if (rdSize != dwDllSize)
		return false;
	CloseHandle(hfile);

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)MapBaseaddr;
	IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)DosHeader + DosHeader->e_lfanew);
	auto headerssize = pNtHeader->OptionalHeader.SizeOfHeaders;
	auto nNumerOfSections = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
	m_ImageSize = pNtHeader->OptionalHeader.SizeOfImage;
	auto ImageBaseMapaddr = ExAllocMemory(m_ImageSize);
	if (!ImageBaseMapaddr)
		return false;
	RtlSecureZeroMemory(ImageBaseMapaddr, m_ImageSize);
	m_ImageBase = (uint64_t)ImageBaseMapaddr;
	m_ImageEnd = m_ImageBase + m_ImageSize - 0x1000;
	// copy hander
	RtlCopyMemory(ImageBaseMapaddr, (void*)MapBaseaddr, headerssize);

	// copy section
	char* chSrcMem = NULL;
	char* chDestMem = NULL;
	DWORD dwSizeOfRawData = 0;
	for (int i = 0; i < nNumerOfSections; i++)
	{
		if ((0 == pSection->VirtualAddress) ||
			(0 == pSection->SizeOfRawData))
		{
			pSection++;
			continue;
		}

		chSrcMem = (char*)((DWORD64)MapBaseaddr + pSection->PointerToRawData);
		chDestMem = (char*)((DWORD64)ImageBaseMapaddr + pSection->VirtualAddress);
		dwSizeOfRawData = pSection->SizeOfRawData;
		RtlCopyMemory(chDestMem, chSrcMem, dwSizeOfRawData);
		pSection++;
	}
	VirtualFree((LPVOID)MapBaseaddr, m_ImageSize, 0);

	PIMAGE_DOS_HEADER mapDosHeader = (PIMAGE_DOS_HEADER)ImageBaseMapaddr;
	IMAGE_NT_HEADERS* mapNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)mapDosHeader + mapDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR mapImportTabe = (PIMAGE_IMPORT_DESCRIPTOR)(mapNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE*)m_ImageBase);
	PIMAGE_BASE_RELOCATION mapLoc = (PIMAGE_BASE_RELOCATION)(mapNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (BYTE*)m_ImageBase);
	m_ImportBaseAddr = (uint64_t)mapImportTabe;
	// sample map && iat && rep
	this->InitsampleIatRep();

	// modify ImageBase & oep

	// map
	uc_mem_map(m_uc, m_ImageBase, m_ImageSize, UC_PROT_EXEC | UC_PROT_READ | UC_PROT_EXEC);
	uc_mem_write(m_uc, m_ImageBase, (void *)m_ImageBase, m_ImageSize);

	return true;
}

bool PeEmu::prInitEmu(
)
{
	// Init stack & heap
	auto stackbufaddr = ExAllocMemory(m_stackSize);
	if (!stackbufaddr)
		return false;
	memset((LPVOID)stackbufaddr, 0, m_stackSize);
	uc_mem_map(m_uc, m_stackBaseaddr, m_stackSize, UC_PROT_READ | UC_PROT_WRITE);
	uc_mem_write(m_uc, m_stackBaseaddr, stackbufaddr, m_stackSize);

	uc_mem_map(m_uc, m_heapBaseaddr, m_heapSize, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);

	// SetUp gdt
	this->InitGdtr();

	// tib peb peb_ldr_data
	this->InitTibPeb_PebLdrdata();

	// systemdll load
	this->InitSysDLL();

	// Code image map
	this->SamplePeMapImage();

	// Init Reg write uc
	m_InitReg.Rsp = m_ImageEnd;
	m_InitReg.Rbp = m_ImageEnd;
	m_InitReg.Rcx = m_ImageBase;
	m_InitReg.Rdx = DLL_PROCESS_ATTACH;
	m_InitReg.R8 = 0;

	uc_mem_map(m_uc, m_ImageEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);
	uc_mem_write(m_uc, m_InitReg.Rsp, &m_ImageEnd, sizeof(m_ImageEnd));
	uc_reg_write(m_uc, UC_X86_REG_RAX, &m_InitReg.Rax);
	uc_reg_write(m_uc, UC_X86_REG_RBX, &m_InitReg.Rbx);
	uc_reg_write(m_uc, UC_X86_REG_RCX, &m_InitReg.Rcx);
	uc_reg_write(m_uc, UC_X86_REG_RDX, &m_InitReg.Rdx);
	uc_reg_write(m_uc, UC_X86_REG_RSI, &m_InitReg.Rsi);
	uc_reg_write(m_uc, UC_X86_REG_RDI, &m_InitReg.Rdi);
	uc_reg_write(m_uc, UC_X86_REG_R8, &m_InitReg.R8);
	uc_reg_write(m_uc, UC_X86_REG_R9, &m_InitReg.R9);
	uc_reg_write(m_uc, UC_X86_REG_R10, &m_InitReg.R10);
	uc_reg_write(m_uc, UC_X86_REG_R11, &m_InitReg.R11);
	uc_reg_write(m_uc, UC_X86_REG_R12, &m_InitReg.R12);
	uc_reg_write(m_uc, UC_X86_REG_R13, &m_InitReg.R13);
	uc_reg_write(m_uc, UC_X86_REG_R14, &m_InitReg.R14);
	uc_reg_write(m_uc, UC_X86_REG_R15, &m_InitReg.R15);
	uc_reg_write(m_uc, UC_X86_REG_RBP, &m_InitReg.Rbp);
	uc_reg_write(m_uc, UC_X86_REG_RSP, &m_InitReg.Rsp);

	return 0;
}

static void init_descriptor64(
	SegmentDesctiptorX64 *desc, 
	uint64_t base, 
	uint64_t limit,
	bool is_code, 
	bool is_long_mode
)
{
	desc->descriptor.all = 0;  //clear the descriptor
	desc->descriptor.fields.base_low = base;
	desc->descriptor.fields.base_mid = (base >> 16) & 0xff;
	desc->descriptor.fields.base_high = base >> 24;
	desc->base_upper32 = base >> 32;

	if (limit > 0xfffff) {
		limit >>= 12;
		desc->descriptor.fields.gran = 1;
	}

	desc->descriptor.fields.limit_low = limit & 0xffff;
	desc->descriptor.fields.limit_high = limit >> 16;

	desc->descriptor.fields.dpl = 0;
	desc->descriptor.fields.present = 1;
	desc->descriptor.fields.db = 1;   //64 bit
	desc->descriptor.fields.type = is_code ? 0xb : 3;
	desc->descriptor.fields.system = 1;  //code or data
	desc->descriptor.fields.l = is_long_mode ? 1 : 0;
}
bool PeEmu::InitGdtr(
)
{
	uc_x86_mmr gdtr;

	uint64_t kpcr_base = 0xfffff00000000000ull;

	KPCR kpcr;

	memset(&kpcr, 0, sizeof(KPCR));

	gdtr.base = kpcr_base + offsetof(KPCR, gdt);
	gdtr.limit = sizeof(kpcr.gdt) - 1;

	init_descriptor64(&kpcr.gdt[1], 0, 0xffffffffffffffff, true, true);
	init_descriptor64(&kpcr.gdt[2], 0, 0xffffffffffffffff, false, true);

	auto err = uc_mem_map(m_uc, kpcr_base, 0x1000, UC_PROT_READ);
	err = uc_mem_write(m_uc, kpcr_base, &kpcr, sizeof(KPCR));
	err = uc_reg_write(m_uc, UC_X86_REG_GDTR, &gdtr);

	SegmentSelector cs = { 0 };
	cs.fields.index = 1;
	uc_reg_write(m_uc, UC_X86_REG_CS, &cs.all);

	SegmentSelector ds = { 0 };
	ds.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_DS, &ds.all);

	SegmentSelector ss = { 0 };
	ss.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_SS, &ss.all);

	SegmentSelector es = { 0 };
	es.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_ES, &es.all);

	SegmentSelector gs = { 0 };
	gs.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_GS, &gs.all);

	FlagRegister eflags = { 0 };
	eflags.fields.id = 1;
	eflags.fields.intf = 1;
	eflags.fields.reserved1 = 1;

	uc_reg_write(m_uc, UC_X86_REG_EFLAGS, &eflags.all);

	uint64_t cr8 = 0;
	uc_reg_write(m_uc, UC_X86_REG_CR8, &cr8);
	return true;
}

bool PeEmu::InitTibPeb_PebLdrdata(
)
{
	PEB peb = { 0 };

	m_PebBase = 0x90000ull;
	m_PebEnd = m_PebBase + AlignSize(sizeof(PEB), PAGE_SIZE);

	uc_mem_map(m_uc, m_PebBase, m_PebEnd - m_PebBase, UC_PROT_READ);
	uc_mem_write(m_uc, m_PebBase, &peb, sizeof(PEB));

	m_TebBase = 0x80000ull;
	m_TebEnd = m_TebBase + AlignSize(sizeof(TEB), PAGE_SIZE);

	TEB teb = { 0 };

	teb.ProcessEnvironmentBlock = (PPEB)m_PebBase;

	uc_mem_map(m_uc, m_TebBase, m_TebEnd - m_TebBase, UC_PROT_READ);
	uc_mem_write(m_uc, m_TebBase, &teb, sizeof(TEB));

	uc_x86_msr msr;
	msr.rid = (uint32_t)Msr::kIa32GsBase;
	msr.value = m_TebBase;

	uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);

	// PEB.PPEB_LDR_DATA
	m_ppeb_ldrdata_addr = m_PebBase + offsetof(PEB, Ldr);
	// Allocate Mem
	m_Mem_ldrdat_addr = (PPEB_LDR_DATA)ExAllocMemory(sizeof(PEB_LDR_DATA));
	if (!m_Mem_ldrdat_addr)
		return false;
	memset(m_Mem_ldrdat_addr, 0, sizeof(PEB_LDR_DATA));
	// write PEB.PPEB_LDR_DATA allocate mem addr
	uc_mem_write(m_uc, m_ppeb_ldrdata_addr, m_Mem_ldrdat_addr, sizeof(PPEB_LDR_DATA));

	// Create PEB_DATA struct, write PEB_DATA
	m_ldrdata_struct = { 0, };
	// Map  allocate mem addr & write PEB_DATA
	uc_mem_map(m_uc, (uint64_t)m_Mem_ldrdat_addr, sizeof(PEB_LDR_DATA), UC_PROT_READ | UC_PROT_WRITE);
	uc_mem_write(m_uc, (uint64_t)m_Mem_ldrdat_addr, &m_ldrdata_struct, sizeof(PEB_LDR_DATA));

	return true;
}

void PeEmu::InsertTailList(
	IN ULONG64 ListHeadAddress,
	IN ULONG64 EntryAddress
)
{
	PLIST_ENTRY Blink;

	//Blink = ListHead->Blink;
	uc_mem_read(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

	//Entry->Flink = (PLIST_ENTRY)ListHeadAddress;

	uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Flink), &ListHeadAddress, sizeof(ListHeadAddress));

	//Entry->Blink = Blink;

	uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

	//Blink->Flink = (PLIST_ENTRY)EntryAddress;

	uc_mem_write(m_uc, (uint64_t)Blink + offsetof(LIST_ENTRY, Flink), &EntryAddress, sizeof(EntryAddress));

	//ListHead->Blink = (PLIST_ENTRY)EntryAddress;

	uc_mem_write(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &EntryAddress, sizeof(EntryAddress));
}

bool PeEmu::MapInsertIat(
	IMAGE_IMPORT_DESCRIPTOR * pImportTabe,
	DWORD64 dwMoudle,
	uint64_t mapBase,
	ModDLL* mod
)
{
	string funname;
	DWORD64 ImportTabVA = 0, FunAddress = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImport = pImportTabe;
	DWORD Att_old = 0;
	// dll_Name
	while (pImport->Name)
	{
		char* Name = (char*)(pImport->Name + dwMoudle);
		PIMAGE_THUNK_DATA pThunkINT = (PIMAGE_THUNK_DATA)(pImport->OriginalFirstThunk + dwMoudle);
		PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)(pImport->FirstThunk + dwMoudle);
		while (pThunkINT->u1.AddressOfData)
		{
			if (!IMAGE_SNAP_BY_ORDINAL(pThunkIAT->u1.Ordinal))
			{
				// Function_Name
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pThunkINT->u1.AddressOfData + dwMoudle);
				funname = pName->Name;

				// insert mapaddr_offset
				//mod->dll_functionaddr_map[uint64_t(pThunkINT->u1.Function + dwMoudle)] = funname.data();
				mod->dll_functionaddr_map[pThunkINT->u1.Function + mapBase] = funname;

				// MapAddr + offset = iat
				pThunkINT->u1.Function = pThunkINT->u1.Function + mapBase;
			}
			//else
			//{
			//	DWORD64 dwFunOrdinal = IMAGE_ORDINAL((pThunkIAT->u1.Ordinal));
			//	mod->dll_functionaddr_map[pThunkINT->u1.Function + dwMoudle] = dwFunOrdinal;
			//}
			++pThunkINT;
			++pThunkIAT;
		}
		++pImport;
	}
	return 0;
}

bool PeEmu::MapRelocation(
	uint64_t pDos,
	uint64_t mapBase
)
{
	PIMAGE_DOS_HEADER pStuDos = (PIMAGE_DOS_HEADER)pDos;
	PIMAGE_NT_HEADERS pStuNt = (PIMAGE_NT_HEADERS)(pStuDos->e_lfanew + (DWORD64)pDos);
	PIMAGE_BASE_RELOCATION pStuRelocation = (PIMAGE_BASE_RELOCATION)(pStuNt->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD64)pDos);
	typedef struct _Node
	{
		WORD offset : 12;
		WORD type : 4;
	}Node, *PNode;

	LONGLONG dwDelta = (__int64)pDos - mapBase;
	while (pStuRelocation->SizeOfBlock)
	{
		DWORD nStuRelocationBlockCount = (pStuRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		_Node* RelType = (PNode)(pStuRelocation + 1);

		for (DWORD i = 0; i < nStuRelocationBlockCount; ++i)
		{
			if (RelType->type == 10 || RelType[i].type == 3) {
				PULONGLONG pAddress = (PULONGLONG)((DWORD64)pDos + pStuRelocation->VirtualAddress + RelType[i].offset);
				*pAddress += dwDelta;
			}
		}
		pStuRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)pStuRelocation + pStuRelocation->SizeOfBlock);
	}
	return TRUE;
}

uint64_t PeEmu::InitSysDLL(
)
{
	string dllpath;
	ModDLL moddll;
	uint64_t MapBaseaddr;
	uint64_t MudllMapAddr = 0;
	for (map<string, uint64_t>::iterator it = sys_dll_map.begin(); it != sys_dll_map.end(); ++it)
	{
		dllpath = "C:\\Windows\\System32\\";
		dllpath += it->first;

		moddll.DllName = it->first;
		moddll.DllPath = dllpath;

		// Map File

		HANDLE hfile = CreateFileA(
			dllpath.c_str(), FILE_GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, 0, NULL
		);

		if (!hfile)
			return false;

		DWORD dwDllSize = GetFileSize(hfile, NULL);
		if (0 >= dwDllSize)
			return false;

		MapBaseaddr = (uint64_t)ExAllocMemory(dwDllSize);
		if (!MapBaseaddr)
			return false;
		RtlSecureZeroMemory((PVOID)MapBaseaddr, dwDllSize);
		DWORD rdSize = 0;
		ReadFile(hfile, (LPVOID)MapBaseaddr, dwDllSize, &rdSize, NULL);
		if (rdSize != dwDllSize)
			return false;
		CloseHandle(hfile);

		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)MapBaseaddr;
		IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)DosHeader + DosHeader->e_lfanew);
		auto headerssize = pNtHeader->OptionalHeader.SizeOfHeaders;
		auto nNumerOfSections = pNtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

		moddll.peImageBase = pNtHeader->OptionalHeader.ImageBase;
		moddll.ImageSize = pNtHeader->OptionalHeader.SizeOfImage;

		auto ImageBaseMapaddr = ExAllocMemory(moddll.ImageSize);
		if (!ImageBaseMapaddr)
			return false;
		RtlSecureZeroMemory(ImageBaseMapaddr, moddll.ImageSize);		
		// copy hander
		RtlCopyMemory(ImageBaseMapaddr, (void*)MapBaseaddr, headerssize);

		// copy section
		char* chSrcMem = NULL;
		char* chDestMem = NULL;
		DWORD dwSizeOfRawData = 0;
		for (int i = 0; i < nNumerOfSections; i++)
		{
			if ((0 == pSection->VirtualAddress) ||
				(0 == pSection->SizeOfRawData))
			{
				pSection++;
				continue;
			}

			chSrcMem = (char*)((DWORD64)MapBaseaddr + pSection->PointerToRawData);
			chDestMem = (char*)((DWORD64)ImageBaseMapaddr + pSection->VirtualAddress);
			dwSizeOfRawData = pSection->SizeOfRawData;
			RtlCopyMemory(chDestMem, chSrcMem, dwSizeOfRawData);
			pSection++;
		}

		PIMAGE_DOS_HEADER mapDosHeader = (PIMAGE_DOS_HEADER)ImageBaseMapaddr;
		IMAGE_NT_HEADERS* mapNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)mapDosHeader + mapDosHeader->e_lfanew);			
		PIMAGE_IMPORT_DESCRIPTOR mapImportTabe = (PIMAGE_IMPORT_DESCRIPTOR)(mapNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE*)ImageBaseMapaddr);
		PIMAGE_BASE_RELOCATION mapLoc = (PIMAGE_BASE_RELOCATION)(mapNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (BYTE*)ImageBaseMapaddr);

		// ImageBaseMapaddr是申请的内存/扩展PE到内存
		// MudllMapAddr映射到uc_map的地址，也是将ImageBaseMapaddr拷贝到容器的Base
		// 修复iat & 重定位 是映射MudllMapAddr
		// 第一个dll加载使用pe.ImageBase，也是uc_mem_map映射地址。后续DLL加载以MudllMapAddr为准，不在以DLL.ImageBase为基础。
		if (MudllMapAddr == 0)
			MudllMapAddr = moddll.peImageBase;

		// save map_dll_baseaddr + iat.offset
		MapRelocation((uint64_t)ImageBaseMapaddr, MudllMapAddr);
		// if import full
		if (mapNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
			MapInsertIat(mapImportTabe, (uint64_t)ImageBaseMapaddr, MudllMapAddr, &moddll);

		// modify Imagebase , oep
		mapNtHeader->OptionalHeader.ImageBase = MudllMapAddr;
		moddll.MapOep = mapNtHeader->OptionalHeader.ImageBase + mapNtHeader->OptionalHeader.AddressOfEntryPoint;

		// 保存之前要将MapBaseaddr赋值为map.DLL容器的映射baseaddr
		// 样本修复iat时候获取moddll.MapBaseaddr + offset来填充
		moddll.MapImageBase = MudllMapAddr;
		// insert current_processos_moddll_list
		current_dlls_map.push_back(moddll);

		uc_mem_map(m_uc, MudllMapAddr, moddll.ImageSize, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
		uc_mem_write(m_uc, MudllMapAddr, (void *)ImageBaseMapaddr, moddll.ImageSize);

		// DLL-4kb对齐
		MudllMapAddr += moddll.ImageSize;
		if (MudllMapAddr % 0x1000 == 0)
			MudllMapAddr =  ((MudllMapAddr / 0x1000) * 0x1000);
		else
			MudllMapAddr = (((MudllMapAddr / 0x1000) + 1) * 0x1000);

		VirtualFree((LPVOID)MapBaseaddr, dwDllSize, 0);
		VirtualFree(ImageBaseMapaddr, moddll.ImageSize, 0);

		// insert Ldr_data_list : m_ptrldrdat_entry_addr(peb_ldr_data)
		// error
		// if (!m_Mem_ldrdat_addr)
		// {
		//		return false;
		// }
		// Moduole_LdrData modldr = { 0, };
		// m_Mem_ldrdat_addr->InLoadOrderModuleList.Flink = &modldr.List;
		// m_Mem_ldrdat_addr->InLoadOrderModuleList.Blink = &modldr.List;
	}
	return true;
}

bool PeEmu::InitsampleIatRep(
)
{
	// ImageBase = uc_mem_map地址
	// 这里直接用pe.ImageBase即可

	// sample repair iat
	this->RepairTheIAT((IMAGE_IMPORT_DESCRIPTOR *)m_ImportBaseAddr, m_ImageBase);

	// 
	// if processos exe support relocation ? sample repair relocation : not handling
	//
	this->RepairReloCation((PIMAGE_DOS_HEADER)m_ImageBase);

	return true;
}

BOOL PeEmu::RepairReloCation(
	PIMAGE_DOS_HEADER m_studBase
)
{
	PIMAGE_DOS_HEADER pStuDos = (PIMAGE_DOS_HEADER)m_studBase;
	PIMAGE_NT_HEADERS pStuNt = (PIMAGE_NT_HEADERS)(pStuDos->e_lfanew + (DWORD64)m_studBase);
	PIMAGE_BASE_RELOCATION pStuRelocation = (PIMAGE_BASE_RELOCATION)(pStuNt->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD64)m_studBase);
	typedef struct _Node
	{
		WORD offset : 12;
		WORD type : 4;
	}Node, *PNode;

	LONGLONG dwDelta = (__int64)m_studBase - pStuNt->OptionalHeader.ImageBase;
	while (pStuRelocation->SizeOfBlock)
	{
		DWORD nStuRelocationBlockCount = (pStuRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		_Node* RelType = (PNode)(pStuRelocation + 1);

		for (DWORD i = 0; i < nStuRelocationBlockCount; ++i)
		{
			if (RelType->type == 10 || RelType[i].type == 3) {
				PULONGLONG pAddress = (PULONGLONG)((DWORD64)m_studBase + pStuRelocation->VirtualAddress + RelType[i].offset);
				*pAddress += dwDelta;
			}
		}
		pStuRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)pStuRelocation + pStuRelocation->SizeOfBlock);
	}
	return TRUE;
}

void PeEmu::RepairTheIAT(
	IMAGE_IMPORT_DESCRIPTOR * pImportTabe,
	DWORD64 dwMoudle
)
{
	DWORD64 ImportTabVA = 0, FunAddress = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImport = pImportTabe;
	DWORD Att_old = 0;

	uint64_t mapdllbaseaddr = 0;
	ModDLL mod;
	bool currentDllflags = false;
	while (pImport->Name)
	{
		// sample dllname
		char* Name = (char*)(pImport->Name + dwMoudle);
		// find MapModList <sample dllname> MapModDllBaseAddr
		for (size_t idx = 0; idx < current_dlls_map.size(); ++idx)
		{
			mod = current_dlls_map[idx];
			if (mod.DllName == Name)
			{
				// Find OK
				mapdllbaseaddr = mod.MapImageBase;
				if (mapdllbaseaddr <= 0)
					continue;
				currentDllflags = true;
			}
		}
		// currentDllflags为假,没有加载该DLL -- 不支持异常
		if (currentDllflags == false)
			return;

		PIMAGE_THUNK_DATA pThunkINT = (PIMAGE_THUNK_DATA)(pImport->OriginalFirstThunk + dwMoudle);
		PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)(pImport->FirstThunk + dwMoudle);
		while (pThunkINT->u1.AddressOfData)
		{
			if (!IMAGE_SNAP_BY_ORDINAL(pThunkIAT->u1.Ordinal))
			{
				// FunctionName
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pThunkINT->u1.AddressOfData + dwMoudle);
				auto MapIataddr = pThunkINT->u1.Function + mapdllbaseaddr;
				auto iter = mod.dll_functionaddr_map.find(MapIataddr);
				if (iter != mod.dll_functionaddr_map.end())
				{
					pThunkIAT->u1.Function = MapIataddr;
				}
				else
					// exception handling <Levele ModApi>
					return;
			}
			++pThunkINT;
			++pThunkIAT;
		}
		++pImport;
	}
}

bool PeEmu::prRun(
)
{
	// set hook callback 

	// start unicorn

	return 0;
}