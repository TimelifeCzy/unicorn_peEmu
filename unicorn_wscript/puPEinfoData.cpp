#include "puPEinfoData.h"


void* PuPEInfo::m_pFileBase = nullptr;
void* PuPEInfo::m_pNtHeader = nullptr;
UINT64 PuPEInfo::m_ImageBase = 0;
UINT64 PuPEInfo::m_ImportBaseaddr = 0;
void* PuPEInfo::m_SectionHeader = nullptr;
UINT64 PuPEInfo::m_SizeOfImage = 0;
DWORD PuPEInfo::m_FileSize = 0;
bool PuPEInfo::m_x86x64flag = false;
CString PuPEInfo::m_strNamePath;
HANDLE PuPEInfo::m_hFileHandle = nullptr;
DWORD PuPEInfo::m_OldOEP = 0;
int	PuPEInfo::m_SectionCount = 0;

PuPEInfo::PuPEInfo()
{

}

PuPEInfo::~PuPEInfo()
{

}

BOOL PuPEInfo::IsPEFile()
{
	if (IMAGE_DOS_SIGNATURE != ((PIMAGE_DOS_HEADER)PuPEInfo::m_pFileBase)->e_magic) return FALSE;
	
	if (IMAGE_NT_SIGNATURE != ((PIMAGE_NT_HEADERS)PuPEInfo::m_pNtHeader)->Signature) return FALSE;
	
	return TRUE;
}

BOOL PuPEInfo::prOpenFile(
	const CString & PathName
)
{
	m_strNamePath = PathName;
	HANDLE hFile = CreateFile(PathName, GENERIC_READ | GENERIC_WRITE, FALSE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if ((int)hFile <= 0){ 
		return FALSE; 
	}
	_hMapping = CreateFileMappingW(hFile, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);
	if (_hMapping)
	{
		PuPEInfo::m_pFileBase = MapViewOfFile(_hMapping, FILE_MAP_READ, 0, 0, 0);
	}
	else
	{
		_hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

		if (_hMapping)
			PuPEInfo::m_pFileBase = MapViewOfFile(_hMapping, FILE_MAP_READ, 0, 0, 0);
	}
	if (!PuPEInfo::m_pFileBase)
		return false;
	PIMAGE_DOS_HEADER pDosHander = (PIMAGE_DOS_HEADER)PuPEInfo::m_pFileBase;
	PIMAGE_NT_HEADERS pHeadres = (PIMAGE_NT_HEADERS)(pDosHander->e_lfanew + (DWORD64)m_pFileBase);
	m_pNtHeader = pHeadres;
	if (!pHeadres)
		return false;
	// if pe ? true : false
	if (!IsPEFile())
		return false;
	if (pHeadres->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		m_x86x64flag = true;
	else
		m_x86x64flag = false;

	CloseHandle(hFile);
	UnmapViewOfFile(PuPEInfo::m_pFileBase);
	CloseHandle(_hMapping);
	return TRUE;
}

// RVAofFOA
DWORD PuPEInfo::RVAofFOA(const DWORD Rva)
{
	DWORD dwSectionCount = (PIMAGE_NT_HEADERS(PuPEInfo::m_pNtHeader))->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)PuPEInfo::m_pNtHeader);

	for (DWORD i = 0; i < dwSectionCount; ++i)
	{
		if ((Rva >= (pSection->VirtualAddress)) && (Rva < ((pSection->VirtualAddress) + (pSection->SizeOfRawData)))) {
			// DWORD offset = Rva - pSection->VirtualAddress;
			// DWORD FOA = pSection->PointerToRawData + offset;
			return (pSection->VirtualAddress + pSection->PointerToRawData);
		}
		++pSection;
	}
	return 0;
}

PIMAGE_SECTION_HEADER PuPEInfo::GetSectionAddress(const char* Base, const BYTE* SectionName)
{
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)Base)->e_lfanew + Base);

	PIMAGE_SECTION_HEADER pSect = IMAGE_FIRST_SECTION(pNt);

	for (int i = 0; i < m_SectionCount; ++i) { 
		if (0 == _mbscmp(pSect->Name, SectionName))
			return (PIMAGE_SECTION_HEADER)pSect; 
		++pSect; 
	}
	
	return 0;
}

BOOL PuPEInfo::SetFileoffsetAndFileSize(const void* Base, const DWORD & offset, const DWORD size, const BYTE* Name)
{
	 PIMAGE_SECTION_HEADER Address = GetSectionAddress((char*)Base, Name);

	 Address->PointerToRawData = offset;

	 Address->SizeOfRawData = size;

	 return TRUE;
}