#pragma once
#ifndef PUPEINFODATA_H_
#define PUPEINFODATA_H_

#include <Windows.h>
#include <atlstr.h>

class PuPEInfo
{
public:
	PuPEInfo();
	~PuPEInfo();

public:
	void* puCodeMapImageBase(){ return m_pFileBase; }

	void* puGetNtHeadre(){ return m_pNtHeader; }

	void* puGetSection(){ return m_SectionHeader; }

	UINT64 puGetImportBaseAddr() { return m_ImportBaseaddr; }

	UINT64 puGetImageSize() { return m_SizeOfImage; }

	UINT64 puGetImageBase() { return m_ImageBase; }

	bool puGetx86x64() { return m_x86x64flag; };

	DWORD puFileSize(){ return m_FileSize; }

	BOOL puOpenFileLoad(const CString & PathName){ return prOpenFile(PathName); }

	BOOL puIsPEFile(){ return IsPEFile(); }

	DWORD puRVAofFOA(const DWORD Rva){ return RVAofFOA(Rva); }

	CString puFilePath(){ return m_strNamePath; }

	HANDLE puFileHandle() { return m_hFileHandle; }

	DWORD64 puOldOep(){ return this->m_OldOEP; }

	int puGetSectionCount() { return this->m_SectionCount; }

	PIMAGE_SECTION_HEADER puGetSectionAddress(const char* Base, const BYTE* Name){ return this->GetSectionAddress(Base, Name); }

	BOOL puSetFileoffsetAndFileSize(const void* Base, const DWORD & offset, const DWORD size, const BYTE* Name)
	{
		return this->SetFileoffsetAndFileSize(Base, offset, size, Name);
	}

private:

	BOOL prOpenFile(const CString & PathName);
	BOOL IsPEFile();
	// RVAofFOA
	DWORD RVAofFOA(const DWORD Rva);
	PIMAGE_SECTION_HEADER GetSectionAddress(const char* Base, const BYTE* SectionName);
	BOOL SetFileoffsetAndFileSize(const void* Base, const DWORD & offset, const DWORD size, const BYTE* Name);


	static bool m_x86x64flag;
	static void* m_pFileBase;
	static void* m_pNtHeader;
	static void* m_SectionHeader;
	static UINT64 m_ImportBaseaddr;
	static UINT64 m_SizeOfImage;
	static UINT64 m_ImageBase;
	static DWORD m_FileSize;
	static CString m_strNamePath;
	static HANDLE m_hFileHandle;
	static DWORD m_OldOEP;
	static int	m_SectionCount;
	static BOOL OepFlag;
	HANDLE      _hMapping;                     // Memory mapping object

};

#endif
