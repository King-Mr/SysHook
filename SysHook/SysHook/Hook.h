#pragma once

#include <ntifs.h>
#define Pushad 0x50,0x53,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x55,0x56,0x57  
#define Popad 0x5F,0x5E,0x5D,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5A,0x59,0x5B,0x58
#define Nop 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
typedef unsigned short      WORD;
typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned char		BOOL;
#ifndef LDR
#define LDR
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY	InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY	InInitializationOrderLinks;
	LONG64	DllBase;
	LONG64 EntryPoint;
	int SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
}LDR_DATA_TABLE_ENTRY;
#endif

#define IMAGE_SIZEOF_SHORT_NAME              8
typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;  // PBYTE 
		ULONGLONG Function;         // PDWORD
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;                  // 0 if not bound,
											// -1 if bound, and real date\time stamp
											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
											// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

//可选PE头
typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

//标准PE头
typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

//NT头
typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;								//0x5045 "PE" 标记
	IMAGE_FILE_HEADER FileHeader;					//标准PE头
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;			//可选PE头
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;


//DOS 头
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;



typedef struct
{
	IMAGE_DOS_HEADER *Dos_Header;
	IMAGE_NT_HEADERS64 *NT_Header;
	IMAGE_SECTION_HEADER *Section_Header;
}PE;
enum HookType
{
	Inline,
	Direct,
	EAT,
	IAT
};
typedef struct _HookData
{
	LIST_ENTRY List = { NULL };
	HookType Type;
	PVOID SourceAddr;
	PVOID DestinationAddr;
	PVOID RetAddr;
	union
	{
		PVOID EntryAddr;
		PDRIVER_OBJECT driver;
	};

	char ReplaceByteSize;
	union
	{
		char data[20];
		wchar_t* ModuleName;
	};



}HookData, *PHookData;

typedef class _Hook
{
private:
	static _Hook* Instance;
	LIST_ENTRY HookList = { NULL };
private:

	char HookEntry[0xa6] = { Pushad,Nop,Popad,Nop,Nop };
	_Hook() = default;
	~_Hook() = default;
	BOOLEAN IsListEmpty(_In_ const LIST_ENTRY * ListHead);
	VOID InsertHeadList(_Inout_ PLIST_ENTRY ListHead, _Out_ __drv_aliasesMem PLIST_ENTRY Entry);
	BOOLEAN RemoveEntryList(_In_ PLIST_ENTRY Entry);
	LDR_DATA_TABLE_ENTRY* GetModuleInfo(PDRIVER_OBJECT driver, wchar_t* ModuleName);
	PHookData ReturnDataBySource(PVOID Source);
	/// <summary>
	/// Inline Hook Uninstall
	/// </summary>
	/// <param name="Source">Hooked Address</param>
	/// <returns>UnInstall State </returns>
	bool DirectHookUnInstall(PVOID Source);



	/// <summary>
	/// Direct Hook Uninstall
	/// </summary>
	/// <param name="Source">Hooked Address</param>
	/// <returns>UnInstall State </returns>
	bool InlineHookUnInstall(PVOID Source);


	/// <summary>
	/// EAT Hook Uninstall
	/// </summary>
	/// <param name="Source">Hooked Address</param>
	/// <returns>UnInstall State </returns>
	bool EatHookUnInstall(PVOID Source);
public:
	static _Hook* GetInstance();



	/// <summary>
	/// Inline Hook Install
	/// This Hook Not Require Manual Recover Stack
	/// </summary>
	/// <param name="Source">Require Hooked Point </param>
	/// <param name="Destination">Target Filter Function</param>
	/// <param name="HookSize">Hook Code Length</param>
	/// <returns>Hook Install State </returns>
	bool InlineHookInstall(PVOID Source, PVOID Destination, size_t HookSize);




	/// <summary>
	/// EAT Hook Install
	/// The Hook is Replace Target Export Table Function As the Filter Function
	/// </summary>
	/// <param name="driver">Driver Object </param>
	/// <param name="ModuleName">Target Module Name </param>
	/// <param name="HookAddr">Require Hooked Address</param>
	/// <param name="NewAddr">Target Filter Function</param>
	/// <returns>Hook Install State </returns>
	bool EatHookInstall(PDRIVER_OBJECT driver, wchar_t* ModuleName, __int64 HookAddr, __int64 NewAddr);





	/// <summary>
	/// Direct Hook Install
	/// The Hook is Direct Jmp Target Function,Require Manual Recover Stack And Return
	/// </summary>
	/// <param name="Source">Require Hooked Point</param>
	/// <param name="Destination">Target Filter Function</param>
	/// <returns>Hook Install State </returns>
	bool DirectHookInstall(PVOID Source, PVOID Destination);




	/// <summary>
	/// Hook Uninstall
	/// Uninstall Different Types Hooks
	/// </summary>
	/// <param name="Source">Hooked Address</param>
	/// <returns>UnInstall State </returns>
	bool UnInstallHook(PVOID Source);




	/// <summary>
	/// UnInstall All Hooks
	void UnInstallAllHooks();



	bool IsHooked(PVOID Source);
}Hook, *PHook;
