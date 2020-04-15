#include "Hook.h"



_Hook* _Hook::Instance = 0;

void* operator new(size_t Size)
{
	void *pt = ExAllocatePool(NonPagedPool, Size);
	if (pt != NULL)
	{
		memset(pt, 0, Size);
	}
	return pt;
}


_Hook* _Hook::GetInstance()
{
	if (Instance == NULL)
	{
		Instance = new _Hook;
	}
	return Instance;
}
static _declspec(naked)  void WriteProtect_Off()
{
	_asm
	{
		push rax
		cli;						//如果不加分号会蓝屏
		mov rax, cr0
			and rax, not 0x10000
			mov cr0, rax
			pop rax
			ret
	}
}

static _declspec(naked) void  WriteProtect_On()
{
	_asm
	{
		push rax
		mov rax, cr0
		or rax, 0x10000
		mov cr0, rax
		sti;
		pop rax
			ret
	}
}
LDR_DATA_TABLE_ENTRY* _Hook::GetModuleInfo(PDRIVER_OBJECT driver, wchar_t* ModuleName)	//获取模块信息，成功返回LDR指针，失败返回0
{
	for (LDR_DATA_TABLE_ENTRY* ListEntry = (LDR_DATA_TABLE_ENTRY*)driver->DriverSection; ListEntry->InLoadOrderLinks.Flink != driver->DriverSection; ListEntry = (LDR_DATA_TABLE_ENTRY*)ListEntry->InLoadOrderLinks.Flink)
	{
		if (MmIsAddressValid(ListEntry->BaseDllName.Buffer))
		{
			if (!wcscmp(ListEntry->BaseDllName.Buffer, ModuleName))			//确定内核模块位置，通过模块基址加偏移得到指定函数，再通过函数内偏移获得硬编码。计算出变量地址。
			{
				return ListEntry;
			}
		}
	}
	return FALSE;
}

BOOLEAN _Hook::IsListEmpty(_In_ const LIST_ENTRY * ListHead)
{
	return (BOOLEAN)(ListHead->Flink == ListHead);
}
VOID _Hook::InsertHeadList(_Inout_ PLIST_ENTRY ListHead, _Out_ __drv_aliasesMem PLIST_ENTRY Entry)
{
	if (HookList.Flink == NULL)
	{
		InitializeListHead(&Instance->HookList);
	}
	PLIST_ENTRY NextEntry;



	NextEntry = ListHead->Flink;
	Entry->Flink = NextEntry;
	Entry->Blink = ListHead;
	NextEntry->Blink = Entry;
	ListHead->Flink = Entry;
	return;
}
BOOLEAN _Hook::RemoveEntryList(_In_ PLIST_ENTRY Entry)
{

	PLIST_ENTRY PrevEntry;
	PLIST_ENTRY NextEntry;

	NextEntry = Entry->Flink;
	PrevEntry = Entry->Blink;
	if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {
		return false;
	}

	PrevEntry->Flink = NextEntry;
	NextEntry->Blink = PrevEntry;
	return (BOOLEAN)(PrevEntry == NextEntry);
}
void JmpRip(PVOID JmpAddr, PVOID TargetAddr)
{
	char Jmp[] = { 0xff,0x25,0x00,0x00,0x00,0x00 };
	memcpy(JmpAddr, Jmp, 6);
	memcpy((char*)JmpAddr + 6, &TargetAddr, 8);

}
void CallTarget(PVOID CallAddr, PVOID TargetAddr)
{
	char CallCode[] = { 0x48, 0xBF, 0x34 ,0x12 ,0x34 ,0x12 ,0x34 ,0x12 ,0x34 ,0x12 ,0x57 ,0x48 ,0x8B ,0x7C ,0x24 ,0x08 ,0xFF ,0x14 ,0x24 ,0x48 ,0x83 ,0xC4 ,0x08 };
	memcpy(CallAddr, CallCode, sizeof(CallCode));
	memcpy((char*)CallAddr + 2, &TargetAddr, 8);
}
bool _Hook::InlineHookInstall(PVOID Source, PVOID Destination, size_t HookSize)
{
	PHookData HookItem = (PHookData)ExAllocatePool(NonPagedPool, sizeof(HookData));
	if (HookItem == NULL)
	{
		DbgPrint("Memory Alloc Error！\n");
		return false;
	}
	RtlZeroMemory(HookItem, sizeof(HookData));
	HookItem->SourceAddr = Source;
	HookItem->DestinationAddr = Destination;
	HookItem->ReplaceByteSize = HookSize;
	HookItem->RetAddr = (char*)Source + HookSize;
	HookItem->EntryAddr = ExAllocatePool(NonPagedPool, sizeof(HookEntry));
	HookItem->Type = Inline;
	if (HookItem->EntryAddr == NULL)
	{
		DbgPrint("Memory Alloc Error！\n");
		return false;
	}
	WriteProtect_Off();
	memset(HookItem->EntryAddr, 0x90, 0xa6);
	memcpy(HookItem->data, Source, HookSize);				//拷贝HOOK数据
	memcpy(HookItem->EntryAddr, HookEntry, 0xa6);			//HookEntry赋值
															//构建HookEntry中的跳转代码
	CallTarget((char*)HookItem->EntryAddr + 23, Destination);
	//复制Hook的代码流到HookEntry
	memcpy((char*)HookItem->EntryAddr + 86, HookItem->data, HookItem->ReplaceByteSize);
	//构建返回代码
	JmpRip((char*)HookItem->EntryAddr + 126, HookItem->RetAddr);
	//HookEntry代码构建完成，开始Hook目标代码
	JmpRip(Source, HookItem->EntryAddr);

	WriteProtect_On();
	InsertHeadList(&HookList, &HookItem->List);
	return true;
}
PHookData _Hook::ReturnDataBySource(PVOID Source)
{
	PLIST_ENTRY ListEntry = HookList.Flink;
	while (ListEntry != &HookList)
	{
		PHookData Hookdata = CONTAINING_RECORD(ListEntry, HookData, List);
		if (Hookdata->SourceAddr == Source)
		{
			return Hookdata;
		}
		ListEntry = ListEntry->Flink;
	}
	return false;
}
bool  _Hook::InlineHookUnInstall(PVOID Source)
{

	PHookData Hookdata = ReturnDataBySource(Source);
	if (Hookdata->SourceAddr == Source)
	{
		WriteProtect_Off();
		memcpy(Hookdata->SourceAddr, Hookdata->data, Hookdata->ReplaceByteSize);
		WriteProtect_On();
		RemoveEntryList(&Hookdata->List);
		ExFreePool(Hookdata->EntryAddr);
		ExFreePool(Hookdata);
		return true;
	}

	return false;
}
bool _Hook::EatHookInstall(PDRIVER_OBJECT driver, wchar_t* ModuleName, __int64 HookAddr, __int64 NewAddr)
{
	IMAGE_DOS_HEADER* Dos_Header;
	IMAGE_NT_HEADERS64* NT_Header;
	IMAGE_SECTION_HEADER* Section_Header;
	LDR_DATA_TABLE_ENTRY* ModuleInfo = (LDR_DATA_TABLE_ENTRY*)GetModuleInfo(driver, ModuleName);
	if ((NewAddr - ModuleInfo->DllBase) >> 0x20)
	{
		DbgPrint("Eat Hook Failed! Because of Offset Overflow!\n");
	}
	PHookData HookItem = (PHookData)ExAllocatePool(NonPagedPool, sizeof(HookData));
	HookItem->SourceAddr = (PVOID)HookAddr;
	HookItem->DestinationAddr = (PVOID)NewAddr;
	HookItem->driver = driver;
	HookItem->ModuleName = ModuleName;
	HookItem->Type = EAT;
	Dos_Header = (IMAGE_DOS_HEADER*)(PVOID64)ModuleInfo->DllBase;
	NT_Header = (IMAGE_NT_HEADERS64*)(Dos_Header->e_lfanew + (char*)Dos_Header);
	__int64 ImageBase = (__int64)Dos_Header;
	IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((char*)ImageBase + (NT_Header->OptionalHeader.DataDirectory[0].VirtualAddress));//导出表
	__int64 FunctionTable = (__int64)(char*)ExportDirectory->AddressOfFunctions + ImageBase;
	for (int i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		if ((__int64)((char*)ImageBase + *(DWORD32*)((char*)FunctionTable + i * 4)) == HookAddr)
		{
			*(DWORD32*)((char*)FunctionTable + i * 4) = (DWORD32)((char*)NewAddr - ImageBase);
			InsertHeadList(&HookList, &HookItem->List);
			return TRUE;
		}
	}
	return FALSE;
}

bool _Hook::EatHookUnInstall(PVOID Source)
{
	PDRIVER_OBJECT driver;
	wchar_t* ModuleName;
	__int64 HookAddr, __int64 NewAddr;
	PHookData Hookdata = ReturnDataBySource(Source);
	if (Hookdata == NULL)
	{
		return false;
	}
	driver = Hookdata->driver;
	ModuleName = Hookdata->ModuleName;
	HookAddr = (__int64)Hookdata->DestinationAddr;
	NewAddr = (__int64)Hookdata->SourceAddr;
	IMAGE_DOS_HEADER* Dos_Header;
	IMAGE_NT_HEADERS64* NT_Header;
	IMAGE_SECTION_HEADER* Section_Header;
	LDR_DATA_TABLE_ENTRY* ModuleInfo = (LDR_DATA_TABLE_ENTRY*)GetModuleInfo(driver, ModuleName);
	if ((NewAddr - ModuleInfo->DllBase) >> 0x20)
	{
		DbgPrint("Eat Hook Failed! Because of Offset Overflow!\n");
	}
	Dos_Header = (IMAGE_DOS_HEADER*)(PVOID64)ModuleInfo->DllBase;
	NT_Header = (IMAGE_NT_HEADERS64*)(Dos_Header->e_lfanew + (char*)Dos_Header);
	__int64 ImageBase = (__int64)Dos_Header;
	IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((char*)ImageBase + (NT_Header->OptionalHeader.DataDirectory[0].VirtualAddress));//导出表
	__int64 FunctionTable = (__int64)(char*)ExportDirectory->AddressOfFunctions + ImageBase;
	for (int i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		if ((__int64)((char*)ImageBase + *(DWORD32*)((char*)FunctionTable + i * 4)) == HookAddr)
		{
			*(DWORD32*)((char*)FunctionTable + i * 4) = (DWORD32)((char*)NewAddr - ImageBase);
			RemoveEntryList(&Hookdata->List);
			ExFreePool(Hookdata);
			return TRUE;
		}
	}
	return FALSE;
}

bool _Hook::DirectHookInstall(PVOID Source, PVOID Destination)
{
	PHookData HookItem = (PHookData)ExAllocatePool(NonPagedPool, sizeof(HookData));
	if (HookItem == NULL)
	{
		DbgPrint("Memory Alloc Error！\n");
		return false;
	}
	RtlZeroMemory(HookItem, sizeof(HookData));
	HookItem->SourceAddr = Source;
	HookItem->DestinationAddr = Destination;
	HookItem->ReplaceByteSize = 14;
	HookItem->Type = Direct;
	WriteProtect_Off();
	memcpy(HookItem->data, Source, 14);				//拷贝HOOK数据
	JmpRip(Source, Destination);
	WriteProtect_On();
	InsertHeadList(&HookList, &HookItem->List);
	return true;
}
bool _Hook::DirectHookUnInstall(PVOID Source)
{

	PHookData Hookdata = ReturnDataBySource(Source);
	if (Hookdata->SourceAddr == Source)
	{
		WriteProtect_Off();
		memcpy(Hookdata->SourceAddr, Hookdata->data, Hookdata->ReplaceByteSize);
		WriteProtect_On();
		RemoveEntryList(&Hookdata->List);
		ExFreePool(Hookdata);
		return true;
	}

	return false;
}
bool _Hook::UnInstallHook(PVOID Source)
{

	PHookData Hookdata = ReturnDataBySource(Source);
	if (Hookdata->SourceAddr == Source)
	{
		switch (Hookdata->Type)
		{
		case Inline:
			InlineHookUnInstall(Source);
			break;
		case Direct:
			DirectHookUnInstall(Source);
			break;
		case EAT:
			EatHookUnInstall(Source);
			break;
		case IAT:
			break;
		default:
			break;
		}
		return true;
	}

	return false;
}


void _Hook::UnInstallAllHooks()
{

	while (!IsListEmpty(&HookList))
	{
		PLIST_ENTRY ListEntry = HookList.Flink;
		PHookData Hookdata = CONTAINING_RECORD(ListEntry, HookData, List);
		UnInstallHook(Hookdata->SourceAddr);
	}

}



bool _Hook::IsHooked(PVOID Source)
{
	return (ReturnDataBySource(Source) != 0);
}