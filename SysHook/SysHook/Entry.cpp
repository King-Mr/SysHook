

#include "Hook.h"
NTKERNELAPI
extern "C" UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);
__declspec(naked) void temp()
{
	_asm
	{
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		sub rsp, 0x20
	}
	DbgPrint("temp 执行\n");
	_asm add rsp, 0x20
	_asm ret
}
void temp1()
{
	POBJECT_ATTRIBUTES Object = NULL;

	_asm mov Object,r8
	if (Object == NULL)
	{
		return;
	}
	PEPROCESS CurrentProcess = PsGetCurrentProcess();
	UCHAR *ProcessName = PsGetProcessImageFileName(CurrentProcess);
	DbgPrint("HOOK执行，进程;%s,创建文件：%ws\n", ProcessName, Object->ObjectName->Buffer);
}
void temp2()
{
	DbgPrint("temp2执行");
}
NTSTATUS Unload(PDRIVER_OBJECT driver)
{
	Hook::GetInstance()->UnInstallAllHooks();
	return 0;
}
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING64 Path)
{
	Hook::GetInstance()->InlineHookInstall((PVOID)NtCreateFile, temp1, 16);
	Hook::GetInstance()->InlineHookInstall(temp, temp2, 14);
	
	temp();
	
	Hook::GetInstance()->UnInstallHook(temp);
	temp();
	driver->DriverUnload = (PDRIVER_UNLOAD)Unload;
	return 0;

}