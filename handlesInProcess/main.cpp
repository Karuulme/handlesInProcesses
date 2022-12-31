#include "library.cpp"
#include <Processthreadsapi.h>
#include<map>
class processListClass {
public:
	map<DWORD, HANDLE> processList;

	void added(DWORD* key) {
		processList[*key] = 0;
	}
	HANDLE* getHandle(DWORD key) {
		return &processList.find(key)->second;
	}
	~processListClass() {
		std::map<DWORD, HANDLE>::iterator it = processList.begin();
		while (it != processList.end())
		{
			CloseHandle(it->second);
			it++;
		}
	}
	void handleClose(DWORD pid) {
		CloseHandle(processList.find(pid)->second);
		processList.erase(pid);
	}
};
int getProcessIDList(processListClass* process);
/*
int getHandles(DWORD * pid, processListClass* processList, _NtQuerySystemInformation* NtQuerySystemInformation, _NtDuplicateObject *NtDuplicateObject, _NtQueryObject *NtQueryObject)
{
	PSYSTEM_HANDLE_INFORMATION handleLis = (PSYSTEM_HANDLE_INFORMATION)malloc(sizeof(PSYSTEM_HANDLE_INFORMATION));
	NTSTATUS ntStatus = STATUS_INFO_LENGTH_MISMATCH;
	DWORD dwRet;
	DWORD dwSize = 0x0;

	while (true)
	{
		VirtualFree(handleLis, 0x0, MEM_RELEASE);
		handleLis = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		ntStatus = (*NtQuerySystemInformation)(16, handleLis, (ULONG)dwSize, &dwRet);
		if (ntStatus == STATUS_SUCCESS) { break; }
		else if (ntStatus != STATUS_INFO_LENGTH_MISMATCH) {
			VirtualFree(handleLis, 0x0, MEM_RELEASE);
			handleLis = nullptr;
			return 0x1;
		}
		dwSize = dwRet + (2 << 12);
	}
	for (int i = 0; i < handleLis->HandleCount; i++)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleLis->Handles[i];
		HANDLE dupHan;
		POBJECT_TYPE_INFORMATION handlTeype = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		PULONG	ReturnLength = 0;
		OBJECT_INFORMATION_CLASS handleReferance;
		PVOID objectNameInfo = {};
		UNICODE_STRING objectName;
		 
		if (handle.ProcessId == *pid) {
			if ((*NtDuplicateObject)(*processList->getHandle(*pid), (HANDLE)handle.Handle, GetCurrentProcess(), &dupHan, 0, 0, 0) != STATUS_SUCCESS)
				goto next;
			handleReferance = ObjectType;
			if ((*NtQueryObject)(dupHan, handleReferance, handlTeype, 0x1000, ReturnLength) < 0) {
				if ((*NtQueryObject)(dupHan, handleReferance, handlTeype, *ReturnLength, NULL) < 0)
					goto next;
			}
			handleReferance = ObjectName;
			ReturnLength = 0;
			objectNameInfo = malloc(0x1000);
			if ((*NtQueryObject)(dupHan, handleReferance, objectNameInfo, 0x1000, ReturnLength) < 0) {
				if ((*NtQueryObject)(dupHan, handleReferance, objectNameInfo, *ReturnLength, NULL) < 0)
					goto next;
			}
			objectName = *(PUNICODE_STRING)objectNameInfo;
			(objectName.Length) ? printf("%.*S: %.*S\n", handlTeype->Name.Length / 2, handlTeype->Name.Buffer, objectName.Length / 2, objectName.Buffer) : NULL;
		next:
			free(handlTeype);
			free(objectNameInfo);
			CloseHandle(dupHan);
		}
	}
	free(handleLis);
	return 0;
}*/
int main() {
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
	//string a;
	processListClass processList;
	getProcessIDList(&processList);
	std::map<DWORD, HANDLE>::iterator it = processList.processList.begin();
	while (it != processList.processList.end())
	{
		//openProcessHandle(it->first, &processList,&a);	
		HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE,(DWORD)it->first);
		if (processHandle != NULL) {
			cout << "BASARILI" << endl;
			DuplicateHandle(GetCurrentProcess(), processHandle, GetCurrentProcess(), processList.getHandle(it->first), 0, FALSE, DUPLICATE_SAME_ACCESS);
		}
		it++;
		CloseHandle(processHandle);
	}
}
int getProcessIDList(processListClass* process) {
	HANDLE hProcessShot;
	PROCESSENTRY32 ProcessInformation;
	hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	ProcessInformation.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessShot, &ProcessInformation) && INVALID_HANDLE_VALUE != hProcessShot) {
		do
		{
			process->added(&ProcessInformation.th32ProcessID);
		} while (Process32Next(hProcessShot, &ProcessInformation));
	}
	else {

	}
	CloseHandle(hProcessShot);
	return 0;
}
/*
http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FNtQueryObject.html
https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
https://github.com/Zer0Mem0ry/WindowsNT-Handle-Scanner/blob/master/FindHandles/main.cpp
https://cplusplus.com/forum/windows/95774/
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
*/