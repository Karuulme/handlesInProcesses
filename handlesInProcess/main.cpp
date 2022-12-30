#include "library.cpp"
#include <Processthreadsapi.h>
int main() {
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

	int pid=3696;
	HANDLE processHandle=OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	PSYSTEM_HANDLE_INFORMATION handleLis = (PSYSTEM_HANDLE_INFORMATION)malloc(sizeof(PSYSTEM_HANDLE_INFORMATION));
	NTSTATUS ntStatus = STATUS_INFO_LENGTH_MISMATCH;
	DWORD dwRet;
	DWORD dwSize = 0x0;

	while (true)
	{
		VirtualFree(handleLis, 0x0, MEM_RELEASE);
		handleLis = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		ntStatus = NtQuerySystemInformation(16, handleLis, (ULONG)dwSize, &dwRet);
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
		POBJECT_TYPE_INFORMATION handlTeype=(POBJECT_TYPE_INFORMATION)malloc(0x1000);
		PULONG	ReturnLength=0;
		OBJECT_INFORMATION_CLASS handleReferance;
		PVOID objectNameInfo = {};
		UNICODE_STRING objectName;

		if (handle.ProcessId == pid) {
			if (NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHan, 0, 0, 0) != STATUS_SUCCESS)
				continue;
			handleReferance = ObjectType;
			if (NtQueryObject(dupHan, handleReferance, handlTeype, 0x1000, ReturnLength) < 0) {
				if(NtQueryObject(dupHan, handleReferance, handlTeype, *ReturnLength, NULL)<0)
					goto next;
			}
			handleReferance =ObjectName;
			ReturnLength=0;
			objectNameInfo = malloc(0x1000);
			if (NtQueryObject(dupHan, handleReferance, objectNameInfo, 0x1000, ReturnLength) < 0) {
				if (NtQueryObject(dupHan, handleReferance, objectNameInfo, *ReturnLength, NULL) < 0)
					goto next;
			}
			objectName = *(PUNICODE_STRING)objectNameInfo;
			
			(objectName.Length) ? printf("%.*S: %.*S\n", handlTeype->Name.Length / 2, handlTeype->Name.Buffer, objectName.Length / 2, objectName.Buffer):NULL;
		next:
			free(handlTeype);
			free(objectNameInfo);
			CloseHandle(dupHan);
		}	
	}

	//free(handleLis);
	CloseHandle(processHandle);
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