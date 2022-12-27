#include "kaynak.cpp"
#include <Processthreadsapi.h>
int main() {
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
	HANDLE processHandle;
	PSYSTEM_HANDLE_INFORMATION sProInfo=(PSYSTEM_HANDLE_INFORMATION)malloc(sizeof(sProInfo));
	NTSTATUS ntStatus = STATUS_INFO_LENGTH_MISMATCH;
	DWORD dwRet;
	DWORD dwSize = 0x0; 
	while (true)
	{
		// VirtualFree(sProInfo, 0x0, MEM_RELEASE);
		sProInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		ntStatus = NtQuerySystemInformation(16, sProInfo, (ULONG)dwSize, &dwRet);
		if (ntStatus == STATUS_SUCCESS) { break; }
		else if (ntStatus != STATUS_INFO_LENGTH_MISMATCH) {
			VirtualFree(sProInfo, 0x0, MEM_RELEASE);
			sProInfo = nullptr;
			return 0x1;
		}
		dwSize = dwRet + (2 << 12);
	}
	cout<<(int)sProInfo->HandleCount;

	for (int i = 0; i < sProInfo->HandleCount;i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = sProInfo->Handles[i];
		if (handle.ProcessId==2412) {
			//= OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2412);
			printf_s("Handle 0x%x at 0x%p, PID: %x\n", handle.Handle, handle.Object, handle.ProcessId);
		}	
	}
	CloseHandle(processHandle);
	return 0;
}