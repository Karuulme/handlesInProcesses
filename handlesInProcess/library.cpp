#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <vector>
#define NT_SUCCESS(x) ((x) >= 0)
#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")
constexpr unsigned int STATUS_SUCCESS = 0x0;
constexpr unsigned int STATUS_INFO_LENGTH_MISMATCH = 0x0C0000004;
using namespace std;
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG  SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE       SourceProcessHandle,
	HANDLE       SourceHandle,
	HANDLE       TargetProcessHandle,
	PHANDLE      TargetHandle,
	ACCESS_MASK  DesiredAccess,
	ULONG        HandleAttributes,
	ULONG        Options
	);
typedef  NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE    Handle,
	ULONG	  ObjectInformationClass,
	PVOID     ObjectInformation,
	ULONG     ObjectInformationLength,
	PULONG    ReturnLength
	);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;

}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

enum OBJECT_INFORMATION_CLASS
{
	ObjectBasic  = 0,
	ObjectName   = 1,
	ObjectType   = 2,
	ObjectHandle = 16
};



















