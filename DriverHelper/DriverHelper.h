#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>
#include <vector>

#pragma comment( lib, "ntdll.lib" )

// Kernel offsets
#define OFFSET_DIRECTORYTABLEBASE 0x028
#define OFFSET_UNIQUEPROCESSID 0x2e8
#define OFFSET_ACTIVEPROCESSLINKS 0x2f0
#define OFFSET_VIRTUALSIZE 0x338
#define OFFSET_SECTIONBASEADDRESS 0x3c0
#define OFFSET_OBJECTTABLE 0x418
#define OFFSET_IMAGEFILENAME 0x450
#define OFFSET_PRIORITYCLASS 0x45f

typedef BOOL (*_fn_memcpy)(ULONG64 dest, ULONG64 src, DWORD size);
typedef ULONG64(*_fn_mapPhysical)(DWORDLONG physicaladdress, DWORD size);
typedef ULONG64(*_fn_unmapPhysical)(ULONG64 address);

// Remove padding inside structs
#pragma pack(push, 1) 
typedef struct {
	CHAR  ImageFileName[15];
	DWORD PriorityClass;
} _EPROCESS_PATTERN;


// Structure of MAP
typedef struct _READ_REQUEST {
	DWORD InterfaceType;
	DWORD Bus;
	ULONG64 PhysicalAddress;
	DWORD IOSpace;
	DWORD size;
} READ_REQUEST;

typedef struct _WRITE_REQUEST {
	DWORDLONG address;
	DWORD length;
	DWORDLONG buffer;
} WRITE_REQUEST;

typedef struct _MEMCPY_REQUEST {
	ULONG64 dest;
	ULONG64 src;
	DWORD size;
} MEMCPY_REQUEST;



// Kernel Structures
typedef struct _HANDLE_TABLE_ENTRY
{
	ULONGLONG Value;
	ULONGLONG GrantedAccess : 25;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
	CHAR fill[100];
} HANDLE_TABLE, *PHANDLE_TABLE;


struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX			// Size => 28
{
	PVOID Object;									// Size => 4 Offset =>0
	ULONG UniqueProcessId;							// Size => 4 Offset =>4
	ULONG HandleValue;								// Size => 4 Offset =>8
	ULONG GrantedAccess;							// Size => 4 Offset =>12
	USHORT CreatorBackTraceIndex;					// Size => 2 Offset =>16
	USHORT ObjectTypeIndex;							// Size => 2 Offset =>18
	ULONG HandleAttributes;							// Size => 4 Offset =>20
	ULONG Reserved;									// Size => 4 Offset =>24
};

struct SYSTEM_HANDLE_INFORMATION_EX					// Size => 36
{
	ULONG NumberOfHandles;							// Size => 4 Offset => 0
	ULONG Reserved;									// Size => 4 Offset => 4
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];	// Size => 36 Offset => 8
};



class DriverHelper
{
public:
	static int memmem(PBYTE haystack, DWORD haystack_size, PBYTE needle, DWORD needle_size);
	static int getDeviceHandle(LPTSTR name);
	static unsigned __int64 __fastcall ExpLookupHandleTableEntryW7(__int64 HandleTable, unsigned __int64 handle);
	static unsigned __int64 __fastcall ExpLookupHandleTableEntryW10(__int64 HandleTable, __int64 handle);
	static ULONG64 findPhisical_ObjectTable(DWORDLONG startAddress, DWORDLONG stopAddress, DWORD searchSpace, PBYTE  searchBuffer, DWORD bufferSize);
	static DWORDLONG findPhisical(DWORDLONG startAddress, DWORDLONG stopAddress, DWORD searchSpace, PBYTE  searchBuffer, DWORD bufferSize);
	static bool LeakKernelPointers(std::vector<uintptr_t> &pKernelPointers);
	static uintptr_t FindDirectoryBase();
	static uint64_t VAtoPhylAddress(uint64_t directoryTableBase, LPVOID virtualAddress);
	static bool ReadVirtualMemory(uint64_t directoryTableBase, uintptr_t virtualAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead);
	static bool WriteVirtualMemory(uint64_t directoryTableBase, uintptr_t virtualAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);
	static uintptr_t ObtainKProcessPointer(uint64_t directoryTableBase, std::vector<uintptr_t> pKernelPointers);
	static uintptr_t GetKProcess(uintptr_t &directoryTableBase);
	static uintptr_t SearchKProcess(LPCVOID processName, uintptr_t &directoryTableBase, uintptr_t pKProcess);
	static bool ReadPhyMemory( uintptr_t physicalAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead);
	static bool WritePhyMemory( uintptr_t physicalAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);
	static bool CheckProcessHeader(uintptr_t &directoryTableBase, uintptr_t pKProcessAddress);
	static bool ObtainKProcessInfo(uintptr_t &directoryTableBase, uintptr_t pKProcessAddress);


	// Variables
	static HANDLE hDeviceDrv;
	static _fn_memcpy fn_memcpy;
	static _fn_mapPhysical fn_mapPhysical;
	static _fn_unmapPhysical fn_unmapPhysical;
	static uintptr_t DTBTargetProcess;
	static uintptr_t virtualSizeTargetProcess;
	static uintptr_t pBaseAddressTargetProcess;

private:

};