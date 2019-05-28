#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>

// Kernel offsets
#define OFFSET_IMAGEFILENAME 0x450
#define OFFSET_OBJECTTABLE 0x418

typedef BOOL (*_fn_memcpy)(ULONG64 dest, ULONG64 src, DWORD size);
typedef ULONG64(*_fn_mapPhysical)(DWORDLONG physicaladdress, DWORD size);
typedef ULONG64(*_fn_unmapPhysical)(ULONG64 address);

// Remove padding inside structs
#pragma pack(push, 1) 
typedef struct {
	CHAR  ImageFileName[15];
	DWORD PriorityClass;
} _EPROCESS_PATTERN;

class DriverHelper
{
public:
	static int memmem(PBYTE haystack, DWORD haystack_size, PBYTE needle, DWORD needle_size);
	static int getDeviceHandle(LPTSTR name);
	static unsigned __int64 __fastcall ExpLookupHandleTableEntryW7(__int64 HandleTable, unsigned __int64 handle);
	static unsigned __int64 __fastcall ExpLookupHandleTableEntryW10(__int64 HandleTable, __int64 handle);
	static ULONG64 findPhisical_ObjectTable(DWORDLONG startAddress, DWORDLONG stopAddress, DWORD searchSpace, PBYTE  searchBuffer, DWORD bufferSize);
	static DWORDLONG findPhisical(DWORDLONG startAddress, DWORDLONG stopAddress, DWORD searchSpace, PBYTE  searchBuffer, DWORD bufferSize);
	// Variables
	static HANDLE hDeviceDrv;
	static _fn_memcpy fn_memcpy;
	static _fn_mapPhysical fn_mapPhysical;
	static _fn_unmapPhysical fn_unmapPhysical;

private:

};