// StealthHijackingNormalDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <iostream>
#include "CheatHelper.h"
#include <windows.h>

#pragma warning(disable:5040)

#define LOCK 0

// EDIT if you modified the original name
TCHAR fileMapName[] = TEXT("Global\\StealthHijacking");

HANDLE hFileMap = NULL;
LPVOID pFileMapMem = NULL;
SIZE_T fileMapSize = FILEMAPSIZE;

PipeMessageRequest PMRequest;
PipeMessageResponse PMResponse;

int ReadFileMapping()
{

	CopyMemory(&PMRequest, (void*)(pFileMapMem), sizeof(PipeMessageRequest));
	std::cout << "[+] Reading Msg: " << std::endl;
	std::cout << "\t[+] action: " << PMRequest.action << std::endl;
	std::cout << "\t[+] handle: 0x" << PMRequest.handle << std::endl;
	std::cout << "\t[+] address: 0x" << std::hex << PMRequest.address << std::endl;
	std::cout << "\t[+] size: " << PMRequest.size << std::endl;
	std::cout << "\t[+] buffer: ";
	CheatHelper::PrintBytes((PVOID)PMRequest.buffer, PMRequest.size);
	return 1;
}


int WriteFileMapping()
{
	SecureZeroMemory(pFileMapMem, FILEMAPSIZE - 1);
	std::cout << "[+] Sending Msg: " << std::endl;
	std::cout << "\t[+] Status: " << PMResponse.status << std::endl;
	std::cout << "\t[+] bytesRead: " << PMResponse.bytesRead << std::endl;
	std::cout << "\t[+] buffer: ";
	CheatHelper::PrintBytes((PVOID)PMResponse.buffer, PMResponse.bytesRead);
	CopyMemory((void*)(pFileMapMem), &PMResponse, sizeof(PipeMessageResponse));
	return true;
}

int handleAction()
{
	switch (PMRequest.action) {
	case 0: //Ping
	{
		std::cout << '0' << std::endl;
		break;
	}
	case 1: //RPM
	{
		std::cout << '1' << std::endl;
		SIZE_T stRead = 0;

		int status = CheatHelper::RPM((HANDLE)PMRequest.handle, (LPCVOID)PMRequest.address, PMResponse.buffer, PMRequest.size, &PMResponse.bytesRead);

		if (status == 0)//SUCCESS
		{
			PMResponse.status = 0;
			return 0;
		}

		PMResponse.status = 1;
		return 1;
	}
	case 2: //WPM
	{
		std::cout << '2' << std::endl;
		SIZE_T stWrite = 0;

		int status = CheatHelper::WPM((HANDLE)PMRequest.handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, &stWrite);

		if (status == 0) //SUCCESS
		{
			PMResponse.status = 0;
			return 0;
		}

		PMResponse.status = 1;
		return 1;
	}
	case 3: //CreatRemoteThread
	{
		std::cout << '3' << std::endl;
		break;
	}
	case 4: //NtReadVirtualMemory
	{
		std::cout << '4' << std::endl;

		auto status = CheatHelper::NtRVM((HANDLE)PMRequest.handle, (LPVOID)PMRequest.address, PMResponse.buffer, PMRequest.size, (PULONG)&PMResponse.bytesRead);

		if (status == 0)
		{
			PMResponse.status = 0;
			return 0;
		}

		PMResponse.status = 1;
		return 1;

	}
	case 5: //NtWriteVirtualMemory
	{
		std::cout << '5' << std::endl;
		SIZE_T stWrite = 0;

		int status = CheatHelper::NtWVM((HANDLE)PMRequest.handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, (PULONG)&stWrite);
		if (status == 0)
		{
			PMResponse.status = 0;
			return 0;
		}

		PMResponse.status = 1;
		return 1;
	}
	case 6: //ZwReadVirtualMemory
	{
		std::cout << '6' << std::endl;

		auto status = CheatHelper::ZwRVM((HANDLE)PMRequest.handle, (LPVOID)PMRequest.address, PMResponse.buffer, PMRequest.size, (PULONG)&PMResponse.bytesRead);

		if (status == 0)
		{
			PMResponse.status = 0;
			return 0;
		}

		PMResponse.status = 1;
		return 1;

	}
	case 7: //ZwWriteVirtualMemory
	{
		std::cout << '7' << std::endl;
		SIZE_T stWrite = 0;

		int status = CheatHelper::ZwWVM((HANDLE)PMRequest.handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, (PULONG)&stWrite);
		if (status == 0)
		{
			PMResponse.status = 0;
			return 0;
		}

		PMResponse.status = 1;
		return 1;
	}
	default:
	{
		std::cout << "Default" << std::endl;
		break;

	}
	}
}

int Init()
{
	
	// UNCOMMENT IF: We need to delay the connection to the Master.
	//Sleep(300000);

	hFileMap = OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, fileMapName);
	if (hFileMap == NULL)
	{
		std::cout << "[-] CreateFileMappingA failed: " << GetLastError() << std::endl;
		return false;
	}
	std::cout << "[+] CreateFileMappingA." << std::endl;
	pFileMapMem = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, fileMapSize);
	if (!pFileMapMem)
	{
		std::cout << "[-] MapViewOfFile failed." << std::endl;
		return false;
	}
	std::cout << "[+] MapViewOfFile." << std::endl;
	
	// Closing handle to go stealthier
	CloseHandle(hFileMap);

	CheatHelper::setSpinLockByte(pFileMapMem, !LOCK);

}


int main() {
	CheatHelper::ConsoleSetup("Client");
	Init();

	while (1)
	{
		CheatHelper::checkSpinLockByte(pFileMapMem, LOCK);

		if (!ReadFileMapping())
		{
			std::cout << "[-] Failed reading." << std::endl;
		}

		int success = handleAction();

		if (!WriteFileMapping())
		{
			std::cout << "[-] Failed writing." << std::endl;
		}

		CheatHelper::setSpinLockByte(pFileMapMem, !LOCK);

		if (PMRequest.action == 7)
		{
			break;
		}
	}

	UnmapViewOfFile(pFileMapMem);

}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, NULL, NULL, NULL);
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



