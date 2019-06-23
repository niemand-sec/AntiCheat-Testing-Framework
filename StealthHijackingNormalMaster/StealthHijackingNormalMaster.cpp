// StealthHijackingNormalMaster.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "CheatHelper.h"
#include <windows.h>

#pragma warning(disable:5040)
#define LOCK 1 


std::string fileMapName = "";
HANDLE hFileMap = NULL;
HANDLE hTargetProcess = NULL;
HANDLE hExplorerProcess = NULL;
LPVOID pFileMapMem = NULL;
SIZE_T fileMapSize = FILEMAPSIZE;


PipeMessageRequest PMRequest;
PipeMessageResponse PMResponse;

int ReadFileMapping()
{
	CopyMemory(&PMResponse, (void*)(pFileMapMem), sizeof(PipeMessageResponse));
	if (PMResponse.status == 0)
	{
		std::cout << "\t[+] Status: Successful" << std::endl;
	}
	else
	{
		std::cout << "\t[-] Status: Unsuccessful" << std::endl;
	}
	//std::cout << "\t[+] bytesRead: " << PMResponse.bytesRead << std::endl;
	//std::cout << "\t[+] buffer: ";
	//CheatHelper::PrintBytes((PVOID)PMResponse.buffer, (SIZE_T)PMResponse.bytesRead);
	return 1;
}


int WriteFileMapping()
{
	SecureZeroMemory(pFileMapMem, FILEMAPSIZE - 1);
	std::cout << "[+] Sending Msg: " << std::endl;
	std::cout << "\t[+] action: " << PMRequest.action << std::endl;
	std::cout << "\t[+] handle: 0x" << PMRequest.handle << std::endl;
	std::cout << "\t[+] address: 0x" << std::hex << PMRequest.address << std::endl;
	std::cout << "\t[+] size: " << PMRequest.size << std::endl;
	std::cout << "\t[+] buffer: ";
	CheatHelper::PrintBytes((PVOID)PMRequest.buffer, (SIZE_T)PMRequest.size);
	CopyMemory((void*)(pFileMapMem), &PMRequest, sizeof(PipeMessageRequest));
	return true;
}


bool Init()
{
	CheatHelper::loadConfig();

	//fileMapName = "Global\\StealthHijacking";
	hFileMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT | SEC_NOCACHE, 0, (DWORD)fileMapSize, CheatHelper::fileMapName);
	if (!hFileMap)
	{
		std::cout << "[-] CreateFileMappingA failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	std::cout << "[+] CreateFileMappingA." << std::endl;
	pFileMapMem = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, fileMapSize);
	if (!pFileMapMem)
	{
		std::cout << "[-] MapViewOfFile failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	std::cout << "[+] MapViewOfFile." << std::endl;

	CheatHelper::checkSpinLockByte(pFileMapMem, LOCK);

	return 0;
}





int main()
{
	std::cout << "[+] Init\n";


	if (!Init())
	{

		//PMRequest.action = 1;
		//PMRequest.handle = (HANDLE)0xC32;
		//PMRequest.address = 0x0000000144BC6000;
		//strncpy_s(PMRequest.buffer, "ABCD3", BUFSIZE);
		//PMRequest.size = sizeof(PMRequest.buffer);

		PMRequest.handle = CheatHelper::requestHandleNP;
		PMRequest.address = 0x0;
		SecureZeroMemory(PMRequest.buffer, BUFSIZE-1);
		PMRequest.size = 0x0;


		int i = 1;
		while (1)
		{
			PMRequest.action = i;

			CheatHelper::prepareRequest(PMRequest);

			CheatHelper::checkSpinLockByte(pFileMapMem, LOCK);

			if (!WriteFileMapping())
			{
				std::cout << "[-] Failed writing." << std::endl;
			}


			CheatHelper::setSpinLockByte(pFileMapMem, !LOCK);
			CheatHelper::checkSpinLockByte(pFileMapMem, LOCK);

			if (!ReadFileMapping())
			{
				std::cout << "[-] Failed reading." << std::endl;
			}

			if (i == 7)
				break;
			i++;
		}
		CloseHandle(hFileMap);
		UnmapViewOfFile(pFileMapMem);
	}
	Sleep(1000000);
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
