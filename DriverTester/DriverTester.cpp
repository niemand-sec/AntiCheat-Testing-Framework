// DriverTester.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "CheatHelper.h"
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

DWORD targetPid = NULL;
PipeMessageRequest PMRequest;
PipeMessageResponse PMResponse;

typedef NTSTATUS(WINAPI *fn_NtDeviceIoControlFile)(
	__in HANDLE FileHandle,
	__in HANDLE Event,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in PVOID ApcContext,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__in ULONG IoControlCode,
	__in PVOID InputBuffer,
	__in ULONG InputBufferLength,
	__out PVOID OutputBuffer,
	__in ULONG OutputBufferLength
);

fn_NtDeviceIoControlFile NtDeviceIoControlFileInstance;

struct buffer {
	INT64 pid1;
	INT64 pid2;
} inB, outB;

HANDLE hTarget = NULL;

//char bufferRead[BUFSIZE] = { "" };
//char bufferWrite[BUFSIZE] = { "hell2" };
//SIZE_T bytesRead = 0x4;
//SIZE_T bytesWrite = 0x5;
//intptr_t addressRead = 0x0000000144BC6000;
//intptr_t addressWrite = 0x0000000144BC6000;

bool ExploitRazerDriver() {
	HANDLE hDevice = CreateFile("\\\\.\\47CD78C9-64C3-47C2-B80F-677B887CF095", FILE_SHARE_WRITE | FILE_SHARE_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "INVALID_HANDLE_VALUE! " << GetLastError() << std::endl;
		return 1;
	}

	
	HANDLE targetHandle = NULL;

	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (hNtDll == NULL)
	{
		std::cout << "GetModuleHandleW!\n";
	}

	NtDeviceIoControlFileInstance = (fn_NtDeviceIoControlFile)GetProcAddress(hNtDll, "NtDeviceIoControlFile");

	DWORD returnedBytes = 0; 
	memset(&inB, 0, sizeof(buffer));
	memset(&outB, 0, sizeof(buffer));
	inB.pid1 = targetPid;

	DeviceIoControl(hDevice, 0x22a050, &inB, sizeof(buffer), &outB, sizeof(buffer), &returnedBytes, NULL);
	if (returnedBytes == 0)
	{
		std::cout << "[-] Exploit failed: " << std::hex << GetLastError() << std::endl;
	};

	std::cout << "[+] Target process PID: " << std::hex << outB.pid1 << std::endl;
	std::cout << "[+] Target handle: " << std::hex << outB.pid2 << std::endl;
	hTarget = (HANDLE)outB.pid2;
	return 0;
}



void handleTests(HANDLE handle)
{
	SIZE_T stRead = 0;
	SIZE_T stWrite = 0;

	PMRequest.action = 1;
	CheatHelper::prepareRequest(PMRequest);

	CheatHelper::RPM((HANDLE)handle, (LPCVOID)PMRequest.address, PMResponse.buffer, PMRequest.size, NULL);

	PMRequest.action = 2;
	CheatHelper::prepareRequest(PMRequest);

	CheatHelper::WPM((HANDLE)handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, NULL);

	PMRequest.action = 4;
	CheatHelper::prepareRequest(PMRequest);

	CheatHelper::NtRVM((HANDLE)handle, (LPVOID)PMRequest.address, PMResponse.buffer, PMRequest.size, NULL);


	PMRequest.action = 5;
	CheatHelper::prepareRequest(PMRequest);

	CheatHelper::NtWVM((HANDLE)handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, NULL);

}



int main()
{
	
	std::cout << "Hello World!\n";
	CheatHelper::loadConfig();

	
	while (true)
	{
		targetPid = CheatHelper::GetProcId(CheatHelper::targetProc);
		if (targetPid != NULL)
		{
			std::cout << "[+] PID: 0x" << std::hex << targetPid << std::endl;
			break;//
		}
	}

	PMRequest.address = 0x0;
	SecureZeroMemory(PMRequest.buffer, BUFSIZE - 1);
	PMRequest.size = 0x0;
	// Connecting the vulnerable driver (Razer Senapyse rzpnk.sys ZwOpenProcess - ZwOpenProcess)
	ExploitRazerDriver();

	handleTests(hTarget);
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
