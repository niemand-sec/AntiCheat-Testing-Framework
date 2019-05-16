// HandleHijackingDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "CheatHelper.h"
#include <windows.h> 
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <string>
#include <iostream>

// EDIT if you modified the original name
char tmp[] = "\\\\.\\pipe\\driverbypass";


HANDLE hNamedPipe;
PipeMessageRequest PMRequest;
PipeMessageResponse PMResponse;

int ConnectPipe(LPTSTR name)
{

	hNamedPipe = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL);

	while (1)
	{
		if (hNamedPipe != INVALID_HANDLE_VALUE)
		{
			std::cout << "[+] Connected." << std::endl;
			break;
		}
		else
		{
			std::cout << "[-] Couldn't connect: " << std::dec << GetLastError() << std::endl;
			continue;
		}
	}
	return 0;
}

int WritePipe(struct PipeMessageResponse response)
{

	BOOL bWrite;
	DWORD dwWritten;
	//const char *buffer = "Ready";
	std::cout << "[+] Sending Msg: " << std::endl;
	std::cout << "\t[+] status: " << response.status << std::endl;
	std::cout << "\t[+] bytesRead: " << response.bytesRead << std::endl;
	std::cout << "\t[+] buffer: ";
	CheatHelper::PrintBytes((PVOID)response.buffer);
	bWrite = WriteFile(hNamedPipe, &response, sizeof(PipeMessageResponse), &dwWritten, NULL);
	if (!bWrite)
	{
		std::cout << "[-] Failed writing: " << std::dec << GetLastError() << std::endl;
		return 0;
	}
	else
	{
		std::cout << "\t[+] Success writing." << std::endl;
		return 1;
	}

}


int ReadPipe() {
	//HANDLE hHeap = GetProcessHeap();
	//void* message = HeapAlloc(hHeap, 0, BUFSIZE);
	//message = HeapAlloc(hHeap, 0, BUFSIZE);
	DWORD dwRead;
	BOOL bRead;
	std::cout << "[+] Waiting for message. " << std::endl;

	bRead = ReadFile(hNamedPipe, &PMRequest, sizeof(PipeMessageRequest), &dwRead, NULL);

	if (!bRead)
	{
		std::cout << "[-] Failed reading Pipe: " << std::dec << GetLastError() << std::endl;
		return 0;
	}
	else
	{
		std::cout << "\t[+] action: " << PMRequest.action << std::endl;
		std::cout << "\t[+] handle: 0x" << PMRequest.handle << std::endl;
		std::cout << "\t[+] address: 0x" << PMRequest.address << std::endl;
		std::cout << "\t[+] size: " << PMRequest.size << std::endl;
		std::cout << "\t[+] buffer: ";
		CheatHelper::PrintBytes((PVOID)PMRequest.buffer);
		return 1;
	}
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




int main() {

	// UNCOMMENT IF: We need to delay the connection to the Master.
	//Sleep(300000);

	strncpy_s(CheatHelper::namedPipeName, tmp, _countof(tmp));

	CheatHelper::ConsoleSetup("Client");

	ConnectPipe(CheatHelper::namedPipeName);


	PMResponse.status = 1;

	WritePipe(PMResponse);

	while (1)
	{
		ReadPipe();


		//int handle = 0xBF8;
		//LPVOID buffer;
		//TODO: Add loop and reconnection
		int success = handleAction();

		
		WritePipe(PMResponse);

		// if it is the last possible action -> break
		if (PMRequest.action == 7)
		{
			break;
		}
		
	}

	
	
	
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



