// HandleHijackingMaster.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "CheatHelper.h"
#include <iostream>

HANDLE hPipeServer;
HANDLE hProcessOP;
HANDLE hProcessNtOP;
HANDLE hHeap = GetProcessHeap();
void* message = HeapAlloc(hHeap, 0, BUFSIZE);

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* TNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
TNtOpenProcess NtOpenProcess = NULL;

int StartPipe()
{
	//std::string namedPipeName = "\\\\.\\pipe\\driverbypass";
	//LPCSTR namedPipe = namedPipeName.c_str();
	hPipeServer = CreateNamedPipe(CheatHelper::namedPipeName, PIPE_ACCESS_DUPLEX | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
		PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE, 0, NULL);

	if (hPipeServer != NULL)
	{
		std::cout << "[+] NamedPipe created: " << CheatHelper::namedPipeName << std::endl;
	}
	else
	{
		std::cout << "[-] Couldn't create: " << std::dec << GetLastError() << std::endl;
		return 0;
	}

	while (hPipeServer != NULL)
	{
		if (ConnectNamedPipe(hPipeServer, NULL) != FALSE)
		{
			std::cout << "[+] New connection received" << std::endl;
			break;
		}
	}
	return 1;
}

PipeMessageRequest PMRequest;
PipeMessageResponse PMResponse;

int ReadPipe() {
	DWORD dwRead;
	BOOL bRead;
	std::cout << "[+] Waiting for message. " << std::endl;
	
	bRead = ReadFile(hPipeServer, &PMResponse, sizeof(PipeMessageResponse), &dwRead, NULL);

	if (!bRead)
	{
		std::cout << "[-] Failed reading Pipe: " << std::dec << GetLastError() << std::endl;
		return 0;
	}
	else
	{
		std::cout << "\t[+] Status: " << PMResponse.status << std::endl;
		std::cout << "\t[+] bytesRead: " << PMResponse.bytesRead << std::endl;
		std::cout << "\t[+] buffer: ";
		CheatHelper::PrintBytes((PVOID)PMResponse.buffer, PMResponse.bytesRead);
		return 1;
	}
}

int WritePipe()
{

	BOOL bWrite;
	DWORD dwWritten;
	//const char *buffer = "Ready";
	std::cout << "[+] Sending Msg: " << std::endl;
	std::cout << "\t[+] action: "  << PMRequest.action << std::endl;
	std::cout << "\t[+] handle: 0x" << PMRequest.handle << std::endl;
	std::cout << "\t[+] address: 0x" << std::hex << PMRequest.address << std::endl;
	std::cout << "\t[+] size: " << PMRequest.size << std::endl;
	std::cout << "\t[+] buffer: ";
	CheatHelper::PrintBytes((PVOID)PMRequest.buffer, PMRequest.size);
	bWrite = WriteFile(hPipeServer, &PMRequest, sizeof(PipeMessageRequest), &dwWritten, NULL);
	if (!bWrite)
	{
		std::cout << "[-] Failed writing: " << std::dec << GetLastError() << std::endl;
		return 0;
	}
	else
	{
		std::cout << "[+] Success writing." << std::endl;
		return 1;
	}

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

	PMRequest.action = 6;
	CheatHelper::prepareRequest(PMRequest);
	CheatHelper::ZwRVM((HANDLE)handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, NULL);

	PMRequest.action = 7;
	CheatHelper::prepareRequest(PMRequest);
	CheatHelper::ZwWVM((HANDLE)handle, (LPVOID)PMRequest.address, PMRequest.buffer, PMRequest.size, NULL);

}


int main()
{
	CheatHelper::loadConfig();

	// Setting up first action RPM
	//PMRequest.action = 1;
	PMRequest.handle = CheatHelper::requestHandleNP;
	PMRequest.address = 0x0;
	SecureZeroMemory(PMRequest.buffer, BUFSIZE);
	PMRequest.size = 0x0;

	DWORD processID = NULL;
	while (true)
	{
		processID = CheatHelper::GetProcId(CheatHelper::targetProc);
		if (processID != NULL)
		{
			std::cout << "[+] PID: 0x" << std::hex << processID << std::endl;
			break;//
		}
	}

	hProcessOP = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
	if (!hProcessOP) {
		std::cout << "[-] OpenProcess: Unable to obtain handle " << std::dec << GetLastError() << std::endl;
	}
	else
	{
		std::cout << "[+] OpenProcess: 0x" << std::hex << hProcessOP << std::endl;
		//handleTests(hProcessOP);
	}


	if (!StartPipe())
	{
		return 0;
	}

	
	if (!ReadPipe())
	{	
		std::cout << "[-] Failed reading Pipe." << std::endl;
	}

	if (PMResponse.status == 0)
		return 0;
	else
		std::cout << "[+] Cheat ready." << std::endl;

	// Clean PMRequest.address
	PMRequest.address = 0x0;

	int i = 1;
	while (1)
	{
		PMRequest.action = i;

		// We need to set the config values somehow, this is quickest way I found
		CheatHelper::prepareRequest(PMRequest);

		if (!WritePipe())
		{
			std::cout << "[-] Failed writing Pipe." << std::endl;
		}

		if (!ReadPipe())
		{
			std::cout << "[-] Failed reading Pipe." << std::endl;
		}

		if (i == 7)
			break;
		i++;
	}

	
    std::cout << "End!\n"; 
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
