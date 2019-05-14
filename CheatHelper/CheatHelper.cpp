#include "CheatHelper.h"
#include <stdio.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <tchar.h> 
#include <iomanip>


// Check windows
#if _WIN32 || _WIN64
	#if _WIN64
		#define ENV64BIT
	#else
		#define ENV32BIT
	#endif
#endif


// WINAPI Functions

typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);
void CheatHelper::Suspend(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(processHandle);
	CloseHandle(processHandle);
}

typedef LONG(NTAPI *NtResumeProcess)(IN HANDLE ProcessHandle);
void CheatHelper::Resume(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtResumeProcess");

	pfnNtResumeProcess(processHandle);
	CloseHandle(processHandle);
}

//typedef BOOL StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors);
extern "C" NTSTATUS ZwWVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, SIZE_T NumberOfBytesToWrite);
extern "C" NTSTATUS ZwRVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, SIZE_T NumberOfBytesToRead);


// Process Functions
DWORD CheatHelper::GetProcId(char* procName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_stricmp(procEntry.szExeFile, procName))
				{
					procId = procEntry.th32ProcessID;
					std::cout << "[+] Process Found!\n";
					break;
				}
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
	return procId;
}



// DEBUGING functions
void CheatHelper::ConsoleSetup(const char * title)
{
	// With this trick we'll be able to print content to the console, and if we have luck we could get information printed by the game.
	AllocConsole();
	SetConsoleTitle(title);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	freopen("CONIN$", "r", stdin);
}

void CheatHelper::PrintBytes(PVOID buffer)
{
	for (int i = 0; i < sizeof(buffer); i++) {
		std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)((char*)buffer)[i] << " ";
	}
	std::cout << std::endl;
}

// Memory functions
// It will do RPM and print the memory obtained. It will return the buffer value too on the parameter buffer
int CheatHelper::RPM(HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead)
{
	int status = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	if (status == 0)
	{
		std::cout << "[-] ReadProcessMemory failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] ReadProcessMemory: " << lpBuffer << std::endl;
	std::cout << "[+] ReadProcessMemory: ";
	CheatHelper::PrintBytes(lpBuffer);
	return 0;
}

int CheatHelper::WPM(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten)
{
	int status = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	if (status == 0)
	{
		std::cout << "[-] WriteProcessMemory failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] WriteProcessMemory: " << lpBuffer << std::endl;
	std::cout << "[+] WriteProcessMemory: " ;
	CheatHelper::PrintBytes((PVOID)lpBuffer);
	return 0;
}

int CheatHelper::NtRVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	TNtReadVirtualMemory pfnNtReadVirtualMemory = (TNtReadVirtualMemory)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtReadVirtualMemory");

	auto status = pfnNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
	if (status != 0)
	{
		std::cout << "[-] NtReadVirtualMemory failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] NtReadVirtualMemory: " << &Buffer << std::endl;
	std::cout << "[+] NtReadVirtualMemory: ";
	CheatHelper::PrintBytes((PVOID)Buffer);
	return 0;

}

int CheatHelper::NtWVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG  NumberOfBytesWritten)
{
	TNtWriteVirtualMemory pfnNtWriteVirtualMemory = (TNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtWriteVirtualMemory");
	SIZE_T stWrite = 0;

	int status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	if (status != 0)
	{
		std::cout << "[-] NtWriteVirtualMemory Failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] NtWriteVirtualMemory: " << &Buffer << std::endl;
	std::cout << "[+] NtWriteVirtualMemory: ";
	CheatHelper::PrintBytes((PVOID)Buffer);
	return 0;
}


int CheatHelper::ZwRVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead)
{
	auto status = ZwRVM(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead);
	if (status != 0)
	{
		std::cout << "[-] ZwReadVirtualMemory failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] NtReadVirtualMemory: " << &Buffer << std::endl;
	std::cout << "[+] ZwReadVirtualMemory: ";
	CheatHelper::PrintBytes((PVOID)Buffer);
	return 0;

}

int CheatHelper::ZwWVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite)
{
	SIZE_T stWrite = 0;

	int status = ZwWVM(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite);
	if (status != 0)
	{
		std::cout << "[-] ZwWriteVirtualMemory Failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] NtWriteVirtualMemory: " << &Buffer << std::endl;
	std::cout << "[+] ZwWriteVirtualMemory: ";
	CheatHelper::PrintBytes((PVOID)Buffer);
	return 0;
}



// NamedPipe functions



// FileMapping


bool CheatHelper::checkSpinLockByte(LPVOID pFileMapMem, byte value)
{
	//Read last byte to validate if the pivot connected to the shared memory
	//We will use the last byte of the FILEMAP (FILEMAPSIZE-1)
	int n;
	BYTE init = value;
	void * dest = (void *)((intptr_t)pFileMapMem + FILEMAPSIZE - 1);
	std::cout << "[+] Waiting for pivot." << std::endl;
	while (1)
	{
		n = memcmp(dest, &init, sizeof(BYTE));
		if (n == 0)
		{
			std::cout << "[+] Pivot Ready." << std::endl;
			break;
		}
		else
		{
			Sleep(500);
			continue;
		}
	}
	return 0;
}

bool CheatHelper::setSpinLockByte(LPVOID pFileMapMem, byte value)
{
	BYTE init = value;
	void * dest = (void *)((intptr_t)pFileMapMem + FILEMAPSIZE - 1);
	CopyMemory(dest, &init, sizeof(BYTE));
	std::cout << "[+] Ready." << std::endl;
	return 1;
}


void CheatHelper::prepareRequest(PipeMessageRequest &PMRequest)
{
	switch (PMRequest.action) {
	case 0: //Ping
	{
		std::cout << '0' << std::endl;
		break;
	}
	case 1: //RPM
	{
		PMRequest.address = CheatHelper::RPMAddress;
		SecureZeroMemory(PMRequest.buffer, BUFSIZE);
		PMRequest.size = CheatHelper::RPMBufferSize;
		break;
	}
	case 2: //WPM
	{
		PMRequest.address = CheatHelper::WPMAddress;
		strncpy_s(PMRequest.buffer, CheatHelper::WPMBuffer, BUFSIZE);
		PMRequest.size = CheatHelper::WPMBufferSize;
		break;
	}
	case 3: //CreatRemoteThread
	{
		std::cout << "[!] CRThread unavailable." << std::endl;
		break;
	}
	case 4: //NtReadVirtualMemory
	{
		PMRequest.address = CheatHelper::ntRVMAddress;
		SecureZeroMemory(PMRequest.buffer, BUFSIZE);
		PMRequest.size = CheatHelper::ntRVMBufferSize;
		break;
	}
	case 5: //NtWriteVirtualMemory
	{
		PMRequest.address = CheatHelper::ntWVMAddress;
		strncpy_s(PMRequest.buffer, CheatHelper::ntWVMBuffer, BUFSIZE);
		PMRequest.size = CheatHelper::ntWVMBufferSize;
		break;
	}
	}
}


//States
bool CheatHelper::bDelayExecution;

//Addresses
intptr_t CheatHelper::RPMAddressHigh;
intptr_t CheatHelper::RPMAddressLow;
intptr_t CheatHelper::RPMAddress;
intptr_t CheatHelper::WPMAddressHigh;
intptr_t CheatHelper::WPMAddressLow;
intptr_t CheatHelper::WPMAddress;
intptr_t CheatHelper::ntRVMAddressHigh;
intptr_t CheatHelper::ntRVMAddressLow;
intptr_t CheatHelper::ntRVMAddress;
intptr_t CheatHelper::ntWVMAddressHigh;
intptr_t CheatHelper::ntWVMAddressLow;
intptr_t CheatHelper::ntWVMAddress;

//Handles
HANDLE CheatHelper::requestHandleNP = NULL;
HANDLE CheatHelper::requestHandleFM = NULL;



//Buffers
char CheatHelper::RPMBuffer[BUFSIZE];
char CheatHelper::WPMBuffer[BUFSIZE];
char CheatHelper::ntRVMBuffer[BUFSIZE];
char CheatHelper::ntWVMBuffer[BUFSIZE];
SIZE_T CheatHelper::RPMBufferSize;
SIZE_T CheatHelper::WPMBufferSize;
SIZE_T CheatHelper::ntRVMBufferSize;
SIZE_T CheatHelper::ntWVMBufferSize;

//Shared Memory
//LPTSTR CheatHelper::sPipeName;

//Strings
char CheatHelper::targetProc[];
char CheatHelper::namedPipeName[];
char CheatHelper::fileMapName[];

// Configuration file (INI)
bool CheatHelper::loadConfig()
{
	//LPCTSTR configFile = _T(".\\..\\..\\config.ini");
	LPCTSTR configFile = _T("F:\\Recon2019\\AntiCheat-Testing-Framework\\config.ini");

	//States
	CheatHelper::bDelayExecution = (bool)GetPrivateProfileInt("Addresses", "bDelayExecution", 0, configFile);
	std::cout << "[.] bDelayExecution " << std::hex << CheatHelper::bDelayExecution << std::endl;

	//Addresses
	#if defined(ENV64BIT)
		// GetPrivateProfileInt does not allow to obtain int64 values, we need this for x64 processes
		CheatHelper::RPMAddressHigh = GetPrivateProfileInt("Addresses", "RPMAddressHigh", 0x0, configFile);
		CheatHelper::RPMAddressLow = GetPrivateProfileInt("Addresses", "RPMAddressLow", 0x0, configFile);
		CheatHelper::WPMAddressHigh = GetPrivateProfileInt("Addresses", "WPMAddressHigh", 0x0, configFile);
		CheatHelper::WPMAddressLow = GetPrivateProfileInt("Addresses", "WPMAddressLow", 0x0, configFile);
		CheatHelper::ntRVMAddressHigh = GetPrivateProfileInt("Addresses", "ntRVMAddressHigh", 0x0, configFile);
		CheatHelper::ntRVMAddressLow = GetPrivateProfileInt("Addresses", "ntRVMAddressLow", 0x0, configFile);
		CheatHelper::ntWVMAddressHigh = GetPrivateProfileInt("Addresses", "ntWVMAddressHigh", 0x0, configFile);
		CheatHelper::ntWVMAddressLow = GetPrivateProfileInt("Addresses", "ntWVMAddressLow", 0x0, configFile);

		CheatHelper::RPMAddress = CheatHelper::RPMAddressHigh << 32 | CheatHelper::RPMAddressLow;
		CheatHelper::WPMAddress = CheatHelper::WPMAddressHigh << 32 | CheatHelper::WPMAddressLow;
		CheatHelper::ntRVMAddress = CheatHelper::ntRVMAddressHigh << 32 | CheatHelper::ntRVMAddressLow;
		CheatHelper::ntWVMAddress = CheatHelper::ntWVMAddressHigh << 32 | CheatHelper::ntWVMAddressLow;


	#elif defined (ENV32BIT)
		CheatHelper::RPMAddress = GetPrivateProfileStruct("Addresses", "RPMAddress", (LPVOID)CheatHelper::RPMAddress, 0x8, configFile);
		CheatHelper::WPMAddress = GetPrivateProfileInt("Addresses", "WPMAddress", 0x0, configFile);
		CheatHelper::ntRVMAddress = GetPrivateProfileInt("Addresses", "ntRVMAddress", 0x0, configFile);
		CheatHelper::ntWVMAddress = GetPrivateProfileInt("Addresses", "ntWVMAddress", 0x0, configFile);
	#endif


	std::cout << "[.] RPMAddress 0x" << std::hex << CheatHelper::RPMAddress << std::endl;
	std::cout << "[.] WPMAddress 0x" << std::hex << CheatHelper::WPMAddress << std::endl;
	std::cout << "[.] ntRVMAddress 0x" << std::hex << CheatHelper::ntRVMAddress << std::endl;
	std::cout << "[.] ntWVMAddress 0x" << std::hex << CheatHelper::ntWVMAddress << std::endl;


	//Handles
	CheatHelper::requestHandleNP = (HANDLE)GetPrivateProfileInt("Handles", "requestHandleNP", 0x0, configFile);
	CheatHelper::requestHandleFM = (HANDLE)GetPrivateProfileInt("Handles", "requestHandleFM", 0x0, configFile);
	std::cout << "[.] requestHandleNP 0x" << std::hex << CheatHelper::requestHandleNP << std::endl;
	std::cout << "[.] requestHandleFM 0x" << std::hex << CheatHelper::requestHandleFM << std::endl;


	//Buffers
	
	CheatHelper::RPMBufferSize = GetPrivateProfileInt("Buffers", "RPMBufferSize", BUFSIZE, configFile);
	CheatHelper::WPMBufferSize = GetPrivateProfileInt("Buffers", "WPMBufferSize", BUFSIZE, configFile);
	CheatHelper::ntRVMBufferSize = GetPrivateProfileInt("Buffers", "ntRVMBufferSize", BUFSIZE, configFile);
	CheatHelper::ntWVMBufferSize = GetPrivateProfileInt("Buffers", "ntWVMBufferSize", BUFSIZE, configFile);

	std::cout << "[.] RPMBufferSize 0x" << std::hex << CheatHelper::RPMBufferSize << std::endl;
	std::cout << "[.] WPMBufferSize 0x" << std::hex << CheatHelper::WPMBufferSize << std::endl;
	std::cout << "[.] ntRVMBufferSize 0x" << std::hex << CheatHelper::ntRVMBufferSize << std::endl;
	std::cout << "[.] ntWVMBufferSize 0x" << std::hex << CheatHelper::ntWVMBufferSize << std::endl;

	SecureZeroMemory(CheatHelper::RPMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::WPMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::ntRVMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::ntWVMBuffer, BUFSIZE);


	GetPrivateProfileString("Buffers", "RPMBuffer", "calc.exe", CheatHelper::RPMBuffer, CheatHelper::RPMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "WPMBuffer", "calc.exe", CheatHelper::WPMBuffer, CheatHelper::WPMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "ntRVMBuffer", "calc.exe", CheatHelper::ntRVMBuffer, CheatHelper::ntRVMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "ntWVMBuffer", "calc.exe", CheatHelper::ntWVMBuffer, CheatHelper::ntWVMBufferSize, configFile);
	
	std::cout << "[.] RPMBuffer " << CheatHelper::RPMBuffer << std::endl;
	std::cout << "[.] WPMBuffer " << CheatHelper::WPMBuffer << std::endl;
	std::cout << "[.] WPMBuffer " << CheatHelper::ntRVMBuffer << std::endl;
	std::cout << "[.] WPMBuffer " << CheatHelper::ntWVMBuffer << std::endl;

	//Shared Memory
	//GetPrivateProfileString("SharedMemory", "sPipeName", "calc.exe", CheatHelper::sPipeName, BUFSIZE, configFile);
//	std::cout << "[.] sPipeName " << CheatHelper::sPipeName << std::endl;

	//Strings
	GetPrivateProfileString("Strings", "targetProc", "calc2.exe", CheatHelper::targetProc, BUFSIZE, configFile);
	GetPrivateProfileString("Strings", "namedPipeName", "calc.exe", CheatHelper::namedPipeName, BUFSIZE, configFile);
	GetPrivateProfileString("Strings", "fileMapName", "calc.exe", CheatHelper::fileMapName, BUFSIZE, configFile);

	std::cout << "[.] targetProc " << CheatHelper::targetProc << std::endl;
	std::cout << "[.] namedPipeName " << CheatHelper::namedPipeName << std::endl;
	std::cout << "[.] fileMapName " << CheatHelper::fileMapName << std::endl;

	return 0;
}