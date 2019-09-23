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
extern "C" NTSTATUS ZwWriteVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
extern "C" NTSTATUS ZwReadVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);


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

void CheatHelper::PrintBytes(PVOID buffer, SIZE_T  nSize)
{
	/*
	for (int i = 0; i < sizeof(buffer); i++) {
		std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)((char*)buffer)[i] << " ";
	}
	std::cout << std::endl;
	*/
	/*
	printf("[ ");
	for (size_t i = 0; i < sizeof(buffer); i++)
	{
		printf("%02x ", ((char*)buffer)[i]);
	}
	printf("]\n");
	*/
	UCHAR * uBuf = (UCHAR*)buffer;
	for (uint32_t i = 0; i != nSize; i++)
	{
		std::cout <<
			std::hex <<           // output in hex
			std::setw(2) <<       // each byte prints as two characters
			static_cast<unsigned int>(uBuf[i]) << " ";
			std::setfill('0'); // fill with 0 if not enough characters
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
	std::cout << "[+] ReadProcessMemory: \n\t";
	CheatHelper::PrintBytes((PVOID)lpBuffer, nSize);
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
	std::cout << "[+] WriteProcessMemory: \n\t" ;
	CheatHelper::PrintBytes((PVOID)lpBuffer, nSize);
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
	std::cout << "[+] NtReadVirtualMemory: \n\t";
	CheatHelper::PrintBytes((PVOID)Buffer, NumberOfBytesToRead);
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
	std::cout << "[+] NtWriteVirtualMemory: \n\t";
	CheatHelper::PrintBytes((PVOID)Buffer, NumberOfBytesToWrite);
	return 0;
}


int CheatHelper::ZwRVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded = NULL)
{
	auto status = ZwReadVM(hProc, pBaseAddress, pBuffer, NumberOfBytesToRead, NumberOfBytesReaded);
	if (status != 0)
	{
		std::cout << "[-] ZwReadVirtualMemory failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] NtReadVirtualMemory: " << &Buffer << std::endl;
	std::cout << "[+] ZwReadVirtualMemory: \n\t";
	CheatHelper::PrintBytes((PVOID)pBuffer, NumberOfBytesToRead);
	return 0;

}

int CheatHelper::ZwWVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten = NULL)
{
	//SIZE_T stWrite = 0;

	int status = ZwWriteVM(hProc, pBaseAddress, pBuffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	if (status != 0)
	{
		std::cout << "[-] ZwWriteVirtualMemory Failed: " << std::dec << GetLastError() << std::endl;
		return 1;
	}
	//std::cout << "[+] NtWriteVirtualMemory: " << &Buffer << std::endl;
	std::cout << "[+] ZwWriteVirtualMemory: \n\t";
	CheatHelper::PrintBytes((PVOID)pBuffer, NumberOfBytesToWrite);
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
		std::cout << "[+] RPM" << std::endl;
		PMRequest.address = CheatHelper::RPMAddress;
		SecureZeroMemory(PMRequest.buffer, BUFSIZE);
		PMRequest.size = (int)CheatHelper::RPMBufferSize;
		break;
	}
	case 2: //WPM
	{
		std::cout << "[+] WPM" << std::endl;
		PMRequest.address = CheatHelper::WPMAddress;
		strncpy_s(PMRequest.buffer, CheatHelper::WPMBuffer, BUFSIZE);
		PMRequest.size = (int)CheatHelper::WPMBufferSize;
		break;
	}
	case 3: //CreatRemoteThread
	{
		std::cout << "[!] CRThread unavailable." << std::endl;
		break;
	}
	case 4: //NtReadVirtualMemory
	{
		std::cout << "[+] NtReadVirtualMemory" << std::endl;
		PMRequest.address = CheatHelper::ntRVMAddress;
		SecureZeroMemory(PMRequest.buffer, BUFSIZE);
		PMRequest.size = (int)CheatHelper::ntRVMBufferSize;
		break;
	}
	case 5: //NtWriteVirtualMemory
	{
		std::cout << "[+] NtWriteVirtualMemory" << std::endl;
		PMRequest.address = CheatHelper::ntWVMAddress;
		strncpy_s(PMRequest.buffer, CheatHelper::ntWVMBuffer, BUFSIZE);
		PMRequest.size = (int)CheatHelper::ntWVMBufferSize;
		break;
	}
	case 6: //ZwReadVirtualMemory
	{
		std::cout << "[+] ZwReadVirtualMemory" << std::endl;
		PMRequest.address = CheatHelper::ZwRVMAddress;
		SecureZeroMemory(PMRequest.buffer, BUFSIZE);
		PMRequest.size = (int)CheatHelper::ZwRVMBufferSize;
		break;
	}
	case 7: //ZwWriteVirtualMemory
	{
		std::cout << "[+] ZwWriteVirtualMemory" << std::endl;
		PMRequest.address = CheatHelper::ZwWVMAddress;
		strncpy_s(PMRequest.buffer, CheatHelper::ZwWVMBuffer, BUFSIZE);
		PMRequest.size = (int)CheatHelper::ZwWVMBufferSize;
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
intptr_t CheatHelper::ZwRVMAddressHigh;
intptr_t CheatHelper::ZwRVMAddressLow;
intptr_t CheatHelper::ZwRVMAddress;
intptr_t CheatHelper::ZwWVMAddressHigh;
intptr_t CheatHelper::ZwWVMAddressLow;
intptr_t CheatHelper::ZwWVMAddress;

DWORDLONG CheatHelper::startAddressPhyHigh;
DWORDLONG CheatHelper::startAddressPhyLow;
DWORDLONG CheatHelper::startAddressPhy;

//Handles
HANDLE CheatHelper::requestHandleNP = NULL;
HANDLE CheatHelper::requestHandleFM = NULL;
HANDLE CheatHelper::requestHandleDrv = NULL;



//Buffers
char CheatHelper::RPMBuffer[BUFSIZE];
char CheatHelper::WPMBuffer[BUFSIZE];
char CheatHelper::ntRVMBuffer[BUFSIZE];
char CheatHelper::ntWVMBuffer[BUFSIZE];
char CheatHelper::ZwRVMBuffer[BUFSIZE];
char CheatHelper::ZwWVMBuffer[BUFSIZE];
SIZE_T CheatHelper::RPMBufferSize;
SIZE_T CheatHelper::WPMBufferSize;
SIZE_T CheatHelper::ntRVMBufferSize;
SIZE_T CheatHelper::ntWVMBufferSize;
SIZE_T CheatHelper::ZwRVMBufferSize;
SIZE_T CheatHelper::ZwWVMBufferSize;

//Shared Memory
//LPTSTR CheatHelper::sPipeName;

//Strings
char CheatHelper::targetProc[];
char CheatHelper::privotProc[];
char CheatHelper::namedPipeName[];
char CheatHelper::fileMapName[];
char CheatHelper::driverName[];

// Configuration file (INI)
bool CheatHelper::loadConfig()
{
	//LPCTSTR configFile = _T(".\\..\\..\\config.ini");
	LPCTSTR configFile = _T("E:\\Recon2019\\AntiCheat-Testing-Framework-Private\\config.ini");
	std::cout << "[+] Reading config file." << std::endl;

	//States
	CheatHelper::bDelayExecution = (bool)GetPrivateProfileInt("Addresses", "bDelayExecution", 0, configFile);
	std::cout << "\t[.] bDelayExecution " << std::hex << CheatHelper::bDelayExecution << std::endl;

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
		CheatHelper::ZwRVMAddressHigh = GetPrivateProfileInt("Addresses", "ZwRVMAddressHigh", 0x0, configFile);
		CheatHelper::ZwRVMAddressLow = GetPrivateProfileInt("Addresses", "ZwRVMAddressLow", 0x0, configFile);
		CheatHelper::ZwWVMAddressHigh = GetPrivateProfileInt("Addresses", "ZwWVMAddressHigh", 0x0, configFile);
		CheatHelper::ZwWVMAddressLow = GetPrivateProfileInt("Addresses", "ZwWVMAddressLow", 0x0, configFile);
		CheatHelper::startAddressPhyHigh = GetPrivateProfileInt("Addresses", "startAddressPhyHigh", 0x0, configFile);
		CheatHelper::startAddressPhyLow = GetPrivateProfileInt("Addresses", "startAddressPhyLow", 0x0, configFile);

		CheatHelper::RPMAddress = CheatHelper::RPMAddressHigh << 32 | CheatHelper::RPMAddressLow;
		CheatHelper::WPMAddress = CheatHelper::WPMAddressHigh << 32 | CheatHelper::WPMAddressLow;
		CheatHelper::ntRVMAddress = CheatHelper::ntRVMAddressHigh << 32 | CheatHelper::ntRVMAddressLow;
		CheatHelper::ntWVMAddress = CheatHelper::ntWVMAddressHigh << 32 | CheatHelper::ntWVMAddressLow;
		CheatHelper::ZwRVMAddress = CheatHelper::ZwRVMAddressHigh << 32 | CheatHelper::ZwRVMAddressLow;
		CheatHelper::ZwWVMAddress = CheatHelper::ZwWVMAddressHigh << 32 | CheatHelper::ZwWVMAddressLow;
		CheatHelper::startAddressPhy = CheatHelper::startAddressPhyHigh << 32 | CheatHelper::startAddressPhyLow;


	#elif defined (ENV32BIT)
		CheatHelper::RPMAddress = GetPrivateProfileStruct("Addresses", "RPMAddress", (LPVOID)CheatHelper::RPMAddress, 0x8, configFile);
		CheatHelper::WPMAddress = GetPrivateProfileInt("Addresses", "WPMAddress", 0x0, configFile);
		CheatHelper::ntRVMAddress = GetPrivateProfileInt("Addresses", "ntRVMAddress", 0x0, configFile);
		CheatHelper::ntWVMAddress = GetPrivateProfileInt("Addresses", "ntWVMAddress", 0x0, configFile);
		CheatHelper::ZwRVMAddress = GetPrivateProfileInt("Addresses", "ZwRVMAddress", 0x0, configFile);
		CheatHelper::ZwWVMAddress = GetPrivateProfileInt("Addresses", "ZwWVMAddress", 0x0, configFile);
		CheatHelper::startAddressPhy = GetPrivateProfileInt("Addresses", "startAddressPhy", 0x0, configFile);
#endif


	std::cout << "\t[.] RPMAddress 0x" << std::hex << CheatHelper::RPMAddress << std::endl;
	std::cout << "\t[.] WPMAddress 0x" << std::hex << CheatHelper::WPMAddress << std::endl;
	std::cout << "\t[.] ntRVMAddress 0x" << std::hex << CheatHelper::ntRVMAddress << std::endl;
	std::cout << "\t[.] ntWVMAddress 0x" << std::hex << CheatHelper::ntWVMAddress << std::endl;
	std::cout << "\t[.] ZwRVMAddress 0x" << std::hex << CheatHelper::ZwRVMAddress << std::endl;
	std::cout << "\t[.] ZwWVMAddress 0x" << std::hex << CheatHelper::ZwWVMAddress << std::endl;
	std::cout << "\t[.] startAddressPhy 0x" << std::hex << CheatHelper::startAddressPhy << std::endl;


	//Handles
	CheatHelper::requestHandleNP = (HANDLE)GetPrivateProfileInt("Handles", "requestHandleNP", 0x0, configFile);
	CheatHelper::requestHandleFM = (HANDLE)GetPrivateProfileInt("Handles", "requestHandleFM", 0x0, configFile);
	CheatHelper::requestHandleDrv = (HANDLE)GetPrivateProfileInt("Handles", "requestHandleDrv", 0x0, configFile);
	std::cout << "\t[.] requestHandleNP 0x" << std::hex << CheatHelper::requestHandleNP << std::endl;
	std::cout << "\t[.] requestHandleFM 0x" << std::hex << CheatHelper::requestHandleFM << std::endl;
	std::cout << "\t[.] requestHandleDrv 0x" << std::hex << CheatHelper::requestHandleDrv << std::endl;


	//Buffers
	
	CheatHelper::RPMBufferSize = GetPrivateProfileInt("Buffers", "RPMBufferSize", BUFSIZE, configFile);
	CheatHelper::WPMBufferSize = GetPrivateProfileInt("Buffers", "WPMBufferSize", BUFSIZE, configFile);
	CheatHelper::ntRVMBufferSize = GetPrivateProfileInt("Buffers", "ntRVMBufferSize", BUFSIZE, configFile);
	CheatHelper::ntWVMBufferSize = GetPrivateProfileInt("Buffers", "ntWVMBufferSize", BUFSIZE, configFile);
	CheatHelper::ZwRVMBufferSize = GetPrivateProfileInt("Buffers", "ZwRVMBufferSize", BUFSIZE, configFile);
	CheatHelper::ZwWVMBufferSize = GetPrivateProfileInt("Buffers", "ZwWVMBufferSize", BUFSIZE, configFile);

	std::cout << "\t[.] RPMBufferSize 0x" << std::hex << CheatHelper::RPMBufferSize << std::endl;
	std::cout << "\t[.] WPMBufferSize 0x" << std::hex << CheatHelper::WPMBufferSize << std::endl;
	std::cout << "\t[.] ntRVMBufferSize 0x" << std::hex << CheatHelper::ntRVMBufferSize << std::endl;
	std::cout << "\t[.] ntWVMBufferSize 0x" << std::hex << CheatHelper::ntWVMBufferSize << std::endl;
	std::cout << "\t[.] ZwRVMBufferSize 0x" << std::hex << CheatHelper::ZwRVMBufferSize << std::endl;
	std::cout << "\t[.] ZwWVMBufferSize 0x" << std::hex << CheatHelper::ZwWVMBufferSize << std::endl;

	SecureZeroMemory(CheatHelper::RPMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::WPMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::ntRVMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::ntWVMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::ZwRVMBuffer, BUFSIZE);
	SecureZeroMemory(CheatHelper::ZwWVMBuffer, BUFSIZE);


	GetPrivateProfileString("Buffers", "RPMBuffer", "calc.exe", CheatHelper::RPMBuffer, (DWORD)CheatHelper::RPMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "WPMBuffer", "calc.exe", CheatHelper::WPMBuffer, (DWORD)CheatHelper::WPMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "ntRVMBuffer", "calc.exe", CheatHelper::ntRVMBuffer, (DWORD)CheatHelper::ntRVMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "ntWVMBuffer", "calc.exe", CheatHelper::ntWVMBuffer, (DWORD)CheatHelper::ntWVMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "ZwRVMBuffer", "calc.exe", CheatHelper::ZwRVMBuffer, (DWORD)CheatHelper::ZwRVMBufferSize, configFile);
	GetPrivateProfileString("Buffers", "ZwWVMBuffer", "calc.exe", CheatHelper::ZwWVMBuffer, (DWORD)CheatHelper::ZwWVMBufferSize, configFile);
	
	std::cout << "\t[.] RPMBuffer " << CheatHelper::RPMBuffer << std::endl;
	std::cout << "\t[.] WPMBuffer " << CheatHelper::WPMBuffer << std::endl;
	std::cout << "\t[.] ntWPMBuffer " << CheatHelper::ntRVMBuffer << std::endl;
	std::cout << "\t[.] ntWPMBuffer " << CheatHelper::ntWVMBuffer << std::endl;
	std::cout << "\t[.] ZwRPMBuffer " << CheatHelper::ZwRVMBuffer << std::endl;
	std::cout << "\t[.] ZwWPMBuffer " << CheatHelper::ZwWVMBuffer << std::endl;

	//Shared Memory
	//GetPrivateProfileString("SharedMemory", "sPipeName", "calc.exe", CheatHelper::sPipeName, BUFSIZE, configFile);
//	std::cout << "[.] sPipeName " << CheatHelper::sPipeName << std::endl;

	//Strings
	GetPrivateProfileString("Strings", "targetProc", "calc2.exe", CheatHelper::targetProc, BUFSIZE, configFile);
	GetPrivateProfileString("Strings", "privotProc", "calc2.exe", CheatHelper::privotProc, BUFSIZE, configFile);
	GetPrivateProfileString("Strings", "namedPipeName", "\\.\\pipe\\driverbypass", CheatHelper::namedPipeName, BUFSIZE, configFile);
	GetPrivateProfileString("Strings", "fileMapName", "Global\StealthHijacking", CheatHelper::fileMapName, BUFSIZE, configFile);
	GetPrivateProfileString("Strings", "driverName", "\\.\\GIO", CheatHelper::driverName, BUFSIZE, configFile);

	std::cout << "\t[.] targetProc " << CheatHelper::targetProc << std::endl;
	std::cout << "\t[.] privotProc " << CheatHelper::privotProc << std::endl;
	std::cout << "\t[.] namedPipeName " << CheatHelper::namedPipeName << std::endl;
	std::cout << "\t[.] fileMapName " << CheatHelper::fileMapName << std::endl;
	std::cout << "\t[.] driverName " << CheatHelper::driverName << std::endl;

	return 0;
}