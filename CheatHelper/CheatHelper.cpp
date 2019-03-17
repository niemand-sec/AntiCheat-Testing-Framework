#include "CheatHelper.h"
#include <stdio.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <tchar.h> 
#include <iomanip>

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


// Process Functions
DWORD CheatHelper::GetProcId(const char* procName)
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

// NamedPipe functions
