#pragma once
#include <windows.h>

#define BUFSIZE 100

typedef LONG(WINAPI *TNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
typedef LONG(WINAPI *TNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG  NumberOfBytesWritten);

class CheatHelper
{
public:
	// WINAPI Functions
	static void Suspend(DWORD processId);
	static void Resume(DWORD processId);
	// Process Functions
	static DWORD GetProcId(const char* procName);
	// Debuging Functions
	static void ConsoleSetup(const char * title);
	static void PrintBytes(PVOID buffer);
	// Memory functions
	static int RPM(HANDLE  hProcess, LPCVOID lpBaseAddress,	LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead);
	static int WPM(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);
	static int NtRVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
	static int NtWVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG  NumberOfBytesWritten);
	//DX functions
	//DX11 functions


};



class NamedPipeHelper
{
public:
	// NamedPipe functions
	int StartPipe(LPTSTR name);
	int ConnectPipe(LPTSTR name);
	PVOID ListenPipe();
	int WritePipe(const char * buffer);
	

private:
	HANDLE hPipeServer;
	HANDLE hNamedPipe;
};


struct PipeMessageRequest {
	int action = 0;
	int handle = 0;
	intptr_t address = 0;
	int size = BUFSIZE;
	char buffer[BUFSIZE] = { "" };
};

struct PipeMessageResponse {
	int status = 0;
	SIZE_T bytesRead= 0;
	char buffer[BUFSIZE] = { "" };
};