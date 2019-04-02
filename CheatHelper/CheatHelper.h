#pragma once
#include <windows.h>
#include <iostream>

#define BUFSIZE 100
#define FILEMAPSIZE 4096

typedef LONG(WINAPI *TNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
typedef LONG(WINAPI *TNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG  NumberOfBytesWritten);


struct PipeMessageRequest {
	int action = 0;
	HANDLE handle = 0;
	intptr_t address = 0;
	int size = BUFSIZE;
	char buffer[BUFSIZE] = { "" };
};

struct PipeMessageResponse {
	int status = 0;
	SIZE_T bytesRead = 0;
	char buffer[BUFSIZE] = { "" };
};

class CheatHelper
{
public:
	// WINAPI Functions
	static void Suspend(DWORD processId);
	static void Resume(DWORD processId);
	// Process Functions
	static DWORD GetProcId(char* procName);
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

	//FileMapping
	static bool checkSpinLockByte(LPVOID pFileMapMem, BYTE value);
	static bool setSpinLockByte(LPVOID pFileMapMem, BYTE value);
	static void prepareRequest(PipeMessageRequest &PMRequest);

	// Configuration file (INI)
	static bool loadConfig();

	//States
	static bool bDelayExecution;


	//Addresses
	static intptr_t RPMAddressHigh;
	static intptr_t RPMAddressLow;
	static intptr_t RPMAddress;
	static intptr_t WPMAddressHigh;
	static intptr_t WPMAddressLow;
	static intptr_t WPMAddress;
	static intptr_t ntRVMAddress;
	static intptr_t ntRVMAddressHigh;
	static intptr_t ntRVMAddressLow;
	static intptr_t ntWVMAddress;
	static intptr_t ntWVMAddressHigh;
	static intptr_t ntWVMAddressLow;

	//Handles
	static HANDLE requestHandleNP;
	static HANDLE requestHandleFM;



	//Buffers
	static char RPMBuffer[BUFSIZE];
	static char WPMBuffer[BUFSIZE];
	static char ntRVMBuffer[BUFSIZE];
	static char ntWVMBuffer[BUFSIZE];
	static SIZE_T RPMBufferSize;
	static SIZE_T WPMBufferSize;
	static SIZE_T ntRVMBufferSize;
	static SIZE_T ntWVMBufferSize;

	//Shared Memory
	//static LPCSTR sPipeName;

	//Strings
	static char targetProc[BUFSIZE];
	static char namedPipeName[BUFSIZE];
	static char fileMapName[BUFSIZE];


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

