# CheatHelper

## Introduction


## Usage

This module provides all key features required by a cheat in order to interact with the Windows API, Memory, NamedPipes and FileMapping.

## Key Features

Class NamedPipeHelper will provide assistance for NamedPipe interaction.

Class CheatHelper will provide the following method:

- WINAPI Functions
  - static void Suspend(DWORD processId);
  - static void Resume(DWORD processId);
- Process Functions
  - static DWORD GetProcId(char* procName);
  - Debuging Functions
  - static void ConsoleSetup(const char * title);
  - static void PrintBytes(PVOID buffer, SIZE_T  nSize);
- Memory functions
  - static int RPM(HANDLE  hProcess, LPCVOID lpBaseAddress,	LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead);
  - static int WPM(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);
  - static int NtRVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
  - static int NtWVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG  NumberOfBytesWritten);
  - static int ZwRVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
  - static int ZwWVM(HANDLE hProc, PVOID pBaseAddress, PVOID pBuffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
- FileMapping
  - static bool checkSpinLockByte(LPVOID pFileMapMem, BYTE value);
  - static bool setSpinLockByte(LPVOID pFileMapMem, BYTE value);
  - static void prepareRequest(PipeMessageRequest &PMRequest);
  - Configuration file (INI)
  - static bool loadConfig();

