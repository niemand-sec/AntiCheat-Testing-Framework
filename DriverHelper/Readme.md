# DriverHelper

## Introduction


## Usage

This module provides all key features required to exploit and communicate with a Driver.

## Key Features

Class DriverHelper will provide the following method:

- static int memmem(PBYTE haystack, DWORD haystack_size, PBYTE needle, DWORD needle_size);
- static int getDeviceHandle(LPTSTR name);
- static unsigned __int64 __fastcall ExpLookupHandleTableEntryW7(__int64 HandleTable, unsigned __int64 handle);
- static unsigned __int64 __fastcall ExpLookupHandleTableEntryW10(__int64 HandleTable, __int64 handle);
- static ULONG64 findPhisical_ObjectTable(DWORDLONG startAddress, DWORDLONG stopAddress, DWORD searchSpace, PBYTE  searchBuffer, DWORD bufferSize);
- static DWORDLONG findPhisical(DWORDLONG startAddress, DWORDLONG stopAddress, DWORD searchSpace, PBYTE  searchBuffer, DWORD bufferSize);


## Usefull Structures:

EPROCESS pattern:
```
typedef struct {
	CHAR  ImageFileName[15];
	DWORD PriorityClass;
} _EPROCESS_PATTERN;
```

Read physicalAddress:
```
typedef struct _READ_REQUEST {
	DWORD InterfaceType;
	DWORD Bus;
	ULONG64 PhysicalAddress;
	DWORD IOSpace;
	DWORD size;
} READ_REQUEST;
```

Write physicalAddress:
```
typedef struct _WRITE_REQUEST {
	DWORDLONG address;
	DWORD length;
	DWORDLONG buffer;
} WRITE_REQUEST;
```

Structure for memcpy using VA:
```
typedef struct _MEMCPY_REQUEST {
	ULONG64 dest;
	ULONG64 src;
	DWORD size;
} MEMCPY_REQUEST;
```

HANDLE_TABLE_ENTRY:
```
typedef struct _HANDLE_TABLE_ENTRY
{
	ULONGLONG Value;
	ULONGLONG GrantedAccess : 25;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
```

HANDLE_TABLE:_
```
typedef struct _HANDLE_TABLE
{
	CHAR fill[100];
} HANDLE_TABLE, *PHANDLE_TABLE;
```