# DriverTester

## Introduction


## Usage

This module exploits **Razer Synapse rzpnk.sys (2.20.15.1104) - CVE-2017-9769** to open a new HANDLE to the game from kernel mode. Then it attempts to access to the memory of the game by using this handle.

> A specially crafted IOCTL can be issued to the rzpnk.sys driver in Razer Synapse 2.20.15.1104 that is forwarded to ZwOpenProcess allowing a handle to be opened to an arbitrary process.
References

__Actions that this module attemps:__

-  ReadProcessMemory
-  WriteProcessMemory
-  ntReadVirtualMemory
-  ntWriteVirtualMemory
-  ZwReadVirtualMemory
-  ZwWriteVirtualMemory

## Configuration

This module requires configuration:

- The following variables in config.ini need to the provided:

[Addresses]
```
RPMAddressHigh=0x1
RPMAddressLow=0x58A60000
RPMAddress=0x0
WPMAddressHigh=0x00000000
WPMAddressLow=0x58A60000
WPMAddress=0x0
ntRVMAddressHigh=0x00000000
ntRVMAddressLow=0x58A60000
ntRVMAddress=0x0
ntWVMAddressHigh=0x00000000
ntWVMAddressLow=0x58A60000
ntWVMAddress=0x0
ZwRVMAddressHigh=0x00000000
ZwRVMAddressLow=0x58A60000
ZwRVMAddress=0x0
ZwWVMAddressHigh=0x00000000
ZwWVMAddressLow=0x58A60000
ZwWVMAddress=0x0
```


[Buffers]
```
#SIZE MUST BE SIZE+1
RPMBuffer=TTTT1
RPMBufferSize=0x6
WPMBuffer=TTTT2
WPMBufferSize=0x6
ntRVMBuffer=TTTT4
ntRVMBufferSize=0x6
ntWVMBuffer=TTTT5
ntWVMBufferSize=0x6
ZwRVMBuffer=TTTT6
ZwRVMBufferSize=0x6
ZwWVMBuffer=TTTT7
ZwWVMBufferSize=0x6
``` 

[Strings]
```
targetProc=r5apex.exe
```

## Combination with other techniques

- **RUNASKINVOKER**: By executing the game using this options we will prevent the Anti-cheat to fully protect the game end load the driver.


## Links

https://warroom.rsmus.com/cve-2017-9769/