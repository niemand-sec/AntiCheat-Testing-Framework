# StealthHandleHijackingMaster

## Introduction


## Usage

This module is used combinaded with **StealthHandleHijackingDLL**. This is the "command and control" implementation. Has to be executed before injecting the DLL. 

HandleHijakingMaster will create a FileMapping (Share Memory) that this module uses to receive instructions and then return information to the master (where all the bot logic should be located).

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

[Handles]

```
requestHandleFM=0x15FC
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
targetProc=BlackDesert64.exe
privotProc=lsass.exe
#Edit in DLL if you changed it here
fileMapName=Global\StealthHijacking
```

## Combination with other techniques

- **RUNASKINVOKER**: By executing the game using this options we will prevent the Anti-cheat to fully protect the game end load the driver.


