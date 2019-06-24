# Handle Elevation Driver

## Introduction

Implementation that abuse of a vulnerable driver to Read/Write from physical memory in order to perform a **DKOM** attack. The module will locate the target handle from an specific process and elevate the GrantedAccess to get PROCESS_ALL_ACCESS.
The main purpose is to elevate a HANDLE so we don't need to create a new one.
This implementation uses gigabyte driver to achiev its goal, however, changing the vulnerable driver should be quite easy, given that all the methods are created in a modular way inside DriverHelper.

## Usage

This module makes use of **DriverHelper** and **CheatHelper**.
HandleHijakingMaster will create a NamedPipe that the DLL will use to receive instructions and then return information to the master (where all the bot logic should be located).

## Configuration

This module requires configuration:

- The following variables in config.ini need to the provided:

[Addresses]
```
startAddressPhyHigh=0x00000000
startAddressPhyLow=0x58A60000
startAddressPhy=0x0
```

[Handles]
```
requestHandleDrv=0x15FC
```

[Strings]
```
privotProc=lsass.exe
driverName=\\.\GIO
```


## Notes

- startPhysicalAddress: Physical memory to start looking for EPROCESS structures.
- driverName: Name of the driver device to exploit
- requestHandleDrv: HANDLE number to elevate and use as pivot
 
