# External Cheat Driver

## Introduction

Implementation that abuse of a vulnerable driver to Read/Write from physical memory in order to directly read/modify the target process.
The main purpose is to avoid performing a DKOM, which would be much easier to be detected.
This implementation uses gigabyte driver to achieve its goal, however, changing the vulnerable driver should be quite easy, given that all the methods are created in a modular way inside DriverHelper.

## Usage

This module makes use of **DriverHelper** and **CheatHelper**.

> Note that this module has been created as a PoC to manipulate one particular game (BlackDesertOnline), however, the method `ActivateHack` can be modified in order to create any desired PoC.


## Configuration

This module requires configuration:

- The following variables in config.ini need to the provided:

[Strings]
```
targetProc=BlackDesert64.exe
driverName=\\.\GIO
```

## Notes

- driverName: Name of the driver device to exploit
- targetProc: Process name of the game
 
