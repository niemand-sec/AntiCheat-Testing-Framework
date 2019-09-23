// ExternalCheatDriver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "CheatHelper.h"
#include "DriverHelper.h"
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <cstdint>



// Definition of IOCTL numbers
// GPCIDrv64 Driver
#define IOCTL_MAPPHYSICAL	0x9C402580
#define IOCTL_UNMAPPHYSICAL	0x9C402584
// GIO Driver
#define IOCTL_GIO_MAPPHYSICAL	0xC3502004
#define IOCTL_GIO_UNMAPPHYSICAL 0xC3502008
#define IOCTL_GIO_MEMCPY 0xC3502808

// Kernel offsets
// W10
#define OFFSET_IMAGEFILENAME 0x450
#define OFFSET_OBJECTTABLE 0x418

#pragma comment(lib, "ntdll.lib")


ULONG64 GIO_mapPhysical(ULONG64 physicaladdress, DWORD size)
{
	READ_REQUEST inbuffer = { 0, 0, physicaladdress, 0, size };
	ULONG64 outbuffer[2] = { 0 };
	DWORD bytes_returned = 0;
	DeviceIoControl(DriverHelper::hDeviceDrv,
		IOCTL_GIO_MAPPHYSICAL,
		&inbuffer,
		sizeof(inbuffer),
		&outbuffer,
		sizeof(outbuffer),
		&bytes_returned,
		(LPOVERLAPPED)NULL);

	return outbuffer[0];
}

ULONG64 GIO_unmapPhysical(ULONG64 address)
{
	ULONG64 inbuffer = address;
	ULONG64 outbuffer[2] = { 0 };
	DWORD bytes_returned = 0;
	DeviceIoControl(DriverHelper::hDeviceDrv,
		IOCTL_GIO_UNMAPPHYSICAL,
		(LPVOID)&inbuffer,
		sizeof(inbuffer),
		(LPVOID)outbuffer,
		sizeof(outbuffer),
		&bytes_returned,
		(LPOVERLAPPED)NULL);

	return outbuffer[0];
}

BOOL GIO_memcpy(ULONG64 dest, ULONG64 src, DWORD size)
{
	MEMCPY_REQUEST mystructIn = { dest, src, size };
	BYTE outbuffer[0x30] = { 0 };
	DWORD returned = 0;

	DeviceIoControl(DriverHelper::hDeviceDrv, IOCTL_GIO_MEMCPY, (LPVOID)&mystructIn, sizeof(mystructIn), (LPVOID)outbuffer, sizeof(outbuffer), &returned, NULL);
	if (returned) {
		return TRUE;
	}
	return FALSE;
}

bool bFirstActivation = true;

bool ActivateHack(uintptr_t speedAddress, uintptr_t attackSpeedAddress, boolean activate, int32_t &initialSpeed, int32_t &initialAttackSpeed)
{
	if (activate)
	{
		if (bFirstActivation)
		{
			std::cout << "[+] Activating Hack" << std::endl;
			std::cout << "\t[+] PlayerSpeed Address:\t 0x" << std::hex << speedAddress << std::endl;
			std::cout << "\t[+] PlayerAttackSpeed Address:\t 0x" << std::hex << attackSpeedAddress << std::endl;

			if (!DriverHelper::ReadVirtualMemory(DriverHelper::DTBTargetProcess,
				speedAddress,
				&initialSpeed, sizeof(initialSpeed), NULL))
			{
				std::cout << "[-] Reading PlayerSpeed: Failed" << std::endl;
				return false;
			}

			if (!DriverHelper::ReadVirtualMemory(DriverHelper::DTBTargetProcess,
				attackSpeedAddress,
				&initialAttackSpeed, sizeof(initialAttackSpeed), NULL))
			{
				std::cout << "[-] Reading PlayerAttackSpeed: Failed" << std::endl;
				return false;
			}

			std::cout << "\t[+] Current PlayerSpeed:\t 0x" << std::hex << initialSpeed << std::endl;
			std::cout << "\t[+] Current PlayerAttackSpeed:\t 0x" << std::hex << initialAttackSpeed << std::endl;
		}

		int32_t newSpeed = (std::numeric_limits<std::int32_t>::max)();
		int32_t newAttackSpeed = 9999999;
			
		if (!DriverHelper::WriteVirtualMemory(DriverHelper::DTBTargetProcess,
			speedAddress,
			&newSpeed, sizeof(newSpeed), NULL))
		{
			std::cout << "[-] Activating SpeedHack: Failed" << std::endl;
			return false;
		}
		if (!DriverHelper::WriteVirtualMemory(DriverHelper::DTBTargetProcess,
			attackSpeedAddress,
			&newAttackSpeed, sizeof(newAttackSpeed), NULL))
		{
			std::cout << "[-] Activating AttackSpeedHack: Failed" << std::endl;
			return false;
		}

		if (bFirstActivation)
		{
			std::cout << "\t[+] Current PlayerSpeed:\t 0x" << std::hex << newSpeed << std::endl;
			std::cout << "\t[+] Current PlayerAttackSpeed:\t 0x" << std::hex << newAttackSpeed << std::endl;
		}
	}
	else
	{
		std::cout << "[+] Deactivating Hack" << std::endl;

		int32_t currentSpeed = 0;
		int32_t currentAttackSpeed = 0;

		if (!DriverHelper::ReadVirtualMemory(DriverHelper::DTBTargetProcess,
			speedAddress,
			&currentSpeed, sizeof(currentSpeed), NULL))
		{
			std::cout << "[-] Deactivating SpeedHack: Failed" << std::endl;
			return false;
		}
		if (!DriverHelper::ReadVirtualMemory(DriverHelper::DTBTargetProcess,
			attackSpeedAddress,
			&currentAttackSpeed, sizeof(currentAttackSpeed), NULL))
		{
			std::cout << "[-] Deactivating AttackSpeedHack: Failed" << std::endl;
			return false;
		}

		std::cout << "\t[+] Current PlayerSpeed:\t 0x" << std::hex << currentSpeed << std::endl;
		std::cout << "\t[+] Current AttackPlayerSpeed:\t 0x" << std::hex << currentAttackSpeed << std::endl;

		if (!DriverHelper::WriteVirtualMemory(DriverHelper::DTBTargetProcess,
			speedAddress,
			&initialSpeed, sizeof(initialSpeed), NULL))
		{
			std::cout << "[-] Deactivating SpeedHack: Failed" << std::endl;
			return false;
		}
		if (!DriverHelper::WriteVirtualMemory(DriverHelper::DTBTargetProcess,
			attackSpeedAddress,
			&initialAttackSpeed, sizeof(initialAttackSpeed), NULL))
		{
			std::cout << "[-] Deactivating AttackSpeedHack: Failed" << std::endl;
			return false;
		}

		std::cout << "\t[+] Current PlayerSpeed:\t 0x" << std::hex << initialSpeed << std::endl;
		std::cout << "\t[+] Current AttackPlayerSpeed:\t 0x" << std::hex << initialAttackSpeed << std::endl;

	}
	
	bFirstActivation = false;

	return true;
}


int main()
{
	std::cout << "[+] Init" << std::endl;
	CheatHelper::loadConfig();


	// Connecting the vulnerable driver (GPCIDrv64.sys AORUS GRAPHICS ENGINE v1.25)
	std::cout << "[+] Obtaining HANDLE to Drv" << std::endl;
	if (DriverHelper::getDeviceHandle(CheatHelper::driverName))
	{
		std::cout << "[-] Obtaining HANDLE: failed." << std::endl;
		return 1;
	}

	// If we want to change the driver, we just need to create our functions for communication and set the following variables
	DriverHelper::fn_memcpy = (_fn_memcpy)GIO_memcpy;
	DriverHelper::fn_mapPhysical = (_fn_mapPhysical)GIO_mapPhysical;
	DriverHelper::fn_unmapPhysical = (_fn_unmapPhysical)GIO_unmapPhysical;

	uintptr_t directoryTableBase = 0;
	uintptr_t pKProcess = DriverHelper::GetKProcess(directoryTableBase);

	uintptr_t pBaseAddress = DriverHelper::SearchKProcess(CheatHelper::targetProc, directoryTableBase, pKProcess);

	if (!DriverHelper::ObtainKProcessInfo(directoryTableBase, pBaseAddress))
	{
		std::cout << "[-] ObtainKProcessInfo failed" << std::endl;
	}

	//	objectTable	0xcccccccccccccccc	unsigned __int64
	if (pBaseAddress == 0)
	{
		std::cout << "[-] Target process not found :(" << std::endl;
		return 1;
	}
	
	if (!DriverHelper::CheckProcessHeader(DriverHelper::DTBTargetProcess,
		DriverHelper::pBaseAddressTargetProcess))
	{
		std::cout << "[-] Failed process header checking" << std::endl;
		return 1;
	}
	
	std::cout << "[+] Process Header Check: SUCCESS" << std::endl;
	
	bool activate = true;

	// From this part you will need to customize everything
	// This is just a practical example to show how it is possible to validate if the
	// memory of a game is accessible with this techinque
	uintptr_t localPlayerOffset = 0x390d858;
	uintptr_t speedAddressOffset = 0xB58;
	uintptr_t attackSpeedAddressOffset = 0xB5C;
	uintptr_t speedAddress = 0;
	uintptr_t attackSpeedAddress = 0;
	uintptr_t playerAddress = 0;

	playerAddress = DriverHelper::pBaseAddressTargetProcess + localPlayerOffset;

	uintptr_t pLocalPlayer = 0;

	std::cout << "[+] Locating localPlayer Address" << std::endl;
	if (!DriverHelper::ReadVirtualMemory(DriverHelper::DTBTargetProcess,
			playerAddress,
			&pLocalPlayer, sizeof(pLocalPlayer), NULL))
	{
			std::cout << "[-] Obtaining localPlayer: Failed" << std::endl;
			return false;
	}

	std::cout << "\t[+] localPlayerAddress: 0x" << std::hex << playerAddress << std::endl;

	speedAddress = pLocalPlayer + speedAddressOffset;
	attackSpeedAddress = pLocalPlayer + attackSpeedAddressOffset;

	int32_t initialSpeed = 0;
	int32_t initialAttackSpeed = 0;

	// Activating Cheat
	if (!ActivateHack(speedAddress, attackSpeedAddress, activate, initialSpeed, initialAttackSpeed))
		return 1;

	// We need this while to lock the value we want on memory. The game could change the value anytime
	// and we have to overwrite it.
	while (true)
	{
		// InsertKey to disable cheat
		if (GetKeyState(VK_INSERT) & 0x8000)
			break;

		if (!ActivateHack(speedAddress, attackSpeedAddress, activate, initialSpeed, initialAttackSpeed))
			return 1;

		Sleep(100);
	}
	
	// Deactivating cheat
	activate = false;
	if (!ActivateHack(speedAddress, attackSpeedAddress, activate, initialSpeed, initialAttackSpeed))
		return 1;

	return 0;

}