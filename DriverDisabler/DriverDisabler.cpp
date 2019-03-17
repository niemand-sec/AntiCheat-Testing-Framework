// DriverDisabler.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "CheatHelper.h"
#include <iostream>
#include <windows.h>


bool DriverBypass(int pID)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pID);
	if (!hProcess) {
		std::cout << "Error1" << std::endl;
		return false;
	}


	HMODULE hMod = GetModuleHandle("advapi32.dll");
	if (!hMod) {
		std::cout << "Error2" << std::endl;
		return false;
	}

	
	std::cout << std::hex << hMod << std::endl;
	LPVOID dwSSA = (LPVOID)GetProcAddress(hMod, "StartServiceA");
	LPVOID dwOSW = (LPVOID)GetProcAddress(hMod, "OpenServiceW");
	if (!dwSSA || !dwOSW) {
		std::cout << "Error3" << std::endl;
		return false;
	}
	std::cout << std::hex << dwSSA << std::endl;
	std::cout << std::hex << dwOSW << std::endl;
	byte wByte[] = { 0xC2, 0x0C, 0x00 };
	if (!WriteProcessMemory(hProcess, dwSSA, &wByte, sizeof(wByte), NULL)) {
		std::cout << "Error4" << std::endl;
		return false;
	}
	if (!WriteProcessMemory(hProcess, dwOSW, &wByte, sizeof(wByte), NULL)) {
		std::cout << "Error5" << std::endl;
		return false;
	}

	return true;
}


int main()
{
	std::cout << "Hello World!\n";
	const char* procName = "BlackDesert64.exe";
	DWORD processID = NULL;
	while (true)
	{
		processID = CheatHelper::GetProcId(procName);
		if (processID != NULL)
		{
			std::cout << std::hex << processID << std::endl;
			break;
		}
		Sleep(1000);
	}
	Sleep(1000);
	DriverBypass(processID);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
