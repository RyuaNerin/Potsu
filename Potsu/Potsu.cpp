// Potsu.cpp : 다음 팟플레이어 이용을 원활하게 해주는 팟수 프로그램입니다
//

#include "stdafx.h"
#include "Potsu.h"
#include <psapi.h>

// Modified BMH - http://en.wikipedia.org/wiki/Boyer-Moore-Horspool_algorithm
int search_ptn(LPWORD ptn, size_t ptn_size, LPBYTE *addr, HANDLE hProcess, HMODULE hModule)
{
	MODULEINFO dllInfo;
	if (!GetModuleInformation(hProcess, hModule, &dllInfo, sizeof(dllInfo)))
	{
		MessageBox(0, L"GetModuleInformation Failed", 0, MB_ICONERROR);
		return 0;
	}


	UINT i;
	int scan;
	LPBYTE p;

	UINT defSkipLen;
	UINT skipLen[UCHAR_MAX + 1];
	UINT searchSuccessCount;

	UINT ptnEnd = ptn_size - 1;
	while ((HIBYTE(ptn[ptnEnd]) != 0x00) && (ptnEnd > 0))
		ptnEnd--;

	defSkipLen = ptnEnd;
	for (i = 0; i < ptnEnd; i++)
		if (HIBYTE(ptn[i]) != 0x00)
			defSkipLen = ptnEnd - i;

	for (i = 0; i < UCHAR_MAX + 1; i++)
		skipLen[i] = defSkipLen;

	for (i = 0; i < ptnEnd; i++)
		if (HIBYTE(ptn[i]) == 0x00)
			skipLen[LOBYTE(ptn[i])] = ptnEnd - i;

	searchSuccessCount = 0;
	p = (LPBYTE)dllInfo.lpBaseOfDll;
	LPBYTE searchEnd = (LPBYTE)dllInfo.lpBaseOfDll + dllInfo.SizeOfImage;
	BYTE ps;
	while (p + ptn_size < searchEnd)
	{
		scan = ptnEnd;
		while (scan >= 0)
		{
			ReadProcessMemory(hProcess, p + scan, &ps, sizeof(BYTE), NULL);
			if ((HIBYTE(ptn[scan]) == 0x00) && (LOBYTE(ptn[scan]) != ps))
				break;
			if (scan == 0)
			{
				*addr = p;
				searchSuccessCount++;
			}
			scan--;
		}
		ReadProcessMemory(hProcess, p + ptnEnd, &ps, sizeof(BYTE), NULL);
		p += skipLen[ps];
	}
	if (searchSuccessCount != 1) addr = 0;
	return searchSuccessCount;
}

HMODULE GetPotInst(const PROCESS_INFORMATION &ProcessInformation)
{
	BOOL bExit = false;
	while (!bExit)
	{
		HMODULE hMods[1024];
		DWORD cbNeeded;
		if (EnumProcessModules(ProcessInformation.hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				TCHAR szModName[MAX_PATH];

				if (GetModuleFileNameEx(ProcessInformation.hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
				{
					_wcslwr_s(szModName, MAX_PATH);
					if (wcsstr(szModName, L"potplayer.dll"))
					{
						return hMods[i];
					}
				}
			}
		}
		Sleep(10);
	}
	return 0;
}

bool PatchPotsu(HANDLE hProcess, DWORD dwProcessId, HMODULE hModule)
{
	WORD ptn[] = { 0x89, 0x6C, 0x24, 0x1C, 0x8B, 0x45, 0x00, 0x83, 0x78, 0xF4, 0x00, 0x0F, 0x84 };

	LPBYTE addr = 0;
	int r = search_ptn(ptn, _countof(ptn), &addr, hProcess, hModule);

	if (r == 0 || r > 1)
		return false;
	else
	{
		BYTE Patch[1] = { 0x81 };

		int PatchSize = _countof(Patch);
		addr += 12;

		DWORD OldProtect, OldProtect2;
		HANDLE hHandle;
		hHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
		VirtualProtectEx(hHandle, (void *)addr, PatchSize, PAGE_EXECUTE_READWRITE, &OldProtect);
		WriteProcessMemory(hProcess, addr, Patch, PatchSize, NULL);
		hHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
		VirtualProtectEx(hHandle, (void *)addr, PatchSize, OldProtect, &OldProtect2);
	}

	return true;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	memset(&StartupInfo, 0, sizeof(STARTUPINFO));
	memset(&ProcessInformation, 0, sizeof(PROCESS_INFORMATION));
	
	BOOL result = CreateProcess(L"PotPlayer.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation);
	if (!result)
	{
		MessageBox(0, L"PotPlayer.exe 파일을 찾을 수 없습니다.", L"PotPlayer Not Found", MB_ICONERROR);
		return 0;
	}
	HMODULE hModule = GetPotInst(ProcessInformation);
	if (!PatchPotsu(ProcessInformation.hProcess, ProcessInformation.dwProcessId, hModule))
		MessageBox(0, L"Patch failed", 0, 0);

	return 0;
}