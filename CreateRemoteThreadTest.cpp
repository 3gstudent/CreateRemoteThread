
#pragma once  
#include <windows.h>  
#include <TlHelp32.h>  
#include "stdio.h"  
//线程参数结构体定义  
typedef struct _RemoteParam {  
	char szMsg[12];    //MessageBox函数中显示的字符提示  
	DWORD dwMessageBox;//MessageBox函数的入口地址  
} RemoteParam, * PRemoteParam;  
//定义MessageBox类型的函数指针  
typedef int (__stdcall * PFN_MESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, DWORD);  

//线程函数定义  
DWORD __stdcall threadProc(LPVOID lParam)  
{  
	RemoteParam* pRP = (RemoteParam*)lParam;  
	PFN_MESSAGEBOX pfnMessageBox;  
	pfnMessageBox = (PFN_MESSAGEBOX)pRP->dwMessageBox;  
	pfnMessageBox(NULL, pRP->szMsg, pRP->szMsg, 0);  
	return 0;  
}  
//提升进程访问权限  
bool enableDebugPriv()  
{  
	HANDLE hToken;  
	LUID sedebugnameValue;  
	TOKEN_PRIVILEGES tkp;  

	if (!OpenProcessToken(GetCurrentProcess(),   
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {  
			return false;  
	}  
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {  
		CloseHandle(hToken);  
		return false;  
	}  
	tkp.PrivilegeCount = 1;  
	tkp.Privileges[0].Luid = sedebugnameValue;  
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {  
		CloseHandle(hToken);  
		return false;  
	}  
	return true;  
}  

//根据进程名称得到进程ID,如果有多个运行实例的话，返回第一个枚举到的进程的ID  
DWORD processNameToId(LPCTSTR lpszProcessName)  
{  
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  
	PROCESSENTRY32 pe;  
	pe.dwSize = sizeof(PROCESSENTRY32);  
	if (!Process32First(hSnapshot, &pe)) {  
		MessageBox(NULL,   
			"The frist entry of the process list has not been copyied to the buffer",   
			"Notice", MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  
	while (Process32Next(hSnapshot, &pe)) {  
		if (!strcmp(lpszProcessName, pe.szExeFile)) {  
			return pe.th32ProcessID;  
		}  
	}  

	return 0;  
}  
int main(int argc, char* argv[])  
{  

	//定义线程体的大小  
	const DWORD dwThreadSize = 4096;  
	DWORD dwWriteBytes;  
	//提升进程访问权限  
	enableDebugPriv();  

	char *szExeName="calc.exe";

	DWORD dwProcessId = processNameToId(szExeName);  
	if (dwProcessId == 0) {  
		MessageBox(NULL, "The target process have not been found !",  
			"Notice", MB_ICONINFORMATION | MB_OK);  
		return -1;  
	}  
	//根据进程ID得到进程句柄  
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);  

	if (!hTargetProcess) {  
		MessageBox(NULL, "Open target process failed !",   
			"Notice", MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  

	//在宿主进程中为线程体开辟一块存储区域  
	//在这里需要注意MEM_COMMIT | MEM_RESERVE内存非配类型以及PAGE_EXECUTE_READWRITE内存保护类型  
	//其具体含义请参考MSDN中关于VirtualAllocEx函数的说明。  
	void* pRemoteThread = VirtualAllocEx(hTargetProcess, 0,   
		dwThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  
	if (!pRemoteThread) {  
		MessageBox(NULL, "Alloc memory in target process failed !",   
			"notice", MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  

	//将线程体拷贝到宿主进程中  
	if (!WriteProcessMemory(hTargetProcess,   
		pRemoteThread, &threadProc, dwThreadSize, 0)) {  
			MessageBox(NULL, "Write data to target process failed !",   
				"Notice", MB_ICONINFORMATION | MB_OK);  
			return 0;  
	}  
	//定义线程参数结构体变量  
	RemoteParam remoteData;  
	ZeroMemory(&remoteData, sizeof(RemoteParam));  

	//填充结构体变量中的成员  
	HINSTANCE hUser32 = LoadLibrary("User32.dll");  
	remoteData.dwMessageBox = (DWORD)GetProcAddress(hUser32, "MessageBoxA");  
	strcat_s(remoteData.szMsg, "Hello＼0");  

	//为线程参数在宿主进程中开辟存储区域  
	RemoteParam* pRemoteParam = (RemoteParam*)VirtualAllocEx(  
		hTargetProcess , 0, sizeof(RemoteParam), MEM_COMMIT, PAGE_READWRITE);  

	if (!pRemoteParam) {  
		MessageBox(NULL, "Alloc memory failed !",   
			"Notice", MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  
	//将线程参数拷贝到宿主进程地址空间中  
	if (!WriteProcessMemory(hTargetProcess ,  
		pRemoteParam, &remoteData, sizeof(remoteData), 0)) {  
			MessageBox(NULL, "Write data to target process failed !",   
				"Notice", MB_ICONINFORMATION | MB_OK);  
			return 0;  
	}  

	//在宿主进程中创建线程  
	HANDLE hRemoteThread = CreateRemoteThread(  
		hTargetProcess, NULL, 0, (DWORD (__stdcall *)(void *))pRemoteThread,   
		pRemoteParam, 0, &dwWriteBytes);  
	if (!hRemoteThread) {  
		MessageBox(NULL, "Create remote thread failed !", "Notice",  MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  
	CloseHandle(hRemoteThread);  
	FreeLibrary(hUser32);  
	return 0;  
}  