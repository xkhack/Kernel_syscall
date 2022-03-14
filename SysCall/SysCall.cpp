// SysCall.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#pragma comment(lib,"User32.lib")
#define SYSCALL_UNIQUE (0x133)
typedef struct _SYSCALL_DATA {
	DWORD RX;
	DWORD RY;
	DWORD Unique;
	DWORD Syscall;
	PVOID Arguments;
} SYSCALL_DATA, *PSYSCALL_DATA;

typedef struct _NTOPENPROCESS_ARGS {
	//PHANDLE ProcessHandle;
	//ACCESS_MASK DesiredAccess;
	//POBJECT_ATTRIBUTES ObjectAttributes;
	//PCLIENT_ID ClientId;

	USHORT RX;
	USHORT RY;
} NTOPENPROCESS_ARGS;



PVOID(NTAPI *NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);

BOOL SetupSyscalls() {
	HMODULE module = LoadLibrary(L"ntdll.dll");
	if (!module) {
		MessageBox(0, L"Failed to load NTDLL", L"Failure", MB_ICONERROR);
		return FALSE;
	}

	*(PVOID *)&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = GetProcAddress(module, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
		MessageBox(0, L"Failed to find \"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter\"", L"Failure", MB_ICONERROR);
		return FALSE;
	}

	return TRUE;
}
//NTSTATUS DoSyscall(SYSCALL syscall, PVOID args);
NTSTATUS DoSyscall(DWORD rx, DWORD ry)
{
	SYSCALL_DATA data = { 0 };
	data.Unique = SYSCALL_UNIQUE;
	//data.Syscall = syscall;
	//data.Arguments = args;
	data.RX = rx;
	data.RY = ry;
	
	PVOID dataPtr = &data;

	INT64 status = 0;
	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter((PVOID)1, &dataPtr, &status, 0);
	return (NTSTATUS)status;
}
int main()
{
	std::cout << "开始!\n";
	BOOL A=SetupSyscalls();//先初始化


	if (A)
	{
		while (true)
		{
			std::cout << "发送消息!\n";
			Sleep(3000);
			DoSyscall(200, 300);
		}
		

	}

}
//MessageBox(0, L"Failed to find \"NtGdiDdDDIGetPresentQueueEvent\"", L"Failure", MB_ICONERROR);
// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
