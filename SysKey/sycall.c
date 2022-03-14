#include "Main.h"

PVOID(NTAPI *EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);

NTSTATUS(NTAPI *PsResumeThread)(PETHREAD Thread, PULONG PreviousCount);
NTSTATUS(NTAPI *PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);


BOOL ProbeUserAddress(PVOID addr, SIZE_T size, ULONG alignment) {
	if (size == 0) {
		return TRUE;
	}

	ULONG_PTR current = (ULONG_PTR)addr;
	if (((ULONG_PTR)addr & (alignment - 1)) != 0) {
		return FALSE;
	}

	ULONG_PTR last = current + size - 1;
	if ((last < current) || (last >= MmUserProbeAddress)) {
		return FALSE;
	}

	return TRUE;
}

BOOL SafeCopy(PVOID dest, PVOID src, SIZE_T size) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
		return TRUE;
	}

	return FALSE;
}

//BYTE GetInstructionLength(BYTE table[], PBYTE instruction) {
//	BYTE i = table[*instruction++];
//	return i < 0x10 ? i : GetInstructionLength(INSTRUCTION_TABLES[i - 0x10], instruction);
//}



PCHAR LowerStr(PCHAR str) {
	for (PCHAR s = str; *s; ++s) {
		*s = (CHAR)tolower(*s);
	}
	return str;
}

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask) {
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask) {
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

PVOID GetBaseAddress(PCHAR name, PULONG outSize) {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		printf("! ZwQuerySystemInformation for size failed: %x !\n", status);
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = ExAllocatePool(NonPagedPool, size);
	if (!modules) {
		printf("! failed to allocate %d bytes for modules !\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		printf("! ZwQuerySystemInformation failed: %x !\n", status);
		ExFreePool(modules);
		return addr;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];

		if (strstr(LowerStr((PCHAR)m.FullPathName), name)) {
			addr = m.ImageBase;
			if (outSize) {
				*outSize = m.ImageSize;
			}
			break;
		}
	}

	ExFreePool(modules);
	return addr;
}


PVOID NTAPI EnumerateDebuggingDevicesHook(PSYSCALL_DATA data, PINT64 status) 
{
	//如果不是用户层的 不进行处理
	if (ExGetPreviousMode() != UserMode) {
		return EnumerateDebuggingDevicesOriginal(data, status);
	}

	SYSCALL_DATA safeData = { 0 };
	if (!ProbeUserAddress(data, sizeof(safeData), sizeof(ULONG)) || !SafeCopy(&safeData, data, sizeof(safeData)) || safeData.Unique != SYSCALL_UNIQUE) 
	{
		return EnumerateDebuggingDevicesOriginal(data, status);
	}

	else
	{
		DbgPrint("来自R3 的消息%d", safeData.RX);
		DbgPrint("来自R3 的消息%d", safeData.RY);
	}




	//switch (safeData.Syscall) {
	//	
	//		NTOPENPROCESS_ARGS args  = { 0 };
	//		SafeCopy(&args, safeData.Arguments, sizeof(args));

	//	DbgPrint("%d", args.RX);
	//	DbgPrint("%d", args.RY);

	//}

	*status = STATUS_NOT_IMPLEMENTED;
	return 0;
}

ULONG PreviousModeOffset = 0;
KPROCESSOR_MODE KeSetPreviousMode(KPROCESSOR_MODE mode) {
	KPROCESSOR_MODE old = ExGetPreviousMode();
	*(KPROCESSOR_MODE *)((PBYTE)KeGetCurrentThread() + PreviousModeOffset) = mode;
	return old;
}

NTSTATUS Main()
{
	// Hook ntoskrnl syscall
	PVOID NtosBase = GetBaseAddress("ntoskrnl.exe", 0);
	if (!NtosBase) {
		DbgPrint("! failed to get \"ntoskrnl.exe\" base !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	PVOID func = FindPatternImage(NtosBase,"\x48\x8B\x05\x00\x00\x00\x00\x75\x07\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00", "xxx????xxxxx????x????");
	if (!func) {
		DbgPrint("! failed to find xKdEnumerateDebuggingDevices !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	func = (PBYTE)func + *(PINT)((PBYTE)func + 3) + 7;

	DbgPrint("func :0x%llX\n", func);
	*(PVOID *)&EnumerateDebuggingDevicesOriginal = InterlockedExchangePointer(func, (PVOID)EnumerateDebuggingDevicesHook);

	DbgPrint("hook成功success\n");
	return STATUS_SUCCESS;
}
