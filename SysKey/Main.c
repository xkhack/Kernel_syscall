#include "Main.h"
NTSTATUS Main();
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	Main();

	
	return STATUS_SUCCESS;
}