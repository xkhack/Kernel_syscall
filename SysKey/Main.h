#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
//#include "util.h"
#include "syscall.h"


#define printf(fmt, ...) DbgPrint("[dbg] "fmt, ##__VA_ARGS__)
#define HANDLE_SYSCALL(name, args) \
    case Syscall##name: {                                         \
        args safe = { 0 };                                        \
        if (!SafeCopy(&safe, safeData.Arguments, sizeof(args))) { \
            *status = STATUS_ACCESS_VIOLATION;                    \
            return 0;                                             \
        }                                                         \
        *status = Core##name(&safe);                              \
        return 0;                                                 \
    }

// Important thread info excluding most critical structures
#define THREAD_INFO_SIZE (0x6E4)
static ULONG THREAD_INFO_SECTIONS[] = { 0x78, 0x7C, 0xC3, 0xC5, 0x220, 0x228, 0x233, 0x234, 0x240, 0x250, 0x28C, 0x290, 0x2DC, 0x2E0, 0x5D8, 0x618, 0x680, 0x6A8, 0x6BC, THREAD_INFO_SIZE };

KPROCESSOR_MODE KeSetPreviousMode(KPROCESSOR_MODE mode);

/*** Process ***/
INT64 CoreNtOpenProcess(PVOID HOOK);