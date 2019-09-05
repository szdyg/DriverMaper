#pragma once
#include "Pch.h"


// FullName:  LeiLeiSafeInitString
// Access:     public 
// Returns:    NTSTATUS
// Parameter: OUT PUNICODE_STRING result
// Parameter: IN PUNICODE_STRING source
// Info:           分配内存初始化字符串
//************************************
NTSTATUS LeiLeiSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source);

//************************************
// FullName:  LeiLeiSafeSearchString
// Access:    public 
// Returns:   LONG                                返回位置
// Parameter: IN PUNICODE_STRING source
// Parameter: IN PUNICODE_STRING target
// Parameter: IN BOOLEAN CaseInSensitive          大小写敏感
// Info:      查找子串
//************************************
LONG LeiLeiSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive);


//************************************
// FullName:  LeiLeiStripFilename
// Access:    public 
// Returns:   NTSTATUS
// Parameter: IN PUNICODE_STRING path
// Parameter: OUT PUNICODE_STRING dir
// Info:      根据文件完整路径，截取文件名
//************************************
NTSTATUS LeiLeiStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name);

//************************************
// FullName:  LeiLeiStripFilename
// Access:    public 
// Returns:   NTSTATUS
// Parameter: IN PUNICODE_STRING path
// Parameter: OUT PUNICODE_STRING dir
// Info:      根据文件完整路径，截取文件夹路径
//************************************
NTSTATUS LeiLeiStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir);

NTSTATUS LeiLeiFileExists(IN PUNICODE_STRING path);

NTSTATUS LeiLeiSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

BOOLEAN LeiLeiCheckProcessTermination(PEPROCESS pProcess);

//************************************
// FullName:  LeiLeiGetKernelBase
// Access:    public 
// Returns:   PVOID                  内存基址
// Parameter: OUT PULONG pSize       内核大小
// Info:      利用内核导出函数，返回内核基址和大小
//************************************
PVOID LeiLeiGetKernelBase(OUT PULONG pSize);

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase();

PVOID GetSSDTEntry(IN ULONG index);

NTSTATUS LeiLeiScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);

NTSTATUS LeiLeiSafeInitStringEx(OUT PUNICODE_STRING result, IN PUNICODE_STRING source, USHORT addSize);

PEPROCESS BBGetProcessByName(char* szProcessName);

BOOLEAN CheckSig(PUNICODE_STRING pRegPath);