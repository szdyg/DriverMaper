#pragma once
#include "Pch.h"


// FullName:  LeiLeiSafeInitString
// Access:     public 
// Returns:    NTSTATUS
// Parameter: OUT PUNICODE_STRING result
// Parameter: IN PUNICODE_STRING source
// Info:           �����ڴ��ʼ���ַ���
//************************************
NTSTATUS LeiLeiSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source);

//************************************
// FullName:  LeiLeiSafeSearchString
// Access:    public 
// Returns:   LONG                                ����λ��
// Parameter: IN PUNICODE_STRING source
// Parameter: IN PUNICODE_STRING target
// Parameter: IN BOOLEAN CaseInSensitive          ��Сд����
// Info:      �����Ӵ�
//************************************
LONG LeiLeiSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive);


//************************************
// FullName:  LeiLeiStripFilename
// Access:    public 
// Returns:   NTSTATUS
// Parameter: IN PUNICODE_STRING path
// Parameter: OUT PUNICODE_STRING dir
// Info:      �����ļ�����·������ȡ�ļ���
//************************************
NTSTATUS LeiLeiStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name);

//************************************
// FullName:  LeiLeiStripFilename
// Access:    public 
// Returns:   NTSTATUS
// Parameter: IN PUNICODE_STRING path
// Parameter: OUT PUNICODE_STRING dir
// Info:      �����ļ�����·������ȡ�ļ���·��
//************************************
NTSTATUS LeiLeiStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir);

NTSTATUS LeiLeiFileExists(IN PUNICODE_STRING path);

NTSTATUS LeiLeiSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

BOOLEAN LeiLeiCheckProcessTermination(PEPROCESS pProcess);

//************************************
// FullName:  LeiLeiGetKernelBase
// Access:    public 
// Returns:   PVOID                  �ڴ��ַ
// Parameter: OUT PULONG pSize       �ں˴�С
// Info:      �����ں˵��������������ں˻�ַ�ʹ�С
//************************************
PVOID LeiLeiGetKernelBase(OUT PULONG pSize);

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase();

PVOID GetSSDTEntry(IN ULONG index);

NTSTATUS LeiLeiScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);

NTSTATUS LeiLeiSafeInitStringEx(OUT PUNICODE_STRING result, IN PUNICODE_STRING source, USHORT addSize);

PEPROCESS BBGetProcessByName(char* szProcessName);

BOOLEAN CheckSig(PUNICODE_STRING pRegPath);