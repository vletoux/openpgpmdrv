/*	OpenPGP Smart Card Mini Driver
    Copyright (C) 2009 Vincent Le Toux

    This library is Free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <windows.h>
#include <tchar.h>
#include <Evntprov.h>
#include <initguid.h>
#include <Wmistr.h>
#include <Evntrace.h>
#include "cardmod.h"
#include <DelayImp.h>
#pragma comment(lib, "Delayimp.lib")
#include "Tracing.h"

/** We are doing a lot of complicated stuff (like hooking a delay load import)
because the Vista tracing function is much better than XP ones.
The choice was :
- do not allow the driver to run on xp (set WINVER to 0x600)
- don't use the great vista tracing functions (set WINVER to 0x500 and comment the function)
- run on xp AND use this function (set WINVER to 0x600 and allow to run on xp)

=> tried to have the best
*/

#define MessageBoxWin32(status) MessageBoxWin32Ex (status, __FILE__,__LINE__);

// to enable tracing in kernel debugger, issue the following command in windbg : ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF
// OR
// Open up the registry and go to this path,
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter 
// and add the following value "DEFAULT" : REG_DWORD : 0xFFFFFFFF and then reboot

// {081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}
DEFINE_GUID(TracingGuid, 
0x81cce5f, 0x5f9c, 0x4b43, 0x9a, 0x15, 0x1d, 0xcf, 0x5d, 0x2d, 0x45, 0xf5);

REGHANDLE hPub = 0;
BOOL          g_bTracingEnabled         = FALSE;
TRACEHANDLE   g_SessionHandle = 0; // The handle to the session that enabled the provider.
UCHAR g_EnableLevel = 0; // Determines the severity of events to log.
extern BOOL fRunOnVistaAndLater;
BOOL fDebugOutputIsEnabled = FALSE;

typedef struct _event
{
    EVENT_TRACE_HEADER Header;
    MOF_FIELD Data[MAX_MOF_FIELDS];  // Event-specific data
} MY_EVENT, *PMY_EVENT;

#define MY_EVENT_TYPE 1
#define EVENT_DATA_FIELDS_CNT  1

INT_PTR FAR WINAPI DoNothing()
{
	return 0;
}

// delayHookFunc - Delay load hooking function
// don't fail to load our dll is the computer is xp
FARPROC WINAPI delayHookFailureFunc (unsigned dliNotify, PDelayLoadInfo pdli)
{
	UNREFERENCED_PARAMETER(pdli);
	if (_stricmp(pdli->szDll,"advapi32.dll") == 0 && dliNotify == dliFailGetProc)
	{
		return &DoNothing;
	}

	return NULL;
}


// __delayLoadHelper gets the hook function in here:
PfnDliHook __pfnDliFailureHook2 = delayHookFailureFunc;



// The callback function that receives enable/disable notifications
// from one or more ETW sessions. Because more than one session
// can enable the provider, this example ignores requests from other 
// sessions if it is already enabled.

ULONG WINAPI ControlCallback(
    WMIDPREQUESTCODE RequestCode,
    PVOID Context,
    ULONG* Reserved, 
    PVOID Header
    )
{
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE TempSessionHandle = 0; 

    switch (RequestCode)
    {
        case WMI_ENABLE_EVENTS:  // Enable the provider.
        {
            SetLastError(0);

            // If the provider is already enabled to a provider, ignore 
            // the request. Get the session handle of the enabling session.
            // You need the session handle to call the TraceEvent function.
            // The session could be enabling the provider or it could be
            // updating the level and enable flags.

            TempSessionHandle = GetTraceLoggerHandle(Header);
            if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
            {
                wprintf(L"GetTraceLoggerHandle failed. Error code is %lu.\n", status = GetLastError());
                break;
            }

            if (0 == g_SessionHandle)
            {
                g_SessionHandle = TempSessionHandle;
            }
            else if (g_SessionHandle != TempSessionHandle)
            {
                break;
            }

            // Get the severity level of the events that the
            // session wants you to log.

            g_EnableLevel = GetTraceEnableLevel(g_SessionHandle); 
            g_bTracingEnabled = TRUE;
            break;
        }
 
        case WMI_DISABLE_EVENTS:  // Disable the provider.
        {
            // Disable the provider only if the request is coming from the
            // session that enabled the provider.

            TempSessionHandle = GetTraceLoggerHandle(Header);
            if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
            {
                wprintf(L"GetTraceLoggerHandle failed. Error code is %lu.\n", status = GetLastError());
                break;
            }

            if (g_SessionHandle == TempSessionHandle)
            {
                g_bTracingEnabled = FALSE;
                g_SessionHandle = 0;
            }
            break;
        }

        default:
        {
            status = ERROR_INVALID_PARAMETER;
            break;
        }
    }

    return status;
}

// callback to know if the tracing is activated
VOID NTAPI ControlCallbackVista (
    __in LPCGUID SourceId,
    __in ULONG IsEnabled,
    __in UCHAR Level,
    __in ULONGLONG MatchAnyKeyword,
    __in ULONGLONG MatchAllKeyword,
    __in_opt PEVENT_FILTER_DESCRIPTOR FilterData,
    __in_opt PVOID CallbackContext
    )
{
	g_bTracingEnabled = (IsEnabled?TRUE:FALSE);
}

// called to setup the tracing context
void TracingRegister() 
{
	if (fRunOnVistaAndLater)
	{
		EventRegister(&TracingGuid,ControlCallbackVista,NULL,&hPub);
	}
	else
	{
		RegisterTraceGuids(
			  ControlCallback,
			  NULL,
			  &TracingGuid, 
			  0, NULL, NULL, 
			  NULL,
			  &hPub);
	}
#ifdef _DEBUG
	fDebugOutputIsEnabled = TRUE;
#endif
}
// called to clean up the tracing context
void TracingUnRegister() 
{
	if (fRunOnVistaAndLater)
	{
		EventUnregister(hPub);
	}
	else
	{
		UnregisterTraceGuids(hPub );
	}
}
// write a single line in the trace
void WriteTrace(UCHAR dwLevel, PWSTR szTrace)
{
	if (fRunOnVistaAndLater)
	{
		EventWriteString(hPub,dwLevel,0,szTrace);
	}
	else
	{
		MY_EVENT MyEvent; 
		NTSTATUS status;
		
		if (g_bTracingEnabled && (0 == g_EnableLevel || dwLevel <= g_EnableLevel))
		{
			// Initialize the event data structure.

			ZeroMemory(&MyEvent, sizeof(MY_EVENT));
			MyEvent.Header.Size = sizeof(EVENT_TRACE_HEADER) + (sizeof(MOF_FIELD) * EVENT_DATA_FIELDS_CNT);
			MyEvent.Header.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR;
			MyEvent.Header.Guid = TracingGuid;
			MyEvent.Header.Class.Type = MY_EVENT_TYPE;
			MyEvent.Header.Class.Version = 1;
			MyEvent.Header.Class.Level = dwLevel;

			// Load the event data. You can also use the DEFINE_TRACE_MOF_FIELD
			// macro defined in evntrace.h to set the MOF_FIELD members. For example,
			// DEFINE_TRACE_MOF_FIELD(&EventData.Data[0], &EventData.Cost, sizeof(EventData.Cost), 0);

			MyEvent.Data[0].DataPtr = (ULONG64) szTrace;
			MyEvent.Data[0].Length = (ULONG) (sizeof(WCHAR) * (1 + wcslen(szTrace)));
			MyEvent.Data[0].DataType = ETW_STRING_TYPE_VALUE;

			// Write the event.

			status = TraceEvent(g_SessionHandle, &(MyEvent.Header));
			if (ERROR_SUCCESS != status)
			{
				g_bTracingEnabled = FALSE;
			}
		}
	}
}

void TraceEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...) 
{
	WCHAR Buffer[256];
	WCHAR Buffer2[356];
	int ret;
	va_list ap;
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFile);
#endif
	if (!hPub) TracingRegister();
	if ( g_bTracingEnabled || fDebugOutputIsEnabled) {

		va_start (ap, szFormat);
		ret = _vsnwprintf_s (Buffer, 256, _TRUNCATE, szFormat, ap);
		va_end (ap);
		if (ret <= 0) return;
		if (ret > 256) ret = 255;
		Buffer[255] = L'\0';
		if (fDebugOutputIsEnabled)
		{
			swprintf_s(Buffer2,356,L"%S(%d) : %S - %s\r\n",szFile,dwLine,szFunction,Buffer);
			OutputDebugString(Buffer2);
		}
		if (g_bTracingEnabled)
		{
			swprintf_s(Buffer2,356,L"%S(%d) : %s",szFunction,dwLine,Buffer);
			WriteTrace(dwLevel, Buffer2);
		}
	}
}



void TraceDumpEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel,
			  __in PBYTE pbCmd, __in DWORD dwCmdSize)
{
	WCHAR szData[10 * 3 + 1];
	DWORD dwI;
	PWSTR szPointer = szData;
	for(dwI = 0; dwI < dwCmdSize; dwI++)
	{
		if (dwI%10 == 0 && dwI != 0)
		{
			TraceEx(szFile,dwLine,szFunction,dwLevel,L"DUMP : %s",szData);
			szPointer = szData;
		}
		swprintf_s(szPointer + 3 * (dwI%10),4,L"%02X ",pbCmd[dwI]);
		
	}
	TraceEx(szFile,dwLine,szFunction,dwLevel,L"DUMP : %s",szData);
}

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex(DWORD status, LPCSTR szFile, DWORD dwLine) {
	LPVOID Error;
	TCHAR szTitle[1024];
#ifdef UNICODE
	_stprintf_s(szTitle,ARRAYSIZE(szTitle),TEXT("%S(%d)"),szFile, dwLine);
#else
	_stprintf_s(szTitle,ARRAYSIZE(szTitle),TEXT("%s(%d)"),szFile, dwLine);
#endif
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,status,0,(LPTSTR)&Error,0,NULL);
	MessageBox(NULL,(LPCTSTR)Error,szTitle ,MB_ICONASTERISK);
	LocalFree(Error);
}

BOOL StartLogging()
{
	BOOL fReturn = FALSE;
	TRACEHANDLE SessionHandle;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	ULONG err;
	__try
	{
		memset(&Properties, 0, sizeof(Properties));
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		Properties.TraceProperties.Wnode.Guid = TracingGuid;
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.Wnode.ClientContext = 1;
		Properties.TraceProperties.LogFileMode = 4864; 
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
		Properties.TraceProperties.MaximumFileSize = 8;
		_tcscpy_s(Properties.LogFileName,1024,TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\OpenPGPmdrv.etl"));
		DeleteFile(Properties.LogFileName);
		err = StartTrace(&SessionHandle, TEXT("OpenPGPmdrv"), &(Properties.TraceProperties));
		if (err != ERROR_SUCCESS)
		{
			MessageBoxWin32(err);
			__leave;
		}
		err = EnableTraceEx(&TracingGuid,NULL,SessionHandle,TRUE,WINEVENT_LEVEL_VERBOSE,0,0,0,NULL);
		if (err != ERROR_SUCCESS)
		{
			MessageBoxWin32(err);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	return fReturn;
}

void StopLogging()
{
	LONG err;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	memset(&Properties, 0, sizeof(Properties));
	Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
	Properties.TraceProperties.Wnode.Guid = TracingGuid;
	Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	Properties.TraceProperties.LogFileMode = 4864; 
	Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(TCHAR);
	Properties.TraceProperties.MaximumFileSize = 8;
	err = ControlTrace((TRACEHANDLE)NULL, TEXT("OpenPGPmdrv"), &(Properties.TraceProperties),EVENT_TRACE_CONTROL_STOP);
	if (err != ERROR_SUCCESS && err != 0x00001069)
	{
		MessageBoxWin32(err);
	}
}

void EnableLogging()
{
	DWORD64 qdwValue;
	DWORD dwValue;
	LONG err;

	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("Guid"), REG_SZ, TEXT("{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"),sizeof(TEXT("{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}")));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("FileName"), REG_SZ, TEXT("c:\\windows\\system32\\LogFiles\\WMI\\OpenPGPmdrv.etl"),sizeof(TEXT("c:\\windows\\system32\\LogFiles\\WMI\\OpenPGPmdrv.etl")));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 8;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("FileMax"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 1;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("Start"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 8;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("BufferSize"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("FlushTimer"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("MaximumBuffers"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("MinimumBuffers"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 1;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("ClockType"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 64;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("MaxFileSize"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 4864;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("LogFileMode"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 5;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("FileCounter"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"), 
		TEXT("Status"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}

	dwValue = 1;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv\\{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"), 
		TEXT("Enabled"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 5;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv\\{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"), 
		TEXT("EnableLevel"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv\\{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"), 
		TEXT("EnableProperty"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv\\{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"), 
		TEXT("Status"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	qdwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv\\{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"), 
		TEXT("MatchAllKeyword"), REG_QWORD,&qdwValue,sizeof(DWORD64));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	qdwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv\\{081CCE5F-5F9C-4b43-9A15-1DCF5D2D45F5}"), 
		TEXT("MatchAnyKeyword"), REG_QWORD,&qdwValue,sizeof(DWORD64));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	StartLogging();
}

void DisableLogging()
{
	
	LONG err = RegDeleteTree(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\OpenPGPmdrv"));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	StopLogging();
}
