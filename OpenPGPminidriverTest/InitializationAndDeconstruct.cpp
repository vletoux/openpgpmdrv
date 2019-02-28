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
#include "cardmod.h"

#pragma comment(lib,"Scarddlg")
#pragma comment(lib,"Winscard")

HMODULE hModule = NULL;
CARD_DATA CardData;
PCARD_DATA pCardData = NULL;
SCARD_ATRMASK atr;
TCHAR szCard[256];

extern "C" {

	//
	// Heap helpers
	//

	LPVOID	WINAPI _Alloc(__in        SIZE_T cBytes)
	{
		return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cBytes);
	}

	LPVOID WINAPI _ReAlloc(
		__in        LPVOID pvMem,
		__in        SIZE_T cBytes)
	{
		return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pvMem, cBytes);
	}

	void WINAPI	_Free(
		__in        LPVOID pvMem)
	{
		HeapFree(GetProcessHeap(), 0, pvMem);
	}

	//
	// Dummy data caching stubs to satisfy the card module callback requirements
	//

	DWORD WINAPI _CacheAddFileStub(
		IN      PVOID       pvCacheContext,
		IN      LPWSTR      wszTag,
		IN      DWORD       dwFlags,
		IN      PBYTE       pbData,
		IN      DWORD       cbData)
	{
		UNREFERENCED_PARAMETER(pvCacheContext);
		UNREFERENCED_PARAMETER(wszTag);
		UNREFERENCED_PARAMETER(dwFlags);
		UNREFERENCED_PARAMETER(pbData);
		UNREFERENCED_PARAMETER(cbData);
		return ERROR_SUCCESS;
	}

	DWORD WINAPI _CacheLookupFileStub(
		IN      PVOID       pvCacheContext,
		IN      LPWSTR      wszTag,
		IN      DWORD       dwFlags,
		IN      PBYTE      *ppbData,
		IN      PDWORD      pcbData)
	{
		UNREFERENCED_PARAMETER(pvCacheContext);
		UNREFERENCED_PARAMETER(wszTag);
		UNREFERENCED_PARAMETER(dwFlags);
		UNREFERENCED_PARAMETER(ppbData);
		UNREFERENCED_PARAMETER(pcbData);
		return ERROR_NOT_FOUND;
	}

	DWORD WINAPI _CacheDeleteFileStub(
		IN      PVOID       pvCacheContext,
		IN      LPWSTR      wszTag,
		IN      DWORD       dwFlags)
	{
		UNREFERENCED_PARAMETER(pvCacheContext);
		UNREFERENCED_PARAMETER(wszTag);
		UNREFERENCED_PARAMETER(dwFlags);
		return ERROR_SUCCESS;
	}
}

DWORD Connect(BOOL fSystemDll)
{
	DWORD dwReturn = 0;
	SCARDCONTEXT     hSCardContext = NULL;
	SCARDHANDLE hSCardHandle = NULL;
	TCHAR szCardModule[256];
	TCHAR szReader[256];
	DWORD dwCardModuleSize = ARRAYSIZE(szCardModule);
	DWORD dwReaderSize = ARRAYSIZE(szReader);
	OPENCARDNAME_EX  dlgStruct;
	PFN_CARD_ACQUIRE_CONTEXT pfnCardAcquireContext;
	
	__try
	{
		// find a smart card
		/////////////////////
		
		dwReturn = SCardEstablishContext(SCARD_SCOPE_USER,
										NULL,
										NULL,
										&hSCardContext );
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}

		// Initialize the structure.
		memset(&dlgStruct, 0, sizeof(dlgStruct));
		dlgStruct.dwStructSize = sizeof(dlgStruct);
		dlgStruct.hSCardContext = hSCardContext;
		dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
		dlgStruct.lpstrRdr = szReader;
		dlgStruct.nMaxRdr = dwReaderSize;
		dlgStruct.lpstrCard = szCard;
		dlgStruct.nMaxCard = ARRAYSIZE(szCard);
		dlgStruct.lpstrTitle = L"Select Card";
		dlgStruct.dwShareMode = 0;
		// Display the select card dialog box.
		dwReturn = SCardUIDlgSelectCard(&dlgStruct);
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}

		// find the dll path / name
		////////////////////////////
		if (fSystemDll)
		{
			
			dwReturn = SCardGetCardTypeProviderName(
				hSCardContext,
				szCard,
				SCARD_PROVIDER_CARD_MODULE,
				(PTSTR) &szCardModule,
				&dwCardModuleSize);
			if (0 == dwCardModuleSize)
			{
				dwReturn = (DWORD) SCARD_E_UNKNOWN_CARD;
				__leave;
			}
		}
		else
		{
#ifdef _M_X64
			_tcscpy_s(szCardModule, dwCardModuleSize, TEXT("openpgpmdrv64.dll"));
#else
			_tcscpy_s(szCardModule, dwCardModuleSize, TEXT("openpgpmdrv32.dll"));
#endif
		}
		// connect to the smart card
		////////////////////////////
		DWORD dwProtocol, dwState;
		dwReturn = SCardConnect(hSCardContext,szReader,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1|SCARD_PROTOCOL_T0, &hSCardHandle, &dwProtocol);
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}
		atr.cbAtr = 32;
		dwReturn = SCardStatus(hSCardHandle, szReader, &dwReaderSize, &dwState, &dwProtocol, atr.rgbAtr,&atr.cbAtr);
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}
		// load
		////////
		if (NULL == (hModule = LoadLibrary(szCardModule)))
        {
            dwReturn = GetLastError();
            __leave;
        }

        if (NULL == (pfnCardAcquireContext = 
                     (PFN_CARD_ACQUIRE_CONTEXT) GetProcAddress(
                         hModule, "CardAcquireContext")))
        {
            dwReturn = GetLastError();
            __leave;
        }
		// initialize context
		//////////////////////
		pCardData = &CardData;
		pCardData->dwVersion = CARD_DATA_CURRENT_VERSION;
        pCardData->pfnCspAlloc = _Alloc;
        pCardData->pfnCspFree = _Free;
        pCardData->pfnCspReAlloc = _ReAlloc;
        pCardData->pfnCspCacheAddFile = _CacheAddFileStub;
        pCardData->pfnCspCacheLookupFile = _CacheLookupFileStub;
        pCardData->pfnCspCacheDeleteFile = _CacheDeleteFileStub;
        pCardData->hScard = hSCardHandle;
        pCardData->hSCardCtx = hSCardContext;
		pCardData->cbAtr = atr.cbAtr;
		pCardData->pbAtr = atr.rgbAtr;
		pCardData->pwszCardName = szCard;
		//dwReturn = SCardBeginTransaction(hSCardHandle);
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}
		dwReturn = pfnCardAcquireContext(pCardData, 0);
	}
	__finally
	{
		if (dwReturn != 0)
		{
			if (hSCardHandle)
			{
				SCardEndTransaction(hSCardHandle,SCARD_LEAVE_CARD);
				SCardDisconnect(hSCardHandle,0);
			}
			if (hSCardContext)
				SCardReleaseContext(hSCardContext);
		}
	}
	return dwReturn;
}

DWORD Disconnect()
{
	DWORD dwReturn = 0;
	if (pCardData)
	{
		if (pCardData->hScard)
		{
			SCardEndTransaction(pCardData->hScard,SCARD_LEAVE_CARD);
			SCardDisconnect(pCardData->hScard,0);
		}
		if (pCardData->hSCardCtx)
			SCardReleaseContext(pCardData->hSCardCtx);
		pCardData = NULL;
	}
	else
	{
		dwReturn = SCARD_E_COMM_DATA_LOST;
	}
	return dwReturn;
}