#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>
#include <commctrl.h>
#include "cardmod.h"
#include <Xenroll.h>
#include <CertEnroll.h>

BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen);

BSTR GetAuthenticationContainer()
{
	BSTR szSignatureContainer = NULL;
	HCRYPTPROV HMainCryptProv = NULL;
	BOOL bStatus = FALSE;
	LPTSTR szMainContainerName = NULL;
	CHAR szContainerName[1024];
	DWORD dwContainerNameLen = sizeof(szContainerName);
	DWORD dwErr = 0;
	DWORD dwFlags = CRYPT_FIRST;
	DWORD dwContextArrayLen = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	LPBYTE pbCert = NULL;
	DWORD dwCertLen = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	PCCERT_CONTEXT pSelectedContext = NULL;
	HCERTSTORE hStore = NULL;
	TCHAR szCardName[256];
	TCHAR szReaderName[256];
	TCHAR szOutProviderName[256];
	DWORD dwOutProviderLength = ARRAYSIZE(szOutProviderName);
	OPENCARDNAME_EX  dlgStruct;
	DWORD dwReturn;
	SCARDCONTEXT     hSCardContext = NULL;
	SCARDHANDLE hSCardHandle = NULL;
	LPWSTR szWideContainerName = NULL;
	__try
	{
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
		dlgStruct.lpstrRdr = szReaderName;
		dlgStruct.nMaxRdr = ARRAYSIZE(szReaderName);
		dlgStruct.lpstrCard = szCardName;
		dlgStruct.nMaxCard = ARRAYSIZE(szCardName);
		dlgStruct.lpstrTitle = L"Select Card";
		dlgStruct.dwShareMode = 0;
		// Display the select card dialog box.
		dwReturn = SCardUIDlgSelectCard(&dlgStruct);
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}
		dwReturn = SCardUIDlgSelectCard(&dlgStruct);
		if ( SCARD_S_SUCCESS != dwReturn )
		{
			__leave;
		}
		if (!SchGetProviderNameFromCardName(szCardName, szOutProviderName, &dwOutProviderLength))
		{
			dwReturn = GetLastError();
			__leave;
		}
	
		size_t ulNameLen = _tcslen(szReaderName);
		szMainContainerName = (LPWSTR) LocalAlloc(0,(DWORD)(ulNameLen + 6) * sizeof(WCHAR));
		if (!szMainContainerName)
		{
			dwReturn = GetLastError();
			__leave;
		}
		swprintf_s(szMainContainerName,(ulNameLen + 6), L"\\\\.\\%s\\", szReaderName);

		bStatus = CryptAcquireContext(&HMainCryptProv,
					szMainContainerName,
					szOutProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			if (dwReturn == NTE_BAD_KEYSET)
			{
				bStatus = CryptAcquireContext(&HMainCryptProv,NULL,	szOutProviderName,	PROV_RSA_FULL,	CRYPT_SILENT);
				if (!bStatus)
				{
					dwReturn = GetLastError();
					__leave;
				}
			}
			else
			{
				__leave;
			}
			
		}



		/* Enumerate all the containers */
		while (CryptGetProvParam(HMainCryptProv,
					PP_ENUMCONTAINERS,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					dwFlags) &&
				(dwContextArrayLen < 128)
				)
		{

			// convert the container name to unicode
			int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
			szWideContainerName = (LPWSTR) LocalAlloc(0,wLen * sizeof(WCHAR));
			MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);

			// Acquire a context on the current container
			if (CryptAcquireContext(&hProv,
					szWideContainerName,
					szOutProviderName,
					PROV_RSA_FULL,
					0))
			{
				// Loop over all the key specs
				if (CryptGetUserKey(hProv,
						AT_SIGNATURE,
						&hKey) )
				{
					if (wcsncmp(szWideContainerName,L"OPENPGP_",8) == 0
						&& wcsstr(szWideContainerName, L"_Authenticate") != NULL)
					{
						szSignatureContainer = SysAllocString(szWideContainerName);
					}
					CryptDestroyKey(hKey);
					hKey = NULL;
				}
				CryptReleaseContext(hProv, 0);
				hProv = NULL;
			}
			LocalFree(szWideContainerName);
			szWideContainerName = NULL;
			// prepare parameters for the next loop
			dwContainerNameLen = sizeof(szContainerName);
			dwFlags = 0;
		}
	}
	__finally
	{
		if (szWideContainerName)
			LocalFree(szWideContainerName);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
		if (szMainContainerName)
			LocalFree(szMainContainerName);
		if (HMainCryptProv)
			CryptReleaseContext(HMainCryptProv, 0);
	}
	return szSignatureContainer;
}


HRESULT Enroll()
{
	BSTR bstrDN = NULL;
	BSTR bstrReq = NULL;
	BSTR bstrOID = NULL;
	ICEnroll4 * pEnroll = NULL;
	HRESULT hr;

	__try
	{
		// initialize COM
		hr = CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
		if (FAILED(hr))
		{
			__leave;
		}

		hr = CoCreateInstance( __uuidof(CEnroll2),
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   __uuidof(IEnroll4),
							   (void **)&pEnroll);
		if (FAILED(hr))
		{
			__leave;
		}
		pEnroll->put_ContainerName(GetAuthenticationContainer());
		pEnroll->put_KeySpec(AT_SIGNATURE);
		pEnroll->put_UseExistingKeySet(TRUE);
		pEnroll->put_WriteCertToCSP(FALSE);
		// generate the DN for the cert request
		bstrDN = SysAllocString( TEXT("CN=Your Name")   // common name
								 TEXT(",OU=Your Unit")  // org unit
								 TEXT(",O=Your Org")    // organization
								 TEXT(",L=Your City")   // locality
								 TEXT(",S=Your State")  // state
								 TEXT(",C=Your Country") );  // country/region
		if (NULL == bstrDN)
		{
			hr = GetLastError();
			__leave;
		}

		// generate the OID, for example, "1.3.6.1.4.1.311.2.1.21".
		bstrOID = SysAllocString(TEXT("1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.20.2.2"));
		if (NULL == bstrOID)
		{
			__leave;
		}

		// create the PKCS10
		hr = pEnroll->createPKCS10( bstrDN, bstrOID, &bstrReq );
		if (FAILED(hr))
		{
			__leave;
		}
		// do something with the PKCS10 (bstrReq);

	}
	__finally
	{

		//clean up resources, etc.
		if ( bstrDN )
			SysFreeString( bstrDN );
		if ( bstrOID )
			SysFreeString( bstrOID );
		if ( bstrReq )
			SysFreeString( bstrReq );
		if ( pEnroll )
			pEnroll->Release();

		CoUninitialize();
	}
	return hr;
}