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
#include <Cryptuiapi.h>
#include <commctrl.h>
#include "cardmod.h"
#include "dialog.h"
#include "global.h"
#pragma comment(lib,"Cryptui")
#pragma comment(lib,"Crypt32")


BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen)
{
	// get provider name
	SCARDCONTEXT hSCardContext;
	LONG lCardStatus;
	lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		return FALSE;
	}
	
	lCardStatus = SCardGetCardTypeProviderName(hSCardContext,
									   szCardName,
									   SCARD_PROVIDER_CSP,
									   szProviderName,
									   pdwProviderNameLen);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		SCardReleaseContext(hSCardContext);
		return FALSE;
	}
	SCardReleaseContext(hSCardContext);
	return TRUE;
}

DWORD ListContainer(HWND hWnd)
{
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
	DWORD pKeySpecs[2] = { AT_KEYEXCHANGE,AT_SIGNATURE};
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
	__try
	{
		
		SendMessage(GetDlgItem(hWnd, IDC_LSTCONTAINER),LB_RESETCONTENT,0,0);
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
			LPWSTR szWideContainerName = (LPWSTR) LocalAlloc(0,wLen * sizeof(WCHAR));
			MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);

			// Acquire a context on the current container
			if (CryptAcquireContext(&hProv,
					szWideContainerName,
					szOutProviderName,
					PROV_RSA_FULL,
					0))
			{
				// Loop over all the key specs
				for (int i = 0; i < 2; i++)
				{
					if (CryptGetUserKey(hProv,
							pKeySpecs[i],
							&hKey) )
					{
						TCHAR szText[256];
						_stprintf_s(szText, ARRAYSIZE(szText), TEXT("%s %d"),szWideContainerName,pKeySpecs[i]);
						SendDlgItemMessage(hWnd,IDC_LSTCONTAINER,LB_ADDSTRING,0,(LPARAM)szText);
						CryptDestroyKey(hKey);
						hKey = NULL;
					}
				}
				CryptReleaseContext(hProv, 0);
				hProv = NULL;
			}
			LocalFree(szWideContainerName);
			
			// prepare parameters for the next loop
			dwContainerNameLen = sizeof(szContainerName);
			dwFlags = 0;
		}
	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
		if (szMainContainerName)
			LocalFree(szMainContainerName);
		if (HMainCryptProv)
			CryptReleaseContext(HMainCryptProv, 0);
	}
	return dwReturn;
}


DWORD ViewCertificate(HWND hWnd, PTSTR szContainer, DWORD dwKeySpec)
{
	BOOL bStatus;
	DWORD dwReturn = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwCertLen = 0;
	PBYTE pbCert = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
	__try
	{
		bStatus = CryptAcquireContext(&hProv,szContainer, MS_SCARD_PROV, PROV_RSA_FULL,	CRYPT_SILENT);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptGetUserKey(hProv, dwKeySpec, &hKey);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptGetKeyParam(hKey,
								KP_CERTIFICATE,
								NULL,
								&dwCertLen,
								0);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		pbCert = (LPBYTE) LocalAlloc(0,dwCertLen);
		if (!pbCert)
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptGetKeyParam(hKey,
							KP_CERTIFICATE,
							pbCert,
							&dwCertLen,
							0);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		pCertContext = CertCreateCertificateContext(
						X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 
						pbCert,
						dwCertLen);
		if (!pCertContext)
		{
			dwReturn = GetLastError();
			__leave;
		}
						
		certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
		certViewInfo.hwndParent = hWnd;
		certViewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DISABLE_HTMLLINK;
		certViewInfo.szTitle = TEXT("Info");
		certViewInfo.pCertContext = pCertContext;
		certViewInfo.cPurposes = 0;
		certViewInfo.rgszPurposes = 0;
		certViewInfo.pCryptProviderData = NULL;
		certViewInfo.hWVTStateData = NULL;
		certViewInfo.fpCryptProviderDataTrustedUsage = FALSE;
		certViewInfo.idxSigner = 0;
		certViewInfo.idxCert = 0;
		certViewInfo.fCounterSigner = FALSE;
		certViewInfo.idxCounterSigner = 0;
		certViewInfo.cStores = 0;
		certViewInfo.rghStores = NULL;
		certViewInfo.cPropSheetPages = 0;
		certViewInfo.rgPropSheetPages = NULL;
		certViewInfo.nStartPage = 0;
						
		dwReturn = CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
		
	}
	__finally
	{
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (pbCert)
			LocalFree(pbCert);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	return dwReturn;
}

DWORD Sign(PTSTR szContainer, DWORD dwKeySpec)
{
	BOOL bStatus;
	DWORD dwReturn = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	PBYTE pbSignature = NULL;
	DWORD dwSignatureSize = 0;
	PBYTE pbSignatureTest = NULL;
	DWORD dwSignatureTestSize = 0;
	BYTE pbChallenge[20];
	TCHAR szDescription[] = TEXT("Test");
	TCHAR szContainerName[] = OPENPGP_TEST_CONTAINER;
	__try
	{
		bStatus = CryptAcquireContext(&hProv,szContainer, MS_SCARD_PROV, PROV_RSA_FULL,	0);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptGetUserKey(hProv, dwKeySpec, &hKey);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptGenRandom(hProv,ARRAYSIZE(pbChallenge),pbChallenge);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, pbChallenge, 0))
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, szDescription, 0, NULL, &dwSignatureSize))
		{
			dwReturn = GetLastError();
			__leave;
		}
		pbSignature = (PBYTE) LocalAlloc(0,dwSignatureSize);
		if (!pbSignature)
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, szDescription, 0, pbSignature, &dwSignatureSize))
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CryptVerifySignature(hHash, pbSignature, dwSignatureSize, hKey, szDescription, 0))
		{
			dwReturn = GetLastError();
		}
	}
	__finally
	{
		if (pbSignature)
			LocalFree(pbSignature);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	return dwReturn;
}

DWORD Decrypt(PTSTR szContainer, DWORD dwKeySpec)
{
	BOOL bStatus;
	DWORD dwReturn = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	PBYTE pbCrypt = NULL;
	DWORD dwCryptSize = 0, dwBufferSize;
	BYTE pbChallenge[20] = "test1234567890";
	__try
	{
		bStatus = CryptAcquireContext(&hProv,szContainer, MS_SCARD_PROV, PROV_RSA_FULL,	0);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptGetUserKey(hProv, dwKeySpec, &hKey);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}
		/*bStatus = CryptGenRandom(hProv,ARRAYSIZE(pbChallenge),pbChallenge);
		if (!bStatus)
		{
			dwReturn = GetLastError();
			__leave;
		}*/
		dwCryptSize = 0;
		dwBufferSize = ARRAYSIZE(pbChallenge);
		if (!CryptEncrypt(hKey,NULL, TRUE, 0, NULL, &dwBufferSize,0))
		{
			dwReturn = GetLastError();
			__leave;
		}
		pbCrypt = (PBYTE) LocalAlloc(0,dwBufferSize);
		if (!pbCrypt)
		{
			dwReturn = GetLastError();
			__leave;
		}
		memcpy(pbCrypt, pbChallenge,  ARRAYSIZE(pbChallenge));
		dwCryptSize =  ARRAYSIZE(pbChallenge);
		if (!CryptEncrypt(hKey,NULL, TRUE, 0, pbCrypt, &dwCryptSize,dwBufferSize))
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CryptDecrypt(hKey, NULL, FALSE, 0, pbCrypt, &dwCryptSize))
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (dwCryptSize != ARRAYSIZE(pbChallenge))
		{
			dwReturn = NTE_BAD_DATA;
			__leave;
		}
		if (memcmp(pbChallenge, pbCrypt, dwCryptSize) != 0)
		{
			dwReturn = NTE_BAD_DATA;
			__leave;
		}
	}
	__finally
	{
		if (pbCrypt)
			LocalFree(pbCrypt);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	return dwReturn;
}

