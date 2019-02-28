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
#include <stdio.h>
#include "cardmod.h"
#include "global.h"
#include "dialog.h"


DWORD ListFiles(HWND hWnd, PSTR szDirectory)
{
	DWORD dwReturn = 0, dwSize;
	LPSTR pszFiles = NULL;
	
	dwSize = 0;
	dwReturn = pCardData->pfnCardEnumFiles(pCardData, szDirectory, &pszFiles, &dwSize, 0);
	if (!dwReturn)
	{
		LPSTR szCurrentFile = pszFiles;
		while (szCurrentFile[0] != 0)
		{
			CHAR szText[256];
			if (szDirectory)
			{
				sprintf_s(szText, ARRAYSIZE(szText),"%s\\%s",szDirectory, szCurrentFile);
			}
			else
			{
				sprintf_s(szText, ARRAYSIZE(szText),"%s",szCurrentFile);
			}
			SendDlgItemMessageA(hWnd,IDC_FILES,LB_ADDSTRING,0,(LPARAM)szText);
			if (_stricmp(szCurrentFile,"cardapps") == 0)
			{
				PBYTE pbData = NULL;
				dwSize = 0;
				dwReturn = pCardData->pfnCardReadFile(pCardData, szDirectory, szCurrentFile, 0, &pbData, &dwSize);
				if (dwReturn == 0)
				{
					CHAR szDirectory[9];
					for (DWORD dwI = 0; dwI < dwSize; dwI+=8)
					{
						memcpy(szDirectory, pbData + dwI, 8);
						szDirectory[8] = 0;
						ListFiles(hWnd, szDirectory);
					}

					pCardData->pfnCspFree(pbData);
				}
			}
			
			szCurrentFile = szCurrentFile + strlen(szCurrentFile)+1;
		}
		pCardData->pfnCspFree(pszFiles);
	}
	return dwReturn;
}

DWORD ListFiles(HWND hWnd)
{
	if (!pCardData)
	{
		return SCARD_E_COMM_DATA_LOST;
	}
	SendMessage(GetDlgItem(hWnd, IDC_FILES),LB_RESETCONTENT,0,0);
	return ListFiles(hWnd, NULL);
}

DWORD ViewFile(HWND hWnd)
{
	CHAR szFileName[256];
	PSTR szFile, szDirectory;
	DWORD dwReturn;
	PBYTE pbData = NULL;
	DWORD dwSize;
	TCHAR szData[10];
	__try
	{
		// clear text
		SendMessage( GetDlgItem(hWnd, IDC_CONTENT), WM_SETTEXT,0,(LPARAM) "");

		DWORD iItem = (DWORD)SendMessage(GetDlgItem(hWnd, IDC_FILES),LB_GETCURSEL,0,0);
		if (iItem == LB_ERR) 
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		SendMessageA( GetDlgItem(hWnd,IDC_FILES), LB_GETTEXT,iItem,(LPARAM)szFileName);

		szFile = strchr(szFileName,'\\');
		if (szFile)
		{
			*szFile = 0;
			szFile++;
			szDirectory = szFileName;
		}
		else
		{
			szDirectory = NULL;
			szFile = szFileName;
		}
		dwReturn = pCardData->pfnCardReadFile(pCardData,szDirectory,szFile, 0, &pbData, &dwSize);
		if (dwReturn)
		{
			__leave;
		}
		if (strcmp(szDirectory, "openpgp") == 0 && strcmp(szFile, "certific") == 0 )
		{
			PCCERT_CONTEXT pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING , pbData, dwSize);
			if (!pCertContext)
			{
				dwReturn = GetLastError();
				__leave;
			}
			ViewCertificate(hWnd, pCertContext);
			CertFreeCertificateContext(pCertContext);
		}
		else
		{
			for(DWORD dwI = 0; dwI < dwSize; dwI++)
			{
				_stprintf_s(szData,ARRAYSIZE(szData),TEXT("%02X "),pbData[dwI]);
				SendMessage(    // returns LRESULT in lResult
					   GetDlgItem(hWnd, IDC_CONTENT),           // (HWND) handle to destination control
					   EM_REPLACESEL,         // (UINT) message ID
					   FALSE,                // = () wParam; 
					   (LPARAM)szData                 // = (LPARAM)(LPCTSTR) lParam;
					);

			}
		}
	}
	__finally
	{
		if (pbData)
			pCardData->pfnCspFree(pbData);
	}
	return dwReturn;
}
