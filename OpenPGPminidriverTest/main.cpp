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
#include <commctrl.h>
#include <Cryptuiapi.h>
#include "dialog.h"
#include "global.h"

#pragma comment(lib,"comctl32")

#ifdef UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

// Variables globales :
HINSTANCE g_hinst;								// instance actuelle

INT_PTR CALLBACK	WndProcConnect(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProcPin(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProcFile(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProcCrypto(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProcCryptoApi(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProcEnroll(HWND, UINT, WPARAM, LPARAM);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	g_hinst = hInstance;
    PROPSHEETPAGE psp[6];
    PROPSHEETHEADER psh;
    psp[0].dwSize = sizeof(PROPSHEETPAGE);
    psp[0].dwFlags = PSP_USETITLE;
    psp[0].hInstance = g_hinst;
    psp[0].pszTemplate = MAKEINTRESOURCE(IDD_CONNECT);
    psp[0].pszIcon = NULL;
    psp[0].pfnDlgProc = WndProcConnect;
    psp[0].pszTitle = TEXT("Connect");
    psp[0].lParam = 0;
    psp[0].pfnCallback = NULL;
    psp[1].dwSize = sizeof(PROPSHEETPAGE);
    psp[1].dwFlags = PSP_USETITLE;
    psp[1].hInstance = g_hinst;
    psp[1].pszTemplate = MAKEINTRESOURCE(IDD_PIN);
    psp[1].pszIcon = NULL;
    psp[1].pfnDlgProc = WndProcPin;
    psp[1].pszTitle = TEXT("Pin");
    psp[1].lParam = 0;
    psp[2].pfnCallback = NULL;
	psp[2].dwSize = sizeof(PROPSHEETPAGE);
    psp[2].dwFlags = PSP_USETITLE;
    psp[2].hInstance = g_hinst;
    psp[2].pszTemplate = MAKEINTRESOURCE(IDD_FILE);
    psp[2].pszIcon = NULL;
    psp[2].pfnDlgProc = WndProcFile;
    psp[2].pszTitle = TEXT("File");
    psp[2].lParam = 0;
    psp[2].pfnCallback = NULL;
	psp[3].dwSize = sizeof(PROPSHEETPAGE);
    psp[3].dwFlags = PSP_USETITLE;
    psp[3].hInstance = g_hinst;
    psp[3].pszTemplate = MAKEINTRESOURCE(IDD_CRYPTO);
    psp[3].pszIcon = NULL;
    psp[3].pfnDlgProc = WndProcCrypto;
    psp[3].pszTitle = TEXT("Crypto");
    psp[3].lParam = 0;
    psp[3].pfnCallback = NULL;
	psp[4].dwSize = sizeof(PROPSHEETPAGE);
    psp[4].dwFlags = PSP_USETITLE;
    psp[4].hInstance = g_hinst;
    psp[4].pszTemplate = MAKEINTRESOURCE(IDD_CRYPTOAPI);
    psp[4].pszIcon = NULL;
    psp[4].pfnDlgProc = WndProcCryptoApi;
    psp[4].pszTitle = TEXT("CryptoApi");
    psp[4].lParam = 0;
    psp[4].pfnCallback = NULL;
	psp[5].dwSize = sizeof(PROPSHEETPAGE);
    psp[5].dwFlags = PSP_USETITLE;
    psp[5].hInstance = g_hinst;
    psp[5].pszTemplate = MAKEINTRESOURCE(IDD_ENROLL);
    psp[5].pszIcon = NULL;
    psp[5].pfnDlgProc = WndProcEnroll;
    psp[5].pszTitle = TEXT("Enroll");
    psp[5].lParam = 0;
    psp[5].pfnCallback = NULL;
    psh.dwSize = sizeof(PROPSHEETHEADER);
    psh.dwFlags = PSH_USEICONID | PSH_PROPSHEETPAGE;
    psh.hwndParent = NULL;
    psh.hInstance = g_hinst;
    psh.pszIcon =NULL;
    psh.pszCaption = TEXT("Test");
    psh.nPages = ARRAYSIZE(psp);
    psh.nStartPage = 0;
    psh.ppsp = (LPCPROPSHEETPAGE) &psp;
    psh.pfnCallback = NULL;
    PropertySheet(&psh);
    return 0;

}

void MessageBoxWin32(DWORD status) {
	LPVOID Error;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,status,0,(LPTSTR)&Error,0,NULL);
	MessageBox(NULL,(LPCTSTR)Error,NULL,MB_ICONASTERISK);
	LocalFree(Error);
}


void ViewCertificate(HWND hWnd, PCCERT_CONTEXT pCertContext)
{
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
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
	
	CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
}

#define C_PAGES 5
 
typedef struct tag_dlghdr { 
    HWND hwndTab;       // tab control 
    HWND hwndDisplay;   // current child dialog box 
    RECT rcDisplay;     // display rectangle for the tab control 
    DLGTEMPLATE *apRes[C_PAGES]; 
	DLGPROC pDialogFunc[C_PAGES];
} DLGHDR; 


BOOL GetContainerName(HWND hWnd, PWSTR szContainer, PDWORD pdwKeySpec)
{
	DWORD iItem = (DWORD)SendMessage(GetDlgItem(hWnd, IDC_LSTCONTAINER),LB_GETCURSEL,0,0);
	if (iItem == LB_ERR) return FALSE;
	SendMessage( GetDlgItem(hWnd,IDC_LSTCONTAINER), LB_GETTEXT,iItem,(LPARAM)szContainer);
	*pdwKeySpec = _tstoi(szContainer + _tcslen(szContainer) - 1);
	szContainer[ _tcslen(szContainer) - 2] = 0;
	return TRUE;
}

 
INT_PTR CALLBACK WndProcConnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	DWORD dwReturn;
	switch (message)
	{
	case WM_INITDIALOG:
		CheckDlgButton(hWnd,IDC_CurrentDll,BST_CHECKED);
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		
		switch (wmId)
		{
			case IDC_CONNECT:
			if (IsDlgButtonChecked(hWnd,IDC_SystemDll))
			{
				dwReturn = Connect(TRUE);
			}
			else
			{
				dwReturn = Connect(FALSE);
			}
			if (dwReturn)
			{
				MessageBoxWin32(dwReturn);
			}
			break;
			case IDC_DISCONNECT:
				dwReturn = Disconnect();
				if (dwReturn)
				{
					MessageBoxWin32(dwReturn);
				}
				break;
		}
		break;
	}
	return FALSE;
}

INT_PTR CALLBACK WndProcPin(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	DWORD dwReturn;
	CHAR szPin[256];
	CHAR szPin2[256];
	DWORD dwRemaining;
	switch (message)
	{
	case WM_INITDIALOG:
		CheckDlgButton(hWnd,IDC_PINUSER,BST_CHECKED);
		SendMessage( GetDlgItem(hWnd, IDC_TXTPIN), WM_SETTEXT,0,(LPARAM) TEXT("123456"));
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		
		switch (wmId)
		{
			case IDC_PINUSER:
				SendMessage( GetDlgItem(hWnd, IDC_TXTPIN), WM_SETTEXT,0,(LPARAM) TEXT("123456"));
			break;
			case IDC_PINADMIN:
				SendMessage( GetDlgItem(hWnd, IDC_TXTPIN), WM_SETTEXT,0,(LPARAM) TEXT("12345678"));
			break;
			case IDC_PUK:
				SendMessage( GetDlgItem(hWnd, IDC_TXTPIN), WM_SETTEXT,0,(LPARAM) TEXT("000000"));
			break;
			case IDC_CHECKPIN:
				GetDlgItemTextA(hWnd,IDC_TXTPIN,szPin,ARRAYSIZE(szPin));

				if (IsDlgButtonChecked(hWnd,IDC_PINADMIN))
				{
					dwReturn = Authenticate(szPin, wszCARD_USER_ADMIN, &dwRemaining);
				}
				else
				{
					dwReturn = Authenticate(szPin, wszCARD_USER_USER, &dwRemaining);
				}
				MessageBoxWin32(dwReturn);
				break;
			case IDC_UNBLOCKPIN:
				GetDlgItemTextA(hWnd,IDC_TXTPIN,szPin,ARRAYSIZE(szPin));
				GetDlgItemTextA(hWnd,IDC_TXTPIN2,szPin2,ARRAYSIZE(szPin2));
				if (IsDlgButtonChecked(hWnd,IDC_PINADMIN))
				{
					dwReturn = ResetPin(szPin, szPin2, FALSE, &dwRemaining);
				}
				else if (IsDlgButtonChecked(hWnd,IDC_PUK))
				{
					dwReturn = ResetPin(szPin, szPin2, TRUE, &dwRemaining);
				}
				else
				{
					dwReturn = E_INVALIDARG;
				}
				MessageBoxWin32(dwReturn);
				break;
			case IDC_CHANGEPIN:
				GetDlgItemTextA(hWnd,IDC_TXTPIN,szPin,ARRAYSIZE(szPin));
				GetDlgItemTextA(hWnd,IDC_TXTPIN2,szPin2,ARRAYSIZE(szPin2));
				if (IsDlgButtonChecked(hWnd,IDC_PINADMIN))
				{
					dwReturn = ChangePin(szPin, szPin2, wszCARD_USER_ADMIN, &dwRemaining);
				}
				else if (IsDlgButtonChecked(hWnd,IDC_PINUSER))
				{
					dwReturn = ChangePin(szPin, szPin2, wszCARD_USER_USER, &dwRemaining);
				}
				else
				{
					dwReturn = E_INVALIDARG;
				}
				MessageBoxWin32(dwReturn);
				break;
			case IDC_SETPUK:
				GetDlgItemTextA(hWnd,IDC_TXTPIN,szPin,ARRAYSIZE(szPin));
				GetDlgItemTextA(hWnd,IDC_TXTPIN2,szPin2,ARRAYSIZE(szPin2));
				dwReturn = SetPuk(szPin, szPin2, &dwRemaining);
				MessageBoxWin32(dwReturn);
				break;
			case IDC_SETSM:
				GetDlgItemTextA(hWnd,IDC_TXTPIN,szPin,ARRAYSIZE(szPin));
				GetDlgItemTextA(hWnd,IDC_TXTPIN2,szPin2,ARRAYSIZE(szPin2));
				dwReturn = SetSM(szPin, szPin2, &dwRemaining);
				MessageBoxWin32(dwReturn);
				break;
			case IDC_PERSONNALIZE:
				dwReturn = Personnalize();
				MessageBoxWin32(dwReturn);
				break;
		}
		break;
	}
	return FALSE;
}

INT_PTR CALLBACK WndProcFile(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	DWORD dwReturn;
	switch (message)
	{
	case WM_INITDIALOG:
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		
		switch (wmId)
		{
			case IDC_LISTFILES:
				dwReturn = ListFiles(hWnd);
				if (dwReturn)
				{
					MessageBoxWin32(dwReturn);
				}
				break;
			case IDC_FILES:
				switch(wmEvent)
				{
					case LBN_SELCHANGE:
						dwReturn = ViewFile(hWnd);
						if (dwReturn)
						{
							MessageBoxWin32(dwReturn);
						}
						break;
				}
				break;
		}
		break;
	}
	return FALSE;
}

INT_PTR CALLBACK WndProcCrypto(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	DWORD dwReturn;
	switch (message)
	{
	case WM_INITDIALOG:
		SendDlgItemMessage(hWnd,IDC_CONTAINERINDEX,CB_ADDSTRING,0,(LPARAM)TEXT("Signature"));
		SendDlgItemMessage(hWnd,IDC_CONTAINERINDEX,CB_ADDSTRING,0,(LPARAM)TEXT("Confidentiality"));
		SendDlgItemMessage(hWnd,IDC_CONTAINERINDEX,CB_ADDSTRING,0,(LPARAM)TEXT("Authentication"));
		SendDlgItemMessage(hWnd,IDC_CONTAINERINDEX, CB_SETCURSEL, 0, 0);
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		
		switch (wmId)
		{
			case IDC_NEWKEY:
				dwReturn = GenerateNewKey((DWORD)SendDlgItemMessage(hWnd,IDC_CONTAINERINDEX, CB_GETCURSEL, 0, 0));
				MessageBoxWin32(dwReturn);
				break;
			case IDC_IMPORTKEY:
				dwReturn = ImportKey((DWORD)SendDlgItemMessage(hWnd,IDC_CONTAINERINDEX, CB_GETCURSEL, 0, 0));
				MessageBoxWin32(dwReturn);
				break;
			case IDC_SAMEKEY:
				dwReturn = SetTheSameKeyForAllContainers();
				MessageBoxWin32(dwReturn);
				break;
			case IDC_SETREADONLY:
				dwReturn = SetReadOnly(TRUE);
				MessageBoxWin32(dwReturn);
				break;
			case IDC_UNSETREADONLY:
				dwReturn = SetReadOnly(FALSE);
				MessageBoxWin32(dwReturn);
				break;
		}
		break;
	}
	return FALSE;
}

INT_PTR CALLBACK WndProcCryptoApi(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	DWORD dwReturn;
	TCHAR szContainer[256];
	DWORD dwKeySpec;
	switch (message)
	{
	case WM_INITDIALOG:
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		
		switch (wmId)
		{
			case IDC_CONTAINER:
				dwReturn = ListContainer(hWnd);
				if (dwReturn)
				{
					MessageBoxWin32(dwReturn);
				}
				break;
			case IDC_SIGN:
				if (GetContainerName(hWnd, szContainer, &dwKeySpec))
				{
					dwReturn = Sign(szContainer, dwKeySpec);
					MessageBoxWin32(dwReturn);
				}
				break;
			case IDC_DECRYPT:
				if (GetContainerName(hWnd, szContainer, &dwKeySpec))
				{
					dwReturn = Decrypt(szContainer, dwKeySpec);
					MessageBoxWin32(dwReturn);
				}
				break;
			case IDC_LSTCONTAINER:
				switch(wmEvent)
				{
					case LBN_DBLCLK:
						if (GetContainerName(hWnd, szContainer, &dwKeySpec))
						{
							dwReturn = ViewCertificate(hWnd, szContainer, dwKeySpec);
							if (dwReturn)
							{
								MessageBoxWin32(dwReturn);
							}
						}
						break;
				}
				break;
		}
		break;
	}
	return FALSE;
}

INT_PTR CALLBACK WndProcEnroll(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	DWORD dwReturn;
	switch (message)
	{
	case WM_INITDIALOG:
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		
		switch (wmId)
		{
			case IDC_ENROLL:
				dwReturn = Enroll();
				MessageBoxWin32(dwReturn);
				break;
		}
	}
	return FALSE;
}