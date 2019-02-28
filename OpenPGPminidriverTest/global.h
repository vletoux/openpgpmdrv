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

extern PCARD_DATA pCardData;
DWORD Connect(BOOL fSystemDll);
DWORD Disconnect();
DWORD Authenticate(PSTR wszPin, PWSTR wszUserId, PDWORD pcAttemptsRemaining);
DWORD ResetPin(PSTR wszPin, PSTR wszPin2, BOOL fIsPUK, PDWORD pcAttemptsRemaining);
DWORD ChangePin(PSTR szPin, PSTR szPin2, PWSTR wszUserId, PDWORD pcAttemptsRemaining);
DWORD SetPuk(PSTR szPin, PSTR szPin2, PDWORD pcAttemptsRemaining);
DWORD SetSM(PSTR szPin, PSTR szPin2, PDWORD pcAttemptsRemaining);
DWORD ListFiles(HWND hWnd);
DWORD ViewFile(HWND hWnd);
DWORD ListContainer(HWND hWnd);
DWORD ViewCertificate(HWND hWnd, PTSTR szContainer, DWORD dwKeySpec);
DWORD Sign(PTSTR szContainer, DWORD dwKeySpec);
DWORD Decrypt(PTSTR szContainer, DWORD dwKeySpec);
DWORD GenerateNewKey(DWORD dwIndex);
DWORD ImportKey(DWORD dwIndex);
DWORD SetTheSameKeyForAllContainers();
DWORD SetReadOnly(BOOL fSet);
void ViewCertificate(HWND hWnd, PCCERT_CONTEXT pCertContext);
DWORD Personnalize();
HRESULT Enroll();
#define OPENPGP_TEST_CONTAINER TEXT("Test_OPENPGPG")