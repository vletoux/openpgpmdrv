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
#include "cardmod.h"
#include "Tracing.h"

// 4.8 Secure key injection


/** The CardImportSessionKey function imports a temporary session key to the card.
The session key is encrypted with a key exchange key, and the function returns a
handle of the imported session key to the caller.*/

DWORD WINAPI CardImportSessionKey(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in VOID  *pPaddingInfo,
    __in LPCWSTR  pwszBlobType,
    __in LPCWSTR  pwszAlgId,
    __out CARD_KEY_HANDLE  *phKey,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The MDImportSessionKey function imports a temporary session key to the card minidriver
and returns a key handle to the caller.*/

DWORD WINAPI MDImportSessionKey(
    __in PCARD_DATA  pCardData,
    __in LPCWSTR  pwszBlobType,
    __in LPCWSTR  pwszAlgId,
    __out PCARD_KEY_HANDLE  phKey,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The MDEncryptData function uses a key handle to encrypt data with a symmetric key.
The data is encrypted in a format that the smart card supports.*/

DWORD WINAPI MDEncryptData(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszSecureFunction,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags,
    __deref_out_ecount(*pcEncryptedData) 
        PCARD_ENCRYPTED_DATA  *ppEncryptedData,
    __out PDWORD  pcEncryptedData
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


/** The CardGetSharedKeyHandle function returns a session key handle to the caller.
Note:  The manner in which this session key has been established is outside the 
scope of this specification. For example, the session key could be established 
by either a permanent shared key or a key derivation algorithm that has occurred 
before the call to CardGetSharedKeyHandle.*/

DWORD WINAPI CardGetSharedKeyHandle(
    __in PCARD_DATA  pCardData,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __deref_opt_out_bcount(*pcbOutput)
        PBYTE  *ppbOutput,
    __out_opt PDWORD  pcbOutput,
    __out PCARD_KEY_HANDLE  phKey
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardDestroyKey function releases a temporary key on the card. The card 
should delete all of the key material that is associated with that key handle.*/

DWORD WINAPI CardDestroyKey(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function can be used to get properties for a cryptographic algorithm.*/
DWORD WINAPI CardGetAlgorithmProperty (
    __in PCARD_DATA  pCardData,
    __in LPCWSTR   pwszAlgId,
    __in LPCWSTR   pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)
        PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function is used to get the properties of a key.*/
DWORD WINAPI CardGetKeyProperty(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
    )
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function is used to set the properties of a key.*/
DWORD WINAPI CardSetKeyProperty(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszProperty,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** CardProcessEncryptedData processes a set of encrypted data BLOBs by 
sending them to the card where the data BLOBs are decrypted.*/

DWORD WINAPI CardProcessEncryptedData(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszSecureFunction,
    __in_ecount(cEncryptedData)
        PCARD_ENCRYPTED_DATA  pEncryptedData,
    __in DWORD  cEncryptedData,
    __out_bcount_part_opt(cbOutput, *pdwOutputLen)
        PBYTE  pbOutput,
    __in DWORD  cbOutput,
    __out_opt PDWORD  pdwOutputLen,
    __in DWORD  dwFlags
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

