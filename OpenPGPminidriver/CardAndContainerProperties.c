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
#include "Context.h"
#include "CryptoOperations.h"
#include "PinOperations.h"

// 4.4	Card capabilities

/** This function queries the card and card-specific minidriver combination 
for the functionality that is provided at this level, such as certificate or
file compression.*/

DWORD WINAPI CardQueryCapabilities(
    __in PCARD_DATA  pCardData,
    __inout PCARD_CAPABILITIES  pCardCapabilities
)
{
	DWORD dwReturn = 0, dwVersion;	
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pCardCapabilities == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardCapabilities == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwVersion = (pCardCapabilities->dwVersion == 0) ? 1 : pCardCapabilities->dwVersion;
		if ( dwVersion != CARD_CAPABILITIES_CURRENT_VERSION )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion %d", dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( dwReturn)
		{
			__leave;
		}
		pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
		pCardCapabilities->fKeyGen = !pContext->fIsReadOnly;
		pCardCapabilities->fCertificateCompression = TRUE;		
		dwReturn = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

// 4.5	Card and container properties

/** The CardGetContainerProperty function is modeled after the query 
functions of CAPI for keys. It takes a LPWSTR  that indicates which parameter
is being requested. Then it returns data written into the pbData parameter.*/

DWORD WINAPI CardGetContainerProperty(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in LPCWSTR  wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter bContainerIndex = %d wszProperty = %s", bContainerIndex, wszProperty);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pdwDataLen == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pdwDataLen == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( wszProperty == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (bContainerIndex >= ContainerMax)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"bContainerIndex == %d", bContainerIndex);
			dwReturn  = SCARD_E_NO_KEY_CONTAINER ;
			__leave;
		}
		if (wcscmp(wszProperty,CCP_CONTAINER_INFO) == 0)
		{
			if (cbData < sizeof(CONTAINER_INFO))
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			*pdwDataLen = cbData;
			dwReturn = CardGetContainerInfo(pCardData, bContainerIndex, dwFlags, (PCONTAINER_INFO) pbData);
		}
		else if (wcscmp(wszProperty,CCP_PIN_IDENTIFIER) == 0)
		{
			if (cbData < sizeof(PIN_ID))
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			*pdwDataLen = cbData;
			if(bContainerIndex >= ContainerMax)
			{
				dwReturn = SCARD_E_NO_KEY_CONTAINER;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", bContainerIndex);
				__leave;
			}
			(*(PDWORD)pbData) = Containers[bContainerIndex].PinId;
			dwReturn = 0;
		}
		/*else if (wcscmp(wszProperty,CCP_ASSOCIATED_ECDH_KEY) == 0)
		{
		}*/
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s", wszProperty);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** This function sets the properties on containers. Only two container
properties are supported:
•	CCP_PIN_IDENTIFIER
•	 CCP_ASSOCIATED_ECDH_KEY 
*/

DWORD WINAPI CardSetContainerProperty(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in LPCWSTR  wszProperty,
    __in_bcount(cbDataLen) PBYTE  pbData,
    __in DWORD  cbDataLen,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter bContainerIndex = %d wszProperty = %s", bContainerIndex, wszProperty);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( wszProperty == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (wcscmp(wszProperty,CCP_PIN_IDENTIFIER) == 0)
		{
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			__leave;
		}
		else if (wcscmp(wszProperty,CCP_ASSOCIATED_ECDH_KEY) == 0)
		{
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			__leave;
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s", wszProperty);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardGetProperty function is modeled after the query functions of
CAPI for keys. It takes a LPWSTR that indicates which parameter is being 
requested. The function returns data in the pbData parameter.*/

DWORD WINAPI CardGetProperty(
    __in PCARD_DATA  pCardData,
    __in LPCWSTR  wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	PBYTE pbTempData = NULL;
	DWORD dwTempSize = 0;
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter wszProperty = %s", wszProperty);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( wszProperty == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pdwDataLen == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pdwDataLen == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( dwReturn )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"GetContext dwReturn == 0x%08X", dwReturn);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
		if (wcscmp(wszProperty,CP_CARD_FREE_SPACE) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(CARD_FREE_SPACE_INFO);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			dwReturn = CardQueryFreeSpace(pCardData, dwFlags, (PCARD_FREE_SPACE_INFO) pbData);
		}
		else if (wcscmp(wszProperty,CP_CARD_CAPABILITIES) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(CARD_CAPABILITIES);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			dwReturn = CardQueryCapabilities(pCardData, (PCARD_CAPABILITIES) pbData);
		}
		else if (wcscmp(wszProperty,CP_CARD_KEYSIZES) == 0)
		{
			*pdwDataLen = sizeof(CARD_KEY_SIZES);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			dwReturn = CardQueryKeySizes(pCardData, dwFlags, 0, (PCARD_KEY_SIZES) pbData);
		}
		else if (wcscmp(wszProperty,CP_CARD_READ_ONLY) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(BOOL);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			*((PBOOL)pbData) = pContext->fIsReadOnly;
		}
		else if (wcscmp(wszProperty,CP_CARD_CACHE_MODE) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(DWORD);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			*((PDWORD)pbData) = CP_CACHE_MODE_NO_CACHE;
		}
		else if (wcscmp(wszProperty,CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(BOOL);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			*((PBOOL)pbData) = FALSE;
		}
		else if (wcscmp(wszProperty,CP_CARD_GUID) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			dwReturn = CardReadFile(pCardData, NULL, szCARD_IDENTIFIER_FILE, 0, &pbTempData, &dwTempSize);
			if (dwReturn)
			{
				__leave;
			}
			*pdwDataLen = dwTempSize;
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			memcpy(pbData, pbTempData, dwTempSize);
		}
		else if (wcscmp(wszProperty,CP_CARD_SERIAL_NO) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(OPENPGP_AID);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			memcpy(pbData, &(((POPENPGP_CONTEXT)pCardData->pvVendorSpecific)->Aid), sizeof(OPENPGP_AID));
			dwReturn = 0;
		}
		else if (wcscmp(wszProperty,CP_CARD_PIN_INFO) == 0)
		{
			PPIN_INFO pPinInfo;
			*pdwDataLen = sizeof(PIN_INFO);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			pPinInfo = (PPIN_INFO) pbData;
			dwReturn = GetPinInfo(dwFlags, pPinInfo);
		}
		else if (wcscmp(wszProperty,CP_CARD_LIST_PINS) == 0)
		{
			PPIN_SET pPinSet;
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(PIN_SET);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			pPinSet = (PPIN_SET) pbData;
			*pPinSet = CREATE_PIN_SET(ROLE_SIGNATURE);
			SET_PIN(*pPinSet, ROLE_AUTHENTICATION);
			SET_PIN(*pPinSet, ROLE_PUK);
			SET_PIN(*pPinSet, ROLE_ADMIN);
		}
		else if (wcscmp(wszProperty,CP_CARD_AUTHENTICATED_STATE) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
		}
		else if (wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_VERIFY) == 0)
		{
			PPIN_SET pPinSet;
			switch(dwFlags)
			{
			case ROLE_SIGNATURE:
			case ROLE_AUTHENTICATION:
			case ROLE_ADMIN:
			case ROLE_PUK:
				break;
			default:
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(PIN_SET);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			pPinSet = (PPIN_SET) pbData;
			*pPinSet = CARD_PIN_STRENGTH_PLAINTEXT;
		}
		else if (wcscmp(wszProperty,CP_KEY_IMPORT_SUPPORT) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			*pdwDataLen = sizeof(DWORD);
			if (cbData < *pdwDataLen)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
				dwReturn  = ERROR_INSUFFICIENT_BUFFER;
				__leave;
			}
			if (pContext->fIsReadOnly)
			{
				*((PDWORD)pbData) = 0;
			}
			else
			{
				*((PDWORD)pbData) = CARD_KEY_IMPORT_RSA_KEYEST;
			}
		}
		else if (wcscmp(wszProperty,CP_ENUM_ALGORITHMS ) == 0)
		{
			if (dwFlags == CARD_CIPHER_OPERATION)
			{
				*pdwDataLen = sizeof(OPENPGP_SUPPORTED_CYPHER_ALGORITHM);
				if (cbData < *pdwDataLen)
				{
					Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
					dwReturn  = ERROR_INSUFFICIENT_BUFFER;
					__leave;
				}
				memcpy(pbData,OPENPGP_SUPPORTED_CYPHER_ALGORITHM,*pdwDataLen);
			}
			else if (dwFlags == CARD_ASYMMETRIC_OPERATION   )
			{
				*pdwDataLen = sizeof(OPENPGP_SUPPORTED_ASYMETRIC_ALGORITHM);
				if (cbData < *pdwDataLen)
				{
					Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
					dwReturn  = ERROR_INSUFFICIENT_BUFFER;
					__leave;
				}
				memcpy(pbData,OPENPGP_SUPPORTED_ASYMETRIC_ALGORITHM,*pdwDataLen);
			}
			else
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
			}
		}
		else if (wcscmp(wszProperty,CP_PADDING_SCHEMES ) == 0)
		{
			if (dwFlags == CARD_CIPHER_OPERATION)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"CARD_CIPHER_OPERATION", wszProperty);
				dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			}
			else if (dwFlags == CARD_ASYMMETRIC_OPERATION   )
			{
				*pdwDataLen = sizeof(DWORD);
				if (cbData < *pdwDataLen)
				{
					Trace(WINEVENT_LEVEL_ERROR, L"cbData == %d", cbData);
					dwReturn  = ERROR_INSUFFICIENT_BUFFER;
					__leave;
				}
				*((PDWORD)pbData) = CARD_PADDING_PKCS1;
			}
			else
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
			}

		}
		else if (wcscmp(wszProperty,CP_CHAINING_MODES ) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s", wszProperty);
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
		}
		else if ( wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_CHANGE ) == 0
			|| wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_UNBLOCK ) == 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s SCARD_E_UNSUPPORTED_FEATURE", wszProperty);
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s SCARD_E_INVALID_PARAMETER", wszProperty);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
	}
	__finally
	{
		if (pbTempData)
		{
			pCardData->pfnCspFree(pbTempData);
		}
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** This function can be used to set properties on the card.*/

DWORD WINAPI CardSetProperty(
    __in PCARD_DATA  pCardData,
    __in LPCWSTR  wszProperty,
    __in_bcount(cbDataLen) PBYTE  pbData,
    __in DWORD  cbDataLen,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter wszProperty = %s", wszProperty);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( wszProperty == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn)
		{
			__leave;
		}
		pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
		if (wcscmp(wszProperty,CP_CARD_FREE_SPACE) == 0
			|| wcscmp(wszProperty,CP_CARD_CAPABILITIES) == 0
			|| wcscmp(wszProperty,CP_CARD_KEYSIZES) == 0
			|| wcscmp(wszProperty,CP_CARD_LIST_PINS) == 0
			|| wcscmp(wszProperty,CP_CARD_AUTHENTICATED_STATE) == 0
			|| wcscmp(wszProperty,CP_KEY_IMPORT_SUPPORT) == 0
			|| wcscmp(wszProperty,CP_ENUM_ALGORITHMS) == 0
			|| wcscmp(wszProperty,CP_PADDING_SCHEMES) == 0
			|| wcscmp(wszProperty,CP_CHAINING_MODES) == 0
			|| wcscmp(wszProperty,CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0
			|| wcscmp(wszProperty,CP_CARD_CACHE_MODE) == 0
			|| wcscmp(wszProperty,CP_CARD_SERIAL_NO) == 0
			|| wcscmp(wszProperty,CP_CARD_GUID) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			if ( pbData == NULL )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s SCARD_E_UNSUPPORTED_FEATURE", wszProperty);
			dwReturn  = SCARD_E_UNSUPPORTED_FEATURE ;
			__leave;
		}
		else if (wcscmp(wszProperty,CP_CARD_PIN_INFO) == 0
			|| wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_VERIFY) == 0)
		{
			if (dwFlags > ContainerMax)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			if ( pbData == NULL )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s SCARD_E_UNSUPPORTED_FEATURE", wszProperty);
			dwReturn  = SCARD_E_UNSUPPORTED_FEATURE ;
			__leave;
		}
		else if (wcscmp(wszProperty,CP_CARD_READ_ONLY) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			if ( pbData == NULL )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			if ( cbDataLen != sizeof(BOOL) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbDataLen == %d", cbDataLen);
				dwReturn  = SCARD_E_INVALID_PARAMETER ;
				__leave;
			}
			if (pContext->fDoesTheAdminHasBeenAuthenticatedAtLeastOnce)
			{
				pContext->fIsReadOnly = *((PBOOL) pbData);
				dwReturn = 0;
			}
			else
			{
				dwReturn  = SCARD_W_SECURITY_VIOLATION;
			}
		}
		else  if (wcscmp(wszProperty,CP_PARENT_WINDOW) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			if ( pbData == NULL )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			if ( cbDataLen != sizeof(HWND) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"cbDataLen == %d", cbDataLen);
				dwReturn  = SCARD_E_INVALID_PARAMETER ;
				__leave;
			}
			if ( *((HWND*)pbData) != 0)
			{
				if (IsWindow( *((HWND*)pbData)) == 0)
				{
					Trace(WINEVENT_LEVEL_ERROR, L"*pbData == %d GetLastError == %d", *((HWND*)pbData), GetLastError());
					dwReturn  = SCARD_E_INVALID_PARAMETER ;
					__leave;
				}
			}
			Trace(WINEVENT_LEVEL_VERBOSE, L"CP_PARENT_WINDOW = %d", *((HWND*)pbData));
			dwReturn  = 0;
		}
		else  if (wcscmp(wszProperty,CP_PIN_CONTEXT_STRING) == 0)
		{
			if (dwFlags)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			dwReturn  = 0;
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wszProperty == %s Unknown", wszProperty);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

