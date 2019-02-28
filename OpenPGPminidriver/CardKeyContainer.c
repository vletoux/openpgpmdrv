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

// 4.6 Key Container

/** The CardCreateContainer function creates a new key container that is 
identified by the container index that the bContainerIndex argument specifies.
For applications in which the card does not support on-card key generation or
if it is desired to archive the keys, the key material can be supplied with
the call by specifying in flags that the card is to import the supplied key material.*/

DWORD WINAPI CardCreateContainer(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in DWORD  dwFlags,
    __in DWORD  dwKeySpec,
    __in DWORD  dwKeySize,
    __in PBYTE  pbKeyData
)
{
	DWORD dwReturn = 0;	
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter bContainerIndex=%d",bContainerIndex);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (bContainerIndex >= ContainerMax)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"bContainerIndex == %d",bContainerIndex);
			dwReturn  = SCARD_E_NO_KEY_CONTAINER;
			__leave; 
		}
		// controls are done in CardCreateContainerEx
		dwReturn = CardCreateContainerEx(pCardData, 
								bContainerIndex,
								dwFlags,
								dwKeySpec,
								dwKeySize,
								pbKeyData,
								Containers[bContainerIndex].PinId);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardCreateContainerEx function creates a new key container that the 
container index identifies and the bContainerIndex parameter specifies. The function 
associates the key container with the PIN that the PinId parameter specified.
This function is useful if the card-edge does not allow for changing the key attributes
after the key container is created. This function replaces the need to call 
CardSetContainerProperty to set the CCP_PIN_IDENTIFIER property CardCreateContainer
is called.
The caller of this function can provide the key material that the card imports.
This is useful in those situations in which the card either does not support internal
key generation or the caller requests that the key be archived in the card.*/

DWORD WINAPI CardCreateContainerEx(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in DWORD  dwFlags,
    __in DWORD  dwKeySpec,
    __in DWORD  dwKeySize,
    __in PBYTE  pbKeyData,
    __in PIN_ID  PinId
)
{
	DWORD dwReturn = 0;	
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter bContainerIndex=%d",bContainerIndex);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (bContainerIndex >= ContainerMax)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"bContainerIndex == %d",bContainerIndex);
			dwReturn  = SCARD_E_NO_KEY_CONTAINER;
			__leave; 
		}
		if (Containers[bContainerIndex].dwKeySpec != dwKeySpec)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwKeySpec == %d",dwKeySpec);
			dwReturn  = SCARD_E_UNSUPPORTED_FEATURE;
			__leave; 
		}
		if (Containers[bContainerIndex].PinId != PinId)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"PinId == %d",PinId);
			dwReturn  = SCARD_E_UNSUPPORTED_FEATURE;
			__leave; 
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn)
		{
			__leave;
		}
		pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
		if (pContext->fIsReadOnly)
		{
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			Trace(WINEVENT_LEVEL_ERROR, L"Readonly card");
			__leave;
		}
		if (dwFlags == CARD_CREATE_CONTAINER_KEY_GEN)
		{
			dwReturn = OCardCreateKey(pCardData, bContainerIndex, dwKeySize);
		}
		else if (dwFlags == CARD_CREATE_CONTAINER_KEY_IMPORT)
		{
			if (pbKeyData == NULL)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pbKeyData == NULL");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			dwReturn = OCardImportKey(pCardData, bContainerIndex, pbKeyData, dwKeySize);
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d",dwFlags);
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

/** The CardDeleteContainer function deletes the key container specified by its index value.
This is done by deleting all key material (public and private) that is associated with 
that index value.*/

DWORD WINAPI CardDeleteContainer(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in DWORD  dwReserved
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardGetContainerInfo function queries the specified key container for more
information about which keys are present, such as its key specification (such as AT_ECDSA_P384).*/

DWORD WINAPI CardGetContainerInfo(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in DWORD  dwFlags,
    __inout PCONTAINER_INFO  pContainerInfo
)
{
	DWORD dwReturn = 0, dwVersion;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter bContainerIndex=%d",bContainerIndex);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pContainerInfo == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pContainerInfo == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwVersion = (pContainerInfo->dwVersion == 0) ? 1 : pContainerInfo->dwVersion;
		if ( dwVersion != CONTAINER_INFO_CURRENT_VERSION )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion == %d", pContainerInfo->dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		if ( dwFlags )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (bContainerIndex >= ContainerMax)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"bContainerIndex == %d",bContainerIndex);
			dwReturn  = SCARD_E_NO_KEY_CONTAINER;
			__leave; 
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn)
		{
			__leave;
		}
		pContainerInfo->pbSigPublicKey = NULL;
		pContainerInfo->pbKeyExPublicKey = NULL;
		pContainerInfo->cbSigPublicKey = 0;
		pContainerInfo->cbKeyExPublicKey = 0;
		switch(bContainerIndex)
		{
			case ContainerSignature:
			case ContainerAuthentication:
				dwReturn = OCardReadPublicKey(pCardData, bContainerIndex, 
					&(pContainerInfo->pbSigPublicKey),&(pContainerInfo->cbSigPublicKey));
				break;
			case ContainerConfidentiality:
				dwReturn = OCardReadPublicKey(pCardData, bContainerIndex, 
					&(pContainerInfo->pbKeyExPublicKey),&(pContainerInfo->cbKeyExPublicKey));
				break;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}
