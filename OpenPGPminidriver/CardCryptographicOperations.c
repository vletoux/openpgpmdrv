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

// 4.7 Cryptographic operations

/** This function performs an RSA decryption operation on the passed buffer
by using the private key that a container index refers to. Note that for
ECC-only smart cards, this entry point is not defined and is set to NULL 
in the returned CARD_DATA structure from CardAcquireContext. This operation
is restricted to a single buffer of a size equal to the key modulus.*/

DWORD WINAPI CardRSADecrypt(
    __in PCARD_DATA  pCardData,
    __inout PCARD_RSA_DECRYPT_INFO  pInfo
)
{
	DWORD dwReturn = 0;	
	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}

		if ( pInfo == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pInfo == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pInfo->pbData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pInfo->pbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"ERROR_REVISION_MISMATCH");
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		if ( pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION 
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		{
			dwReturn = ERROR_REVISION_MISMATCH;
			Trace(WINEVENT_LEVEL_ERROR, L"ERROR_REVISION_MISMATCH %d", pInfo->dwVersion);
			__leave;
		}
		if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		{
			if (pInfo->dwPaddingType != CARD_PADDING_PKCS1)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"UNSUPPORTED PADDING %d", pInfo->dwPaddingType);
				dwReturn  = SCARD_E_UNSUPPORTED_FEATURE;
				__leave;
			}
		}
		if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"AT_KEYEXCHANGE %d", pInfo->dwKeySpec);
			dwReturn  = SCARD_E_INVALID_PARAMETER ;
			__leave;
		}
		if (pInfo->bContainerIndex != ContainerConfidentiality)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Confidentiality %d", pInfo->bContainerIndex);
			dwReturn  = SCARD_E_NO_KEY_CONTAINER ;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( dwReturn)
		{
			__leave;
		}
		dwReturn = OCardDecrypt(pCardData, pInfo);
		if (dwReturn == SCARD_W_WRONG_CHV)
		{
			dwReturn = SCARD_W_SECURITY_VIOLATION;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}


/** The CardSignData function signs a block of unpadded data. This entry either performs
padding on the card or pads the data by using the PFN_CSP_PAD_DATA callback. All card 
minidrivers must support this entry point.*/

DWORD WINAPI CardSignData(
    __in PCARD_DATA  pCardData,
    __in PCARD_SIGNING_INFO  pInfo
)
{
	DWORD dwReturn = 0;	
	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}

		if ( pInfo == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pInfo == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( ( pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION   ) &&
			( pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION ) )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion == %d", pInfo->dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		if ( pInfo->pbData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pInfo->pbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pInfo->dwKeySpec != AT_SIGNATURE && pInfo->dwKeySpec != AT_KEYEXCHANGE)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"AT_SIGNATURE %d", pInfo->dwKeySpec);
			dwReturn  = SCARD_E_INVALID_PARAMETER ;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( dwReturn)
		{
			__leave;
		}
		switch(pInfo->bContainerIndex)
		{
		case ContainerAuthentication:
		case ContainerConfidentiality:
			dwReturn = OCardAuthenticate(pCardData, pInfo);
			break;
		case ContainerSignature:
			dwReturn = OCardSign(pCardData, pInfo);
			break;
		default:
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", pInfo->bContainerIndex);
			__leave;
		}
		if (dwReturn == SCARD_W_WRONG_CHV)
		{
			dwReturn = SCARD_W_SECURITY_VIOLATION;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** This function returns the public key sizes that are supported by the card in use.*/
DWORD WINAPI CardQueryKeySizes(
    __in PCARD_DATA  pCardData,
    __in DWORD  dwKeySpec,
    __in DWORD  dwFlags,
    __inout PCARD_KEY_SIZES  pKeySizes
)
{
	DWORD dwReturn = 0, dwVersion;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}

		if ( dwFlags != 0 )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags != 0 : %d", dwFlags);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pKeySizes == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pKeySizes == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwVersion = (pKeySizes->dwVersion == 0) ? 1 : pKeySizes->dwVersion;
		if ( dwVersion != CARD_KEY_SIZES_CURRENT_VERSION )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion == %d", pKeySizes->dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( dwReturn)
		{
			__leave;
		}
		switch(dwKeySpec)
		{
			case AT_ECDHE_P256 :
			case AT_ECDHE_P384 :
			case AT_ECDHE_P521 :
			case AT_ECDSA_P256 :
			case AT_ECDSA_P384 :
			case AT_ECDSA_P521 :
				Trace(WINEVENT_LEVEL_ERROR, L"dwKeySpec == %d", dwKeySpec);
				dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
				__leave;
				break;
			case AT_KEYEXCHANGE:
			case AT_SIGNATURE  :
				break;
			default:
				Trace(WINEVENT_LEVEL_ERROR, L"dwKeySpec == %d", dwKeySpec);
				dwReturn = SCARD_E_INVALID_PARAMETER;
				__leave;
				break;
		}

	   pKeySizes->dwMinimumBitlen     = 1024;
	   pKeySizes->dwDefaultBitlen     = 2048;
	   pKeySizes->dwMaximumBitlen     = 2048;
	   pKeySizes->dwIncrementalBitlen = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}


/** The CardConstructDHAgreement function performs a secret agreement calculation 
for Diffie Hellman (DH) key exchange by using a private key that is present on the
card. For RSA-only card minidrivers, this entry point is not defined and is set to
NULL in the CARD_DATA structure that is returned from CardAcquireContext. 
The CARD_DH_AGREEMENT structure changes to allow for return of a handle to
the agreed secret. This raises a point about how to index the DH agreement 
on the card in an opaque manner. Maintaining a map file is unnecessary because
Ncrypt makes no provision for persistent DH agreements and there is no way to 
retrieve one after a provider is closed. DH agreements are addressable on card 
through an opaque BYTE that the card minidriver maintains. This BYTE should be 
associated with a handle to a card-side agreement.*/

DWORD WINAPI CardConstructDHAgreement(
    __in PCARD_DATA  pCardData,
    __inout PCARD_DH_AGREEMENT_INFO  pSecretInfo
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The key derivation structure represents the majority of the required changes
for FIPS 140-2 compliance for smart cards. It holds the requested key derivation
function (KDF) and the associated input. The KDFs are defined in the “CNG Reference” 
documentation on MSDN. For RSA-only card minidrivers, this entry point is not defined
and is set to NULL in the CARD_DATA structure that is returned from CardAcquireContext.*/

DWORD WINAPI CardDeriveKey(
    __in PCARD_DATA  pCardData,
    __inout PCARD_DERIVE_KEY  pAgreementInfo
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardDestroyDHAgreement function removes an agreed secret from the card.
For RSA-only card minidrivers, this entry point is not defined and is set to
NULL in the CARD_DATA structure that was returned from CardAcquireContext.*/

DWORD WINAPI CardDestroyDHAgreement(
    __in PCARD_DATA  pCardData,
    __in BYTE  bSecretAgreementIndex,
    __in DWORD  dwFlags
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}