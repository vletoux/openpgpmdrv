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
#include "SmartCard.h"

// 4.1	Initialization and Deconstruct



/** The CardAcquireContext function, defined by a smart card module, 
initializes communication between the smart card module and either the
Microsoft Base Smart Card Cryptographic Service Provider (CSP) or smart 
card key storage provider (KSP).
*/
DWORD WINAPI CardAcquireContext(
  __in  PCARD_DATA pCardData,
  __in  DWORD dwFlags
)
{
	DWORD dwReturn = 0;	
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}

		if ( dwFlags != 0 )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags != 0");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = CreateContext(pCardData, dwFlags);
		if (dwReturn)
		{
			__leave;
		}

		pCardData->pfnCardDeleteContext           = CardDeleteContext;
		pCardData->pfnCardAuthenticatePin         = CardAuthenticatePin;
		pCardData->pfnCardGetChallenge            = CardGetChallenge;
		pCardData->pfnCardAuthenticateChallenge   = CardAuthenticateChallenge;
		pCardData->pfnCardDeauthenticate          = NULL; //CardDeauthenticate;
		pCardData->pfnCardUnblockPin              = CardUnblockPin;
		pCardData->pfnCardChangeAuthenticator     = CardChangeAuthenticator;
		pCardData->pfnCardCreateDirectory         = CardCreateDirectory;
		pCardData->pfnCardDeleteDirectory         = CardDeleteDirectory;
		pCardData->pfnCardReadFile                = CardReadFile;
		pCardData->pfnCardCreateFile              = CardCreateFile;
		pCardData->pfnCardGetFileInfo             = CardGetFileInfo;
		pCardData->pfnCardWriteFile               = CardWriteFile;
		pCardData->pfnCardDeleteFile              = CardDeleteFile;
		pCardData->pfnCardEnumFiles               = CardEnumFiles;
		pCardData->pfnCardQueryFreeSpace          = CardQueryFreeSpace;
		pCardData->pfnCardQueryCapabilities       = CardQueryCapabilities;
		pCardData->pfnCardCreateContainer         = CardCreateContainer;
		pCardData->pfnCardDeleteContainer         = CardDeleteContainer;
		pCardData->pfnCardGetContainerInfo        = CardGetContainerInfo;
		pCardData->pfnCardRSADecrypt              = CardRSADecrypt;
		pCardData->pfnCardSignData                = CardSignData;
		pCardData->pfnCardSignData                = CardSignData;
		pCardData->pfnCardQueryKeySizes           = CardQueryKeySizes;

		// should be null for RSA only card
		pCardData->pfnCardConstructDHAgreement    = NULL; //CardConstructDHAgreement;
		
		if (pCardData->dwVersion >= CARD_DATA_VERSION_FIVE)
		{
			pCardData->pfnCardDeriveKey               = NULL; //CardDeriveKey;
			pCardData->pfnCardDestroyDHAgreement      = NULL; //CardDestroyDHAgreement;
		}
		if (pCardData->dwVersion >= CARD_DATA_VERSION_SIX)
		{
			pCardData->pfnCardGetChallengeEx          = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx          = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx   = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx        = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty    = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty    = CardSetContainerProperty;
			pCardData->pfnCardGetProperty             = CardGetProperty;
			pCardData->pfnCardSetProperty             = CardSetProperty;
		}
		if (pCardData->dwVersion >= CARD_DATA_VERSION_SEVEN)
		{
			pCardData->pfnMDImportSessionKey         = MDImportSessionKey;
			pCardData->pfnMDEncryptData              = MDEncryptData;
			pCardData->pfnCardImportSessionKey       = CardImportSessionKey;
			pCardData->pfnCardGetSharedKeyHandle     = CardGetSharedKeyHandle;
			pCardData->pfnCardGetAlgorithmProperty   = CardGetAlgorithmProperty;
			pCardData->pfnCardGetKeyProperty         = CardGetKeyProperty;
			pCardData->pfnCardSetKeyProperty         = CardSetKeyProperty;
			pCardData->pfnCardProcessEncryptedData   = CardProcessEncryptedData;
			pCardData->pfnCardDestroyKey             = CardDestroyKey;
			pCardData->pfnCardCreateContainerEx      = CardCreateContainerEx;
		}
	}
	__finally
	{
		if (dwReturn)
		{
			CleanContext(pCardData);
		}
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardDeleteContext function reverses the effect of CardAcquireContext
and severs the communication between the Base CSP/KSP and the card minidriver.
This function also performs any needed deallocations and cleanup. 
*/

DWORD WINAPI CardDeleteContext(
    __inout PCARD_DATA pCardData
     )
{
	DWORD dwReturn;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	dwReturn = CleanContext(pCardData);
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}