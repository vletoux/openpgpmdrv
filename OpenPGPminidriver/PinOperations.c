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
#include "PublicDataOperations.h"
#include "PinOperations.h"


DWORD CheckPinLength(__in PCARD_DATA  pCardData, __in PIN_ID  PinId, __in DWORD  cbPin)
{
	DWORD dwReturn;
	PBYTE pbResponse = NULL;
	DWORD dwMinPinSize = 0, dwMaxPinSize, dwSize;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter PinId=%d",PinId);
		// check min Pin length
		// (hard coded in specication)
		switch(PinId)
		{
		case ROLE_SIGNATURE:
		case ROLE_AUTHENTICATION:
			dwMinPinSize = 6;
			break;
		case ROLE_PUK:
			// undocumented
			dwMinPinSize = 8;
			break;
		case ROLE_ADMIN:
			dwMinPinSize = 8;
			break;
		default:
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_INVALID_PARAMETER PinId = %d",PinId);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (cbPin < dwMinPinSize)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_WRONG_CHV ROLE = %d cbPin = %d minPinSize = %d",PinId, cbPin, dwMinPinSize);
			dwReturn = SCARD_W_WRONG_CHV;
			__leave;
		}
		// check in status DO
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szOpenPGPStatus, &pbResponse, &dwSize);
		if (dwReturn)
		{
			__leave;
		}
		switch(PinId)
		{
		case ROLE_SIGNATURE:
		case ROLE_AUTHENTICATION:
			dwMaxPinSize = pbResponse[1];
			break;
		case ROLE_PUK:
			dwMaxPinSize = pbResponse[2];
			break;
		case ROLE_ADMIN:
			dwMaxPinSize = pbResponse[3];
			break;
		default:
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (cbPin > dwMaxPinSize)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_WRONG_CHV ROLE = %d cbPin = %d dwMaxPinSize = %d", PinId, cbPin, dwMaxPinSize);
			dwReturn = SCARD_W_WRONG_CHV;
			__leave;
		}
		dwReturn = 0;
	}
	__finally
	{
		if (pbResponse)
			pCardData->pfnCspFree(pbResponse);
	}
	return dwReturn;
}

DWORD GetRemainingPin(__in PCARD_DATA  pCardData, __in PIN_ID  PinId, __out PDWORD pdwCounter)
{
	DWORD dwReturn, dwSize;
	PBYTE pbResponse = NULL;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter PinId=%d",PinId);
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szOpenPGPStatus, &pbResponse, &dwSize);
		switch(PinId)
		{
		case ROLE_SIGNATURE:
		case ROLE_AUTHENTICATION:
			*pdwCounter = pbResponse[4];
			break;
		case ROLE_PUK:
			*pdwCounter = pbResponse[5];
			break;
		case ROLE_ADMIN:
			*pdwCounter = pbResponse[6];
			break;
		default:
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
	}
	__finally
	{
		if (pbResponse)
			pCardData->pfnCspFree(pbResponse);
	}
	return dwReturn;
}

DWORD VerifyPIN(__in PCARD_DATA  pCardData,__in PIN_ID  PinId, 
				__in_bcount(cbPin) PBYTE  pbPin, __in DWORD  cbPin)
{
	DWORD dwReturn;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	// 256 because the size of the PIN must fit in a Byte
	BYTE pbCmd[256 + 5] = {0x00, 
				    0x20,
					0x00,
					0x82,
					0x00 
					};
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter PinId=%d",PinId);
		switch(PinId)
		{
		case ROLE_SIGNATURE:
			pbCmd[3] = 0x81;
			break;
		case ROLE_AUTHENTICATION:
			pbCmd[3] = 0x82;
			break;
		case ROLE_ADMIN:
			pbCmd[3] = 0x83;
			break;
		case ROLE_PUK:
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			__leave;
		default:
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (cbPin > 256)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Error failure PinId=%d cbPin = %d",PinId, cbPin);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		pbCmd[4] = (BYTE) cbPin;
		memcpy(pbCmd + 5, pbPin, cbPin);
		dwReturn = OCardSendCommand(pCardData, pbCmd, 5 + cbPin);
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_VERBOSE, L"Authentication failed");
			__leave;
		}
		Trace(WINEVENT_LEVEL_VERBOSE, L"Authentication successfull");
		if (PinId == ROLE_ADMIN)
		{
			pContext->fDoesTheAdminHasBeenAuthenticatedAtLeastOnce = TRUE;
		}
	}
	__finally
	{
		SecureZeroMemory(pbCmd, ARRAYSIZE(pbCmd));
	}
	
	return dwReturn;
}

DWORD ChangePIN(__in PCARD_DATA  pCardData, __in PIN_ID  PinId,
				__in_bcount(cbPin) PBYTE  pbOldPin, __in DWORD  cbOldPin,
				__in_bcount(cbPin) PBYTE  pbNewPin, __in DWORD  cbNewPin
				)
{
	DWORD dwReturn;
	// 256 because the size of the PIN must fit in a Byte
	BYTE pbCmd[256 + 256 + 6] = {0x00, 
				    0x24,
					0x00,
					0x81,
					0x00 
					};
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter PinId=%d",PinId);
		dwReturn = CheckPinLength(pCardData, PinId, cbNewPin);
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Invalid len %d",cbNewPin);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = CheckPinLength(pCardData, PinId, cbOldPin);
		if (dwReturn)
		{
			__leave;
		}
		switch(PinId)
		{
		case ROLE_SIGNATURE:
		case ROLE_AUTHENTICATION:
			pbCmd[3] = 0x81;
			break;
		case ROLE_ADMIN:
			pbCmd[3] = 0x83;
			break;
		case ROLE_PUK:
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			__leave;
		default:
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (cbOldPin + cbNewPin > 256)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Error failure PinId=%d cbOldPin = %d cbNewPin = %d",PinId, cbOldPin, cbNewPin);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		pbCmd[4] = (BYTE) (cbOldPin + cbNewPin);
		memcpy(pbCmd + 5, pbOldPin, cbOldPin);
		memcpy(pbCmd + 5 + cbOldPin, pbNewPin, cbNewPin);
		dwReturn = OCardSendCommand(pCardData, pbCmd, 5 + cbOldPin + cbNewPin);
	}
	__finally
	{
		SecureZeroMemory(pbCmd, ARRAYSIZE(pbCmd));
	}
	return dwReturn;
}

/** only the user PIN can be reseted => target is implicit*/
DWORD ResetUserPIN(__in PCARD_DATA  pCardData,  __in PIN_ID  PinId,
				__in_bcount(cbPin) PBYTE  pbAuthenticator, __in DWORD  cbAuthenticator,
				__in_bcount(cbPin) PBYTE  pbNewPin, __in DWORD  cbNewPin
				)
{
	DWORD dwReturn;
	BYTE pbCmd[256 + 5] = {0x00, 
				    0x2C,
					0x02,
					0x81,
					0x00 
					};
	DWORD dwCmdSize;
	
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter PinId=%d",PinId);
		dwReturn = CheckPinLength(pCardData, ROLE_USER, cbNewPin);
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Invalid len %d",cbNewPin);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (cbNewPin + cbAuthenticator> 256)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Error failure PinId=%d cbNewPin = %d cbAuthenticator = %d",PinId, cbNewPin, cbAuthenticator);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		switch(PinId)
		{
		case ROLE_ADMIN:
			// authenticate the admin
			dwReturn = VerifyPIN(pCardData, PinId, pbAuthenticator, cbAuthenticator);
			if (dwReturn)
			{
				__leave;
			}
			pbCmd[4] = (BYTE) cbNewPin;
			memcpy(pbCmd + 5, pbNewPin, cbNewPin);
			dwCmdSize = 5 + cbNewPin;
			break;
		case ROLE_PUK:
			dwReturn = CheckPinLength(pCardData, PinId, cbAuthenticator);
			if (dwReturn)
			{
				__leave;
			}	
			pbCmd[2] = 0x00;
			pbCmd[4] = (BYTE) (cbAuthenticator + cbNewPin);
			memcpy(pbCmd + 5, pbAuthenticator, cbAuthenticator);
			memcpy(pbCmd + 5 + cbAuthenticator, pbNewPin, cbNewPin);
			dwCmdSize = 5 + cbNewPin + cbAuthenticator;
			break;
		default:
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = OCardSendCommand(pCardData, pbCmd, dwCmdSize);
	}
	__finally
	{
		SecureZeroMemory(pbCmd, ARRAYSIZE(pbCmd));
	}
	return dwReturn;
}

DWORD SetPUK(__in PCARD_DATA  pCardData,
				__in_bcount(cbPin) PBYTE  pbAdminPin, __in DWORD  cbAdminPin,
				__in_bcount(cbPin) PBYTE  pbPuk, __in DWORD  cbPuk
				)
{
	DWORD dwReturn;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		dwReturn = CheckPinLength(pCardData, ROLE_PUK, cbPuk);
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Invalid len %d",cbPuk);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = VerifyPIN(pCardData, ROLE_ADMIN, pbAdminPin, cbAdminPin);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = OCardWriteFile(pCardData, szOpenPGPDir, szOpenPGPPUK, pbPuk, cbPuk);
	}
	__finally
	{
	}
	return dwReturn;
}

DWORD Deauthenticate(__in PCARD_DATA  pCardData)
{
	/*DWORD     dwCode, dwSize;
	DWORD dwReturn;
	__try
	{
		// reset the card
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
		dwCode = SCARD_COLD_RESET; 
		dwReturn = SCardControl(pCardData->hScard, IOCTL_SMARTCARD_POWER,&dwCode,4,NULL,0,&dwSize);  
		if (dwReturn && dwReturn != SCARD_W_RESET_CARD)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCardControl 0x%08X", dwReturn);
			__leave;
		}
		Sleep(200);
		dwReturn = SelectOpenPGPApplication(pCardData);
	}
	__finally
	{
	}
	return dwReturn;*/
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD GetPinInfo(DWORD __in dwPinIndex, __inout PPIN_INFO pPinInfo)
{
	DWORD dwReturn=0, dwVersion;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwPinIndex=%d",dwPinIndex);
		dwVersion = (pPinInfo->dwVersion == 0) ? PIN_INFO_CURRENT_VERSION : pPinInfo->dwVersion;
		if ( dwVersion != PIN_INFO_CURRENT_VERSION )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion %d", dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		pPinInfo->dwVersion = dwVersion;
		switch(dwPinIndex)
		{
		case ROLE_SIGNATURE:
			pPinInfo->PinType = AlphaNumericPinType;
			pPinInfo->PinPurpose = DigitalSignaturePin;
			pPinInfo->dwChangePermission = CREATE_PIN_SET(ROLE_SIGNATURE);
			SET_PIN(pPinInfo->dwChangePermission, ROLE_AUTHENTICATION);
			pPinInfo->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
			SET_PIN(pPinInfo->dwUnblockPermission, ROLE_PUK);
			pPinInfo->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
			pPinInfo->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
			pPinInfo->dwFlags = 0;
			break;
		case ROLE_AUTHENTICATION:
			pPinInfo->PinType = AlphaNumericPinType;
			pPinInfo->PinPurpose = AuthenticationPin;
			pPinInfo->dwChangePermission = CREATE_PIN_SET(ROLE_SIGNATURE);
			SET_PIN(pPinInfo->dwChangePermission, ROLE_AUTHENTICATION);
			pPinInfo->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
			SET_PIN(pPinInfo->dwUnblockPermission, ROLE_PUK);
			pPinInfo->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
			pPinInfo->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
			pPinInfo->dwFlags = 0;
			break;
		case ROLE_ADMIN:
			pPinInfo->PinType = AlphaNumericPinType;
			pPinInfo->PinPurpose = AdministratorPin;
			pPinInfo->dwChangePermission = CREATE_PIN_SET(ROLE_ADMIN);
			pPinInfo->dwUnblockPermission = 0;
			pPinInfo->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
			pPinInfo->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
			pPinInfo->dwFlags = 0;
			break;
		case ROLE_PUK:
			pPinInfo->PinType = AlphaNumericPinType;
			pPinInfo->PinPurpose = UnblockOnlyPin;
			pPinInfo->dwChangePermission = CREATE_PIN_SET(ROLE_ADMIN);
			pPinInfo->dwUnblockPermission = 0;
			pPinInfo->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
			pPinInfo->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
			pPinInfo->dwFlags = 0;
			break;
		default:
			Trace(WINEVENT_LEVEL_ERROR, L"dwPinIndex == %d", dwPinIndex);
			dwReturn  = SCARD_E_INVALID_PARAMETER ;
			__leave;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}