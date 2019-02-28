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
#include "Smartcard.h"
#include "PublicDataOperations.h"
#include "CryptoOperations.h"

SCARD_ATRMASK SupportedATR [] =
{
	{ // v3
		21,
		//3b da 18 ff 81 b1 fe 75 1f 03 00 31 f5 73 c0 01 60 00 90 00 1c
		{0x3b,0xda,0x18,0xff,0x81,0xb1,0xfe,0x75,0x1f,0x03,
			0x00,0x31,0xf5,0x73,0xc0,0x01,0x60,0x00,0x90,0x00,0x1c},
		{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
	},
	{ // v2 
		21, 
		//3B DA 18 FF 81 B1 FE 75 1F 03 00 31 C5 73 C0 01 40 00 90 00 0C
		{0x3B,0xDA,0x18,0xFF,0x81,0xB1,0xFE,0x75,0x1F,0x03,
			0x00,0x31,0xC5,0x73,0xC0,0x01,0x40,0x00,0x90,0x00,0x0C},
		{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
	},
	{ // v1
		20, 
		//3B FA 13 00 FF 81 31 80 45 00 31 C1 73 C0 01 00 00 90 00 B1
		{0x3B,0xFA,0x13,0x00,0xFF,0x81,0x31,0x80,0x45,0x00,
			0x31,0xC1,0x73,0xC0,0x01,0x00,0x00,0x90,0x00,0xB1},
		{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
	}
};
DWORD dwSupportedATRCount = ARRAYSIZE(SupportedATR);

BOOL find_compacttlv(__in PBYTE pbData, __in DWORD dwTotalSize, __in BYTE bCode, __out PBYTE *pbDataOut, __out_opt PDWORD pdwSize)
{
	DWORD dwOffset = 0;
	DWORD dwSize;
	while (dwOffset < dwTotalSize)
	{
		if (bCode * 0x10 == (pbData[dwOffset] & 0xF0) )
		{
			dwSize = (pbData[dwOffset] & 0x0F);
			if (pdwSize)
			{
				*pdwSize = dwSize;
			}
			dwOffset++;
			// size sequence
			
			*pbDataOut = pbData + dwOffset;
			return TRUE;
		}
		else
		{
			
			dwSize = (pbData[dwOffset] & 0x0F);
			dwOffset += dwSize + 1;
		}
	}
	return FALSE;
}



DWORD CheckContextEx(__in PCARD_DATA pCardData, __in BOOL fOpenPGPContextShouldBeNotNull)
{
	DWORD dwReturn;
	DWORD dwI, dwJ;
	BOOL fFound = FALSE;
	BOOL fRightATRLenFound = FALSE;
	DWORD dwMinSupportedVersion;
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pCardData->pbAtr == NULL)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData->pbAtr == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (fRunOnVistaAndLater)
		{
			dwMinSupportedVersion = CARD_DATA_VERSION_SIX;
		}
		else
		{
			// only a subset of functions is supported
			// so the project don't pass the ms test
			// we do this so the driver can operate under XP
			dwMinSupportedVersion = CARD_DATA_VERSION_FIVE;
		}
		if (pCardData->dwVersion < dwMinSupportedVersion)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData->dwVersion(%d) < dwMinSupportedVersion(%d)", pCardData->dwVersion, dwMinSupportedVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		pCardData->dwVersion = min(pCardData->dwVersion, CARD_DATA_VERSION_SEVEN);
		for (dwI = 0; dwI < dwSupportedATRCount; dwI++)
		{
			if (SupportedATR[dwI].cbAtr == pCardData->cbAtr)
			{
				BYTE pbAtr[36];
				fRightATRLenFound = TRUE;
				memcpy(pbAtr, pCardData->pbAtr, SupportedATR[dwI].cbAtr);
				for( dwJ = 0; dwJ < SupportedATR[dwI].cbAtr; dwJ++)
				{
					pbAtr[dwJ] &= SupportedATR[dwI].rgbMask[dwJ];
				}
				if (memcmp(pbAtr, SupportedATR[dwI].rgbAtr, SupportedATR[dwI].cbAtr) == 0)
				{
					fFound = TRUE;
					//Trace(WINEVENT_LEVEL_VERBOSE, L"card match ATR %d", dwI);
					break;
				}

			}
		}
		if (!fRightATRLenFound)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"card doesn't match ATR len %d",pCardData->cbAtr);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (!fFound)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"card doesn't match ATR");
			dwReturn  = SCARD_E_UNKNOWN_CARD;
			__leave;
		}

		if ( pCardData->pwszCardName == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData->pwszCardName");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		/* Memory management functions */
		if ( ( pCardData->pfnCspAlloc   == NULL ) ||
			( pCardData->pfnCspReAlloc == NULL ) ||
			( pCardData->pfnCspFree    == NULL ) )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Memory functions null");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (fOpenPGPContextShouldBeNotNull)
		{
			if (!pCardData->pvVendorSpecific)
			{
				// not found =>
				Trace(WINEVENT_LEVEL_ERROR, L"pCardData->pvVendorSpecific == NULL");
				dwReturn = SCARD_E_UNEXPECTED;
				__leave;
			}
		}
		else
		{
			pCardData->pvVendorSpecific = NULL;
		}
		dwReturn = 0;
	}
	__finally
	{
	}
	return dwReturn;
}

DWORD CheckContext(__in PCARD_DATA pCardData)
{
	return CheckContextEx(pCardData, TRUE);
}

DWORD CleanContext(__in PCARD_DATA pCardData)
{
	DWORD dwReturn = 0, dwI;
	__try
	{
		if (pCardData)
		{
			if ( pCardData->pvVendorSpecific)
			{
				POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
				for(dwI = 0; dwI < KeyMax; dwI++)
				{
					if (pContext->pbModulusInLittleEndian[dwI] != NULL)
					{
						pCardData->pfnCspFree(pContext->pbModulusInLittleEndian[dwI]);
						pContext->pbModulusInLittleEndian[dwI] = NULL;
					}
				}
				pCardData->pfnCspFree( pCardData->pvVendorSpecific);
				pCardData->pvVendorSpecific = NULL;
			}
			else
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pCardData->pvVendorSpecific == NULL");
			}
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
	}
	__finally
	{
	}
	return dwReturn;
}


DWORD CreateContext(__in PCARD_DATA pCardData, __in DWORD dwFlags)
{
	DWORD dwReturn;
	PBYTE					pbCapabilities = NULL, pbCardCapabilities;
	PBYTE					pbExtendedCapabilities = NULL;
	PBYTE					pbApplicationIdentifier = NULL;
	PBYTE					pbFingerPrint = NULL;
	DWORD					dwCapabilitiesSize, 
							dwCardCapabilitiesSize,
							dwApplicationIdentifierSize,
							dwExtendedCapabilitiesSize,
							dwFingerPrintSize;
	DWORD dwI, dwJ;
	BYTE bCategoryIndicator, bStatusIndicator;
	POPENPGP_CONTEXT pContext;
	__try
	{
		dwReturn = CheckContextEx(pCardData, FALSE);
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"CheckContext");
			__leave;
		}
		if (!(dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE))
		{
			if (pCardData->hSCardCtx == 0)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pCardData->hSCardCtx == NULL");
				dwReturn  = SCARD_E_INVALID_HANDLE;
				__leave;
			}
			if (pCardData->hScard == 0)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"pCardData->hScard == NULL");
				dwReturn  = SCARD_E_INVALID_HANDLE;
				__leave;
			}
		}
		
		// not found => initialize context
		pContext = pCardData->pfnCspAlloc(sizeof(OPENPGP_CONTEXT));
		if (!pContext)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			dwReturn = SCARD_E_NO_MEMORY;
			__leave;
		}
		memset(pContext, 0, sizeof(OPENPGP_CONTEXT));
		pCardData->pvVendorSpecific = pContext;

		dwReturn = SelectOpenPGPApplication(pCardData);
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"No SelectOpenPGPApplication");
			__leave;
		}
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szOpenPGPApplicationIdentifier, &pbApplicationIdentifier, &dwApplicationIdentifierSize);
		if (dwReturn)
		{
			__leave;
		}
		if (dwApplicationIdentifierSize != sizeof(OPENPGP_AID))
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwApplicationIdentifierSize = %02X", dwApplicationIdentifierSize);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		memcpy(&(pContext->Aid),pbApplicationIdentifier,sizeof(OPENPGP_AID));
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szOpenPGPHistoricalBytes, &pbCapabilities, &dwCapabilitiesSize);
		if (dwReturn)
		{
			__leave;
		}
		bCategoryIndicator = pbCapabilities[0];
		if (bCategoryIndicator != 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"bCategoryIndicator = %02X", bCategoryIndicator);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		bStatusIndicator = pbCapabilities[dwCapabilitiesSize -3];
		if (bStatusIndicator != 0 && bStatusIndicator != 03 && bStatusIndicator != 05)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"bStatusIndicator = %02X", bStatusIndicator);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		if (!find_compacttlv(pbCapabilities + 1, dwCapabilitiesSize - 1, 7, &pbCardCapabilities, &dwCardCapabilitiesSize))
		{
			Trace(WINEVENT_LEVEL_ERROR, L"tlv not found");
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		if (dwCardCapabilitiesSize != 3)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwCardCapabilitiesSize = %02X", dwCardCapabilitiesSize);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szOpenPGPExtendedCap, &pbExtendedCapabilities, &dwExtendedCapabilitiesSize);
		if (dwReturn)
		{
			__leave;
		}
		pContext->fExtentedLeLcFields = ((pbCardCapabilities[2] & 0x40)?TRUE:FALSE);
		pContext->fSupportCommandChaining = ((pbCardCapabilities[2] & 0x80)?TRUE:FALSE);
		if (pbExtendedCapabilities[0] & 0x80)
		{
			switch(pbExtendedCapabilities[1])
			{
			case 0:
				pContext->aiSecureMessagingAlg = CALG_3DES;
				break;
			case 1:
				pContext->aiSecureMessagingAlg = CALG_AES_128;
				break;
			}
			Trace(WINEVENT_LEVEL_VERBOSE, L"secure messaging supported with aiAlg = %d", pContext->aiSecureMessagingAlg);
		}
		pContext->dwMaxChallengeLength = pbExtendedCapabilities[2] * 0x100 + pbExtendedCapabilities[3];
		pContext->dwMaxCertificateLength = pbExtendedCapabilities[4] * 0x100 + pbExtendedCapabilities[5];
		pContext->dwMaxCommandDataLength = pbExtendedCapabilities[6] * 0x100 + pbExtendedCapabilities[7];
		pContext->dwMaxResponseLength = pbExtendedCapabilities[8] * 0x100 + pbExtendedCapabilities[9];
		pContext->fIsReadOnly = TRUE;
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szOpenPGPFingerprint, &pbFingerPrint, &dwFingerPrintSize);
		if (dwReturn)
		{
			__leave;
		}
		if (dwFingerPrintSize != 60)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFingerPrintSize = %02X", dwFingerPrintSize);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		memcpy(pContext->bFingerPrint, pbFingerPrint, 60);
		for(dwJ = 0; dwJ < KeyMax; dwJ++)
		{
			pContext->fHasKey[dwJ] = FALSE;
			for( dwI = dwJ * 20; dwI < dwJ * 20 + 20; dwI++)
			{
				if (pbFingerPrint[dwI] != 0)
				{
					pContext->fHasKey[dwJ] = TRUE;
					break;
				}
			}
		}
		/*dwReturn = CCIDgetFeatures(pCardData);
		if (dwReturn)
		{
			__leave;
		}*/
		dwReturn = 0;
	}
	__finally
	{
		if (pbFingerPrint)
			pCardData->pfnCspFree(pbFingerPrint);
		if (pbApplicationIdentifier)
			pCardData->pfnCspFree(pbApplicationIdentifier);
		if (pbCapabilities)
			pCardData->pfnCspFree(pbCapabilities);
		if (pbExtendedCapabilities)
			pCardData->pfnCspFree(pbExtendedCapabilities);
	}
	return dwReturn;
}
