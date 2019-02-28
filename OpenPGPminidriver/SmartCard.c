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
#include <stdio.h>
#include "Tracing.h"
#include "Context.h"
#include "SmartCard.h"

#pragma comment(lib,"Winscard")

DWORD SelectOpenPGPApplication(__in PCARD_DATA  pCardData);

/** called to re-select the Openpgp application when a SCARD_W_RESET occured */
DWORD OCardReconnect(__in PCARD_DATA  pCardData)
{
	DWORD     dwAP;
	DWORD dwReturn;
	__try
	{
		// reset the card
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
		dwReturn = SCardReconnect(pCardData->hScard,
                         SCARD_SHARE_SHARED,
                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                         SCARD_LEAVE_CARD,
                         &dwAP );
		if (dwReturn)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCardReconnect 0x%08X", dwReturn);
			__leave;
		}

		dwReturn = SelectOpenPGPApplication(pCardData);
	}
	__finally
	{
	}
	return dwReturn;
}

/** send a command to the smart card with no response expected */
DWORD OCardSendCommand(__in PCARD_DATA  pCardData, __in PBYTE pbCmd, __in DWORD dwCmdSize)
{
	DWORD             dwReturn = 0;

	SCARD_IO_REQUEST  ioSendPci = {1, sizeof(SCARD_IO_REQUEST)};
	SCARD_IO_REQUEST  ioRecvPci = {1, sizeof(SCARD_IO_REQUEST)};
	BYTE     recvbuf[256];
	DWORD     recvlen = sizeof(recvbuf);
	BYTE              SW1, SW2;
	__try
	{

		dwReturn = SCardTransmit(pCardData->hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
		if ( dwReturn != SCARD_S_SUCCESS )
		{
			if (dwReturn == SCARD_W_RESET_CARD)
			{
				dwReturn = OCardReconnect(pCardData);
				if (dwReturn)
				{
					__leave;
				}
				dwReturn = OCardSendCommand(pCardData,pbCmd, dwCmdSize);
				__leave;
			}
			Trace(WINEVENT_LEVEL_ERROR, L"SCardTransmit errorcode: [0x%02X]", dwReturn);
			__leave;
		}
		SW1 = recvbuf[recvlen-2];
		SW2 = recvbuf[recvlen-1];
		if ( (SW1 == 0x6A) && (SW2 == 0x88) )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"card reset");
			recvlen = sizeof(recvbuf);
			dwReturn = SelectOpenPGPApplication(pCardData);
			if (dwReturn)
			{
				__leave;
			}
			dwReturn = SCardTransmit(pCardData->hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
			SW1 = recvbuf[recvlen-2];
			SW2 = recvbuf[recvlen-1];
		}
		if ( ( SW1 == 0x90 ) && ( SW2 == 0x00 ) )
		{

		}
		else if ( (SW1 == 0x69) && (SW2 == 0x82) )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_WRONG_CHV");
			dwReturn = SCARD_W_WRONG_CHV;
			__leave;
		}
		else if ( (SW1 == 0x69) && (SW2 == 0x83) )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_CHV_BLOCKED");
			dwReturn = SCARD_W_CHV_BLOCKED;
			__leave;
		}
		else if ( (SW1 == 0x69) && (SW2 == 0x85) )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION");
			dwReturn = SCARD_W_SECURITY_VIOLATION;
			__leave;
		}
		else
		{
			TraceDump(WINEVENT_LEVEL_ERROR, pbCmd,dwCmdSize);
			Trace(WINEVENT_LEVEL_ERROR, L"SW1=0x%02X SW2=0x%02X", SW1, SW2);
			dwReturn = SCARD_F_UNKNOWN_ERROR;
			__leave;
		}
	}
	__finally
	{
	}
	return dwReturn;
}

/** send the select open pgp application apdu */
DWORD SelectOpenPGPApplication(__in PCARD_DATA  pCardData)
{
	BYTE pbCmd[] = {0x00, 
				    0xA4,
					0x04,
					0x00,
					0x06,
					0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
					0x00
					};
	
	return OCardSendCommand(pCardData, pbCmd, sizeof(pbCmd));
}

/** send a command to the smart card with response expected */
DWORD OCardGetData(__in PCARD_DATA  pCardData, 
					__in PBYTE pbCmd, __in DWORD dwCmdSize,
					__in PBYTE* pbResponse, __in_opt PDWORD pdwResponseSize)
{

	DWORD dwReturn;
	BYTE pbGetResponse[] = {0x00, 
				    0xC0,
					0x00,
					0x00,
					0x00
					};
	DWORD dwGetResponseSize = ARRAYSIZE(pbGetResponse);
	BYTE			recvbuf[0x800];
	DWORD			recvlen = sizeof(recvbuf);
	BYTE            SW1, SW2;
	DWORD			dwDataSize = 0;
	__try
	{

		*pbResponse = NULL;
		dwReturn = SCardTransmit(pCardData->hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
		
		do
		{
			if ( dwReturn != SCARD_S_SUCCESS )
			{
				if (dwReturn == SCARD_W_RESET_CARD)
				{
					dwReturn = OCardReconnect(pCardData);
					if (dwReturn)
					{
						__leave;
					}
					dwReturn = OCardGetData(pCardData,pbCmd, dwCmdSize,pbResponse, pdwResponseSize);
					__leave;
				}
				Trace(WINEVENT_LEVEL_ERROR, L"SCardTransmit errorcode: [0x%02X]", dwReturn);
				__leave;
			}
			SW1 = recvbuf[recvlen-2];
			SW2 = recvbuf[recvlen-1];
			if ( (SW1 == 0x6A) && (SW2 == 0x88) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"card reset");
				recvlen = sizeof(recvbuf);
				dwReturn = SelectOpenPGPApplication(pCardData);
				if (dwReturn)
				{
					__leave;
				}
				dwReturn = SCardTransmit(pCardData->hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
				SW1 = recvbuf[recvlen-2];
				SW2 = recvbuf[recvlen-1];
			}
			if ( ( SW1 == 0x90 ) && ( SW2 == 0x00 ) )
			{
				dwDataSize = recvlen-2;
				*pbResponse = pCardData->pfnCspAlloc(dwDataSize);
				if (! *pbResponse)
				{
					Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
					dwReturn = SCARD_E_NO_MEMORY;
					__leave;
				}
				memcpy(*pbResponse, recvbuf, dwDataSize);
			}
			else if (SW1 == 0x61)
			{
				dwDataSize += SW2;
				if (*pbResponse)
				{
					*pbResponse = pCardData->pfnCspReAlloc(*pbResponse, dwDataSize);
				}
				else
				{
					*pbResponse = pCardData->pfnCspAlloc(dwDataSize);
				}
				dwGetResponseSize = ARRAYSIZE(pbGetResponse);
				dwReturn = SCardTransmit(pCardData->hScard, 
									SCARD_PCI_T1, 
									pbGetResponse, 
									dwGetResponseSize, 
									NULL, 
									recvbuf, 
									&recvlen);
			}
			else if ( (SW1 == 0x69) && (SW2 == 0x82) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_WRONG_CHV");
				dwReturn = SCARD_W_WRONG_CHV;
				__leave;
			}
			else if ( (SW1 == 0x69) && (SW2 == 0x83) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_CHV_BLOCKED");
				dwReturn = SCARD_W_CHV_BLOCKED;
				__leave;
			}
			else if ( (SW1 == 0x69) && (SW2 == 0x85) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION");
				dwReturn = SCARD_W_SECURITY_VIOLATION;
				__leave;
			}
			else
			{
				TraceDump(WINEVENT_LEVEL_ERROR, pbCmd,dwCmdSize);
				Trace(WINEVENT_LEVEL_ERROR, L"SW1=0x%02X SW2=0x%02X", SW1, SW2);
				dwReturn = SCARD_F_UNKNOWN_ERROR;
				__leave;
			}

		} while (SW1 == 0x61);
		if (pdwResponseSize)
		{
			*pdwResponseSize = dwDataSize;
		}
	}
	__finally
	{
	}
	return dwReturn;
}

DWORD CCIDfindFeature(BYTE featureTag, BYTE* features, DWORD featuresLength) 
{
    DWORD idx = 0;
    int count;
    while (idx < featuresLength) {
        BYTE tag = features[idx];
        idx++;
        idx++;
        if (featureTag == tag) {
            DWORD feature = 0;
            for (count = 0; count < 3; count++) {
                feature |= features[idx] & 0xff;
                idx++;
                feature <<= 8;
            }
            feature |= features[idx] & 0xff;
            return feature;
        }
        idx += 4;
    }
    return 0;
}

DWORD CCIDgetFeatures(__in PCARD_DATA  pCardData) 
{
	BYTE pbRecvBuffer[200];
	DWORD dwRecvLength, dwReturn;
	__try
	{
		POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;

		pContext->SmartCardReaderFeatures.VERIFY_PIN_START = 0;
		pContext->SmartCardReaderFeatures.VERIFY_PIN_FINISH = 0;
		pContext->SmartCardReaderFeatures.VERIFY_PIN_DIRECT = 0;
		pContext->SmartCardReaderFeatures.MODIFY_PIN_START = 0;
		pContext->SmartCardReaderFeatures.MODIFY_PIN_FINISH = 0;
		pContext->SmartCardReaderFeatures.MODIFY_PIN_DIRECT = 0;
		pContext->SmartCardReaderFeatures.GET_KEY_PRESSED = 0;
		pContext->SmartCardReaderFeatures.ABORT = 0;

		dwReturn = SCardControl(pCardData->hScard, 
			SCARD_CTL_CODE(3400),
			NULL,
			0,
			pbRecvBuffer,
			sizeof(pbRecvBuffer),
			&dwRecvLength);
		if ( dwReturn ) 
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCardControl errorcode: [0x%02X]", dwReturn);
			__leave;
		}
		pContext->SmartCardReaderFeatures.VERIFY_PIN_START = CCIDfindFeature(FEATURE_VERIFY_PIN_START, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.VERIFY_PIN_FINISH = CCIDfindFeature(FEATURE_VERIFY_PIN_FINISH, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.VERIFY_PIN_DIRECT = CCIDfindFeature(FEATURE_VERIFY_PIN_DIRECT, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.MODIFY_PIN_START = CCIDfindFeature(FEATURE_MODIFY_PIN_START, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.MODIFY_PIN_FINISH = CCIDfindFeature(FEATURE_MODIFY_PIN_FINISH, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.MODIFY_PIN_DIRECT = CCIDfindFeature(FEATURE_MODIFY_PIN_DIRECT, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.GET_KEY_PRESSED = CCIDfindFeature(FEATURE_GET_KEY_PRESSED, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.ABORT = CCIDfindFeature(FEATURE_ABORT, pbRecvBuffer, dwRecvLength);
	}
	__finally
	{
	}
   return dwReturn;
}