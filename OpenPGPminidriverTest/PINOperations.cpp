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
#include "global.h"

DWORD Authenticate(PSTR szPin, PWSTR wszUserId, PDWORD pcAttemptsRemaining)
{
    DWORD cbPin = (DWORD) strlen(szPin);
	DWORD dwReturn;
    __try
    {
        if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}

        dwReturn = pCardData->pfnCardAuthenticatePin(
            pCardData,
            wszUserId,
            (PBYTE) szPin,
            cbPin,
            pcAttemptsRemaining);
    }
    __finally
    {
    }

    return dwReturn;
}

DWORD ChangePin(PSTR szPin, PSTR szPin2, PWSTR wszUserId, PDWORD pcAttemptsRemaining)
{
	DWORD cbPin = (DWORD) strlen(szPin);
	DWORD cbPin2 = (DWORD) strlen(szPin2);
	DWORD dwReturn;
    __try
    {
        if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}

        dwReturn = pCardData->pfnCardChangeAuthenticator(
            pCardData,
            wszUserId,
            (PBYTE) szPin,
            cbPin,
			(PBYTE) szPin2,
            cbPin2,
			0,CARD_AUTHENTICATE_PIN_PIN,
            pcAttemptsRemaining);
    }
    __finally
    {
    }

    return dwReturn;
}

DWORD SetPuk(PSTR szPin, PSTR szPin2, PDWORD pcAttemptsRemaining)
{
	DWORD cbPin = (DWORD) strlen(szPin);
	DWORD cbPin2 = (DWORD) strlen(szPin2);
	DWORD dwReturn;
    __try
    {
        if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}

        dwReturn = pCardData->pfnCardChangeAuthenticatorEx(
            pCardData,
            PIN_CHANGE_FLAG_CHANGEPIN, ROLE_ADMIN,
            (PBYTE) szPin,
            cbPin,
			4,
			(PBYTE) szPin2,
            cbPin2,
			0,
            pcAttemptsRemaining);
    }
    __finally
    {
    }

    return dwReturn;
}

BYTE CharToByte(BYTE b)
{
	if (b >= 0x30 && b <= 0x39)
	{
		return b - 0x30;
	}
	if (b >= 0x41 && b <= 0x46)
	{
		return b - 0x37;
	}
	if (b >= 0x61 && b <= 0x66)
	{
		return b - 0x57;
	}
	return 0xFF;
}

DWORD SetSM(PSTR szPin, PSTR szPin2, PDWORD pcAttemptsRemaining)
{
	DWORD cbPin = (DWORD) strlen(szPin);
	DWORD cbPin2 = (DWORD) strlen(szPin2);
	DWORD dwReturn;
	BYTE  bBuffer[24];
	BYTE bTagBuffer[2 + 2 + 24 + 2 +24];
	DWORD dwBufferSize, dwI;
	BOOL fSet = FALSE;
    __try
    {
        if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		if (cbPin2 % 2 || cbPin2 / 2 > ARRAYSIZE(bBuffer))
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwBufferSize = cbPin2 / 2;
		if (dwBufferSize != 24 && dwBufferSize != 16)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		for(dwI = 0; dwI < cbPin2 / 2; dwI++)
		{
			BYTE b1, b2;
			b1 = szPin2[dwI * 2];
			b2 = szPin2[dwI * 2 + 1];
			b1 = CharToByte(b1);
			b2 = CharToByte(b2);
			if (b1 == 0xFF ||  b2 == 0xFF)
			{
				dwReturn = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			bBuffer[dwI] = (BYTE)(b1) * 16 + (b2);
		}
		bTagBuffer[0] = 0x4d;
		bTagBuffer[1] = (BYTE) dwBufferSize * 2 + 2 * 2;
		bTagBuffer[2] = 0xD1;
		bTagBuffer[3] = (BYTE) dwBufferSize;
		memcpy(bTagBuffer + 4, bBuffer, dwBufferSize);
		bTagBuffer[2 + 2 + dwBufferSize] = 0xD2;
		bTagBuffer[3 + 2 + dwBufferSize] = (BYTE) dwBufferSize;
		memcpy(bTagBuffer + 4 + 2 + dwBufferSize, bBuffer, dwBufferSize);
        dwReturn = pCardData->pfnCardAuthenticateEx(
            pCardData,
            ROLE_ADMIN,0,
            (PBYTE) szPin,
            cbPin, NULL,NULL,
            pcAttemptsRemaining);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = pCardData->pfnCardSetProperty(pCardData, CP_CARD_READ_ONLY, (PBYTE) &fSet, sizeof(BOOL),0);
		if (dwReturn) __leave;
		//dwReturn = pCardData->pfnCardWriteFile(pCardData, "openpgp", "smenc", 0, bBuffer, dwBufferSize);
		dwReturn = pCardData->pfnCardWriteFile(pCardData, "openpgp", "sm", 0, bTagBuffer, 6 + 2*dwBufferSize);
		if (dwReturn) __leave;
		
    }
    __finally
    {
    }

    return dwReturn;
}

DWORD ResetPin(PSTR szPin, PSTR szPin2, BOOL fIsPUK, PDWORD pcAttemptsRemaining)
{
	DWORD cbPin = (DWORD) strlen(szPin);
	DWORD cbPin2 = (DWORD) strlen(szPin2);
	DWORD dwReturn;
    __try
    {
        if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		if (fIsPUK)
		{
			dwReturn = pCardData->pfnCardChangeAuthenticatorEx(
				pCardData,
				PIN_CHANGE_FLAG_UNBLOCK, 5,
				(PBYTE) szPin,cbPin,
				ROLE_USER, (PBYTE)szPin2, cbPin2, 0,
				pcAttemptsRemaining);
		}
		else
		{
			dwReturn = pCardData->pfnCardChangeAuthenticatorEx(
				pCardData,
				PIN_CHANGE_FLAG_UNBLOCK, ROLE_ADMIN,
				(PBYTE) szPin,cbPin,
				ROLE_USER, (PBYTE)szPin2, cbPin2, 0,
				pcAttemptsRemaining);
		}
    }
    __finally
    {
    }

    return dwReturn;
}