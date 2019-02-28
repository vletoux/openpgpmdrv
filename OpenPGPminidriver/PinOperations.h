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


#define ROLE_SIGNATURE ROLE_USER
#define ROLE_AUTHENTICATION 3
#define ROLE_PUK 4

DWORD CheckPinLength(__in PCARD_DATA  pCardData, __in PIN_ID  PinId, __in DWORD  cbPin);
DWORD GetRemainingPin(__in PCARD_DATA  pCardData, __in PIN_ID  PinId, __out PDWORD pdwCounter);
DWORD VerifyPIN(__in PCARD_DATA  pCardData,__in PIN_ID  PinId, 
				__in_bcount(cbPin) PBYTE  pbPin, __in DWORD  cbPin)
;
DWORD ChangePIN(__in PCARD_DATA  pCardData, __in PIN_ID  PinId,
				__in_bcount(cbPin) PBYTE  pbOldPin, __in DWORD  cbOldPin,
				__in_bcount(cbPin) PBYTE  pbNewPin, __in DWORD  cbNewPin
				);
DWORD ResetUserPIN(__in PCARD_DATA  pCardData,  __in PIN_ID  PinId,
				__in_bcount(cbPin) PBYTE  pbAuthenticator, __in DWORD  cbAuthenticator,
				__in_bcount(cbPin) PBYTE  pbNewPin, __in DWORD  cbNewPin
				);
DWORD SetPUK(__in PCARD_DATA  pCardData, 
				__in_bcount(cbPin) PBYTE  pbAdminPin, __in DWORD  cbAdminPin,
				__in_bcount(cbPin) PBYTE  pbPuk, __in DWORD  cbPuk
				);
DWORD Deauthenticate(__in PCARD_DATA  pCardData);
DWORD GetPinInfo(DWORD __in bContainerIndex, __inout PPIN_INFO pPinInfo);
