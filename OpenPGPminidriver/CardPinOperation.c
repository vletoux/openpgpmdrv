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
#include "PinOperations.h"


// 4.2 Card PIN Operations

/** The CardAuthenticatePin function submits a PIN value as a string
to the card to establish the user’s identity and to satisfy access 
conditions for an operation to be undertaken on the user’s behalf. 
Submission of a PIN to the card may involve some processing by the card
minidriver to render the PIN information to a card-specific form. */

DWORD WINAPI CardAuthenticatePin(
    __in PCARD_DATA  pCardData,
    __in LPWSTR  pwszUserId,
    __in_bcount(cbPin) PBYTE  pbPin,
    __in DWORD  cbPin,
    __out_opt PDWORD  pcAttemptsRemaining
)
{
	DWORD dwReturn = 0;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter authenticate %s", pwszUserId);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pwszUserId == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbPin == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbPin == NULL");
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
		if ( wcscmp(pwszUserId, wszCARD_USER_USER) == 0 ) 
		{
			dwReturn = CheckPinLength(pCardData, ROLE_USER, cbPin);
			if (dwReturn)
			{
				__leave;
			}
			dwReturn = VerifyPIN(pCardData, ROLE_USER, pbPin, cbPin);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData, ROLE_USER, pcAttemptsRemaining);
			}
		}
		else if ( wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0)
		{
			dwReturn = CheckPinLength(pCardData, ROLE_ADMIN, cbPin);
			if (dwReturn)
			{
				__leave;
			}
			dwReturn = VerifyPIN(pCardData, ROLE_ADMIN, pbPin, cbPin);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData, ROLE_ADMIN, pcAttemptsRemaining);
			}
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId unknown : %s", pwszUserId);
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

/** A card principal can be authenticated by using either a PIN 
or a challenge/response protocol in which the card generates a block
of challenge data by using its administrative key. The authenticating
caller must compute the response to the challenge by using shared
knowledge of that key and submit the response back to the card. 
If the response is correct, the principal is authenticated to the card. */

DWORD WINAPI CardGetChallenge(
    __in PCARD_DATA  pCardData,
    __deref_out_bcount(*pcbChallengeData) PBYTE  *ppbChallengeData,
    __out PDWORD  pcbChallengeData
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardAuthenticateChallenge function performs authentication of
a card principal by using a challenge/response protocol. The caller of
this function must have previously called CardGetChallenge to retrieve
the challenge data from the card and computed the correct response data
to submit with this call. */

DWORD WINAPI CardAuthenticateChallenge(
    __in PCARD_DATA  pCardData,
    __in_bcount(cbResponseData) PBYTE pbResponseData,
    __in DWORD  cbResponseData,
    __out_opt PDWORD  pcAttemptsRemaining
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardDeauthenticate function is an optional export that should be
provided if it is possible within the card minidriver to efficiently reverse
the effect of authenticating a user or administrator without resetting 
the card. If this function is not implemented, the card minidriver should 
put NULL in the CARD_DATA structure pointer for this function.
The Base CSP/KSP tests this pointer for NULL value before calling it. If it
is found NULL, the Base CSP/KSP deauthenticates a user by resetting the 
card. Because a card reset is a time-consuming operation, the card minidriver
should implement this function if it can be done.
*/

DWORD WINAPI CardDeauthenticate(
    __in PCARD_DATA  pCardData,
    __in LPWSTR  pwszUserId,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter %s", pwszUserId);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pwszUserId == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( dwFlags != 0 )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags != 0 : %d", dwFlags);
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
		dwReturn = Deauthenticate(pCardData);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"%s dwReturn = 0x%08X", pwszUserId,dwReturn);
	return dwReturn;
}

/** The CardAuthenticateEx function handles PIN authentication operations to the card.
This function replaces the CardAuthenticate function of earlier versions of these 
specifications and adds support for the following PIN types:
•	External PINs, which are PINs that are accessed from a device that is connected to the computer.
•	Challenge/response PINs.
•	Secure PIN channels.
•	Session PINs.
*/
DWORD WINAPI CardAuthenticateEx(
    __in PCARD_DATA  pCardData,
    __in PIN_ID  PinId,
    __in DWORD  dwFlags,
    __in_bcount(cbPinData) PBYTE  pbPinData,
    __in  DWORD  cbPinData,
    __deref_opt_out_bcount(*pcbSessionPin) PBYTE  *ppbSessionPin,
    __out_opt PDWORD  pcbSessionPin,
    __out_opt PDWORD  pcAttemptsRemaining
)
{
	DWORD dwReturn = 0;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter authenticate %d", PinId);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ((dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN)
			|| (dwFlags & CARD_AUTHENTICATE_SESSION_PIN))
		{
			if ( ( ppbSessionPin == NULL ) ||
					( pcbSessionPin == NULL ) )
			{
				Trace(WINEVENT_LEVEL_ERROR, L"ppbSessionPin == NULL");
				dwReturn  = SCARD_E_INVALID_PARAMETER;
				__leave;
			}
			else
			{
				Trace(WINEVENT_LEVEL_ERROR, L"SESSION_PIN SCARD_E_UNSUPPORTED_FEATURE");
				dwReturn  = SCARD_E_UNSUPPORTED_FEATURE;
				__leave;
			}
		}
		if ( pbPinData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbPinData == NULL");
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
		dwReturn = CheckPinLength(pCardData, PinId, cbPinData);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = VerifyPIN(pCardData, PinId, pbPinData, cbPinData);
		if (dwReturn && pcAttemptsRemaining)
		{
			GetRemainingPin(pCardData, PinId, pcAttemptsRemaining);
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** Besides authentication by using a PIN, a card principal can be authenticated
by using a challenge/response protocol in which the card generates a block of challenge data.
The authenticating caller must compute the response to the challenge by using
shared knowledge of a key and submit the response back to the card by calling
CardGetChallengeEx. If the response is correct, the principal is authenticated to the card.
*/

DWORD WINAPI CardGetChallengeEx(
    __in PCARD_DATA  pCardData,
    __in PIN_ID  PinId,
    __deref_out_bcount(*pcbChallengeData) PBYTE  *ppbChallengeData,
    __out PDWORD  pcbChallengeData,
    __in DWORD  dwFlags
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardDeauthenticateEx function must always be provided. If it is not
possible within the card minidriver to efficiently reverse the effect of an 
authentication operation without resetting the card, the call must return 
SCARD_E_UNSUPPORTED_FEATURE. In this situation, the Base CSP/KSP performs 
deauthentication by resetting the card. Because a card reset is a time-consuming 
operation, the card minidriver must implement this function if it can be done.*/

DWORD WINAPI CardDeauthenticateEx(
    __in PCARD_DATA  pCardData,
    __in PIN_SET  PinId,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter PinId = %d", PinId);
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
		dwReturn = CheckContext(pCardData);
		if ( dwReturn )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"GetContext dwReturn == 0x%08X", dwReturn);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwReturn = Deauthenticate(pCardData);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"PinId = %d dwReturn = 0x%08X",PinId, dwReturn);
	return dwReturn;
}

/** The CardUnblockPin function is used to unblock a card that has become
blocked by too many incorrect PIN entry attempts. The unblock function is
atomic in that authentication and unblocking the card must occur as a single
operation. Therefore, authentication information and the new user PIN must
be presented when the call is made.*/

DWORD WINAPI CardUnblockPin(
    __in PCARD_DATA  pCardData,
    __in LPWSTR  pwszUserId,
    __in_bcount(cbAuthenticationData) PBYTE  pbAuthenticationData,
    __in DWORD  cbAuthenticationData,
    __in_bcount(cbNewPinData) PBYTE  pbNewPinData,
    __in DWORD  cbNewPinData,
    __in DWORD  cRetryCount,
    __in DWORD  dwFlags
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
		if ( pwszUserId == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbAuthenticationData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbAuthenticationData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbNewPinData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbNewPinData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags == CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)
		{
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			Trace(WINEVENT_LEVEL_ERROR, L"CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE SCARD_E_UNSUPPORTED_FEATURE");
			__leave;
		}
		if (dwFlags != CARD_AUTHENTICATE_PIN_PIN)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_INVALID_PARAMETER dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( !dwReturn )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"GetContext dwReturn == 0x%08X", dwReturn);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( wcscmp(pwszUserId, wszCARD_USER_USER) == 0 ) 
		{
			dwReturn = ResetUserPIN(pCardData, ROLE_PUK,
									pbAuthenticationData, cbAuthenticationData,
									pbNewPinData, cbNewPinData);
		}
		else if ( wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0)
		{
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			Trace(WINEVENT_LEVEL_ERROR, L"wszCARD_USER_ADMIN");
			__leave;
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId unknown : %s", pwszUserId);
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

/** This function changes the authenticator for the affected card principal. 
It can be used to change a user’s PIN or to change the challenge/response key.
The two usages are distinguished by use of a flag value.*/

DWORD WINAPI CardChangeAuthenticator(
    __in PCARD_DATA  pCardData,
    __in LPWSTR  pwszUserId,
    __in_bcount(cbCurrentAuthenticator) 
        PBYTE  pbCurrentAuthenticator,
    __in DWORD  cbCurrentAuthenticator,
    __in_bcount(cbNewAuthenticator) PBYTE  pbNewAuthenticator,
    __in DWORD  cbNewAuthenticator,
    __in DWORD   cRetryCount,
    __in DWORD  dwFlags,
    __out_opt PDWORD  pcAttemptsRemaining
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
		if ( pwszUserId == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbCurrentAuthenticator == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbCurrentAuthenticator == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbNewAuthenticator == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbNewAuthenticator == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags == CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)
		{
			dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		if (dwFlags != CARD_AUTHENTICATE_PIN_PIN)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		if (cRetryCount)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"cRetryCount = %d", cRetryCount);
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"GetContext dwReturn == 0x%08X", dwReturn);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( wcscmp(pwszUserId, wszCARD_USER_USER) == 0 ) 
		{
			dwReturn = ChangePIN(pCardData, ROLE_USER,
								pbCurrentAuthenticator, cbCurrentAuthenticator,
								pbNewAuthenticator, cbNewAuthenticator);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData, ROLE_USER, pcAttemptsRemaining);
			}
		}
		else if ( wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0)
		{
			dwReturn = ChangePIN(pCardData, ROLE_ADMIN,
								pbCurrentAuthenticator, cbCurrentAuthenticator,
								pbNewAuthenticator, cbNewAuthenticator);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData,ROLE_ADMIN, pcAttemptsRemaining);
			}
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pwszUserId unknown : %s", pwszUserId);
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


/** This function changes the authenticator for the affected card principal.
It can be used to change a PIN or unblock a PIN. The usages are distinguished 
by use of a flag value.*/

DWORD WINAPI CardChangeAuthenticatorEx(
    __in PCARD_DATA  pCardData,
    __in DWORD  dwFlags,
    __in PIN_ID  dwAuthenticatingPinId,
    __in_bcount(cbAuthenticatingPinData) 
          PBYTE  pbAuthenticatingPinData,
    __in DWORD  cbAuthenticatingPinData,
    __in PIN_ID  dwTargetPinId,
    __in_bcount(cbTargetData) PBYTE  pbTargetData,
    __in DWORD  cbTargetData,
    __in  DWORD  cRetryCount,
    __out_opt PDWORD  pcAttemptsRemaining
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
		if ( pbAuthenticatingPinData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbAuthenticatingPinData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbTargetData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbTargetData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags != PIN_CHANGE_FLAG_UNBLOCK && dwFlags != PIN_CHANGE_FLAG_CHANGEPIN)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		if (cRetryCount)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"cRetryCount = %d", cRetryCount);
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if ( dwReturn )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"GetContext dwReturn == 0x%08X", dwReturn);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( dwAuthenticatingPinId == dwTargetPinId && dwFlags == PIN_CHANGE_FLAG_CHANGEPIN) 
		{
			dwReturn = ChangePIN(pCardData, dwAuthenticatingPinId,
								pbAuthenticatingPinData, cbAuthenticatingPinData,
								pbTargetData, cbTargetData);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData, dwAuthenticatingPinId, pcAttemptsRemaining);
			}
		}
		else if ( (dwAuthenticatingPinId == ROLE_ADMIN || dwAuthenticatingPinId == ROLE_PUK )
					&&  (dwTargetPinId == ROLE_USER || dwTargetPinId == ROLE_AUTHENTICATION)
					&& dwFlags == PIN_CHANGE_FLAG_UNBLOCK) 
		{
			dwReturn = ResetUserPIN(pCardData, dwAuthenticatingPinId,
								pbAuthenticatingPinData, cbAuthenticatingPinData,
								pbTargetData, cbTargetData);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData,dwAuthenticatingPinId, pcAttemptsRemaining);
			}
		}
		else if ( dwAuthenticatingPinId == ROLE_ADMIN
					&&  dwTargetPinId == ROLE_PUK  && dwFlags == PIN_CHANGE_FLAG_CHANGEPIN) 
		{
			dwReturn = SetPUK(pCardData,
								pbAuthenticatingPinData, cbAuthenticatingPinData,
								pbTargetData, cbTargetData);
			if (dwReturn && pcAttemptsRemaining)
			{
				GetRemainingPin(pCardData,dwAuthenticatingPinId, pcAttemptsRemaining);
			}
		}
		else
		{
			Trace(WINEVENT_LEVEL_ERROR, L"unknown role match: %d %d", dwAuthenticatingPinId, dwTargetPinId);
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
