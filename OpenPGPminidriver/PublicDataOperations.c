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
#include <stdio.h>
#include "cardmod.h"
#include "Tracing.h"
#include "Context.h"
#include "SmartCard.h"
#include "PublicDataOperations.h"
#include "CryptoOperations.h"
#include "tlv.h"

typedef enum _OPENPGP_FILE_TYPE
{
	StoredOnSmartCard,
	Virtual,
} OPENPGP_FILE_TYPE;

#define OPENPGP_FILE_OPTIONAL 1
#define OPENPGP_FILE_WRITE_ONLY 2
#define OPENPGP_FILE_NULL_LENGHT_EQUALS_MISSING 4
#define OPENPGP_FILE_CONF_IS_AUTH 8

typedef struct _OPENPGP_FILE
{
	PCHAR szDirectory;
	PCHAR szFile;
	OPENPGP_FILE_TYPE dwFileType;
	DWORD dwTag;
	DWORD dwTlv;
	CARD_FILE_ACCESS_CONDITION dwAccess;
	DWORD dwFlag;
} OPENPGP_FILE, *POPENPGP_FILE;


#define szCARD_APPLICATION_FILE "cardapps"

OPENPGP_FILE Files[] =
{
	{szOpenPGPDir, szOpenPGPFingerprint, StoredOnSmartCard, 0x6E, 0xC5, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPStatus, StoredOnSmartCard, 0xC4, 0, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPStatusPW1, StoredOnSmartCard, 0xC4, 0, EveryoneReadAdminWriteAc, OPENPGP_FILE_WRITE_ONLY},
	{szOpenPGPDir, szOpenPGPApplicationIdentifier, StoredOnSmartCard, 0x4F, 0, UnknownAc},
	{szOpenPGPDir, szOpenPGPLogin, StoredOnSmartCard, 0x5E, 0, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPName, StoredOnSmartCard, 0x65, 0x5B, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPLanguage, StoredOnSmartCard, 0x65, 0x5F2D, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPSex, StoredOnSmartCard, 0x65, 0x5F35,EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPUrl, StoredOnSmartCard, 0x5F50, 0, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPHistoricalBytes, StoredOnSmartCard, 0x5F52, 0, UnknownAc},
	{szOpenPGPDir, szOpenPGPCertificate, StoredOnSmartCard, 0x7F21, 0, EveryoneReadAdminWriteAc},
	{szOpenPGPDir, szOpenPGPExtendedCap, StoredOnSmartCard, 0x6E, 0xC0, UnknownAc},
	{szOpenPGPDir, szOpenPGPAlgoAttributesSignature, StoredOnSmartCard, 0x6E, 0xC1, UnknownAc},
	{szOpenPGPDir, szOpenPGPAlgoAttributesDecryption, StoredOnSmartCard, 0x6E, 0xC2,UnknownAc},
	{szOpenPGPDir, szOpenPGPAlgoAttributesAuthentication, StoredOnSmartCard, 0x6E, 0xC3, UnknownAc },
	{szOpenPGPDir, szOpenPGPPUK, StoredOnSmartCard, 0xD3, 0, UnknownAc, OPENPGP_FILE_WRITE_ONLY },
	{szOpenPGPDir, szOpenPGPSecureMessaging, StoredOnSmartCard, 0xF4, 0, UnknownAc, OPENPGP_FILE_WRITE_ONLY },
	{szOpenPGPDir, szOpenPGPSecureMessagingCryptographicCheksum, StoredOnSmartCard, 0xD2, 0, UnknownAc, OPENPGP_FILE_WRITE_ONLY },
	{szOpenPGPDir, szOpenPGPSecureMessagingCryptogram, StoredOnSmartCard, 0xD1, 0, UnknownAc, OPENPGP_FILE_WRITE_ONLY },
	{NULL, szCARD_IDENTIFIER_FILE, StoredOnSmartCard, 0x4F, 0, EveryoneReadAdminWriteAc},
	{NULL, szCARD_APPLICATION_FILE, Virtual, 0, 0, EveryoneReadAdminWriteAc},
	{NULL, szCACHE_FILE, Virtual, 0, 0, EveryoneReadUserWriteAc},
	{szBASE_CSP_DIR, szCONTAINER_MAP_FILE, Virtual, 0, 0, EveryoneReadUserWriteAc},
	{szBASE_CSP_DIR, "kxc01", StoredOnSmartCard, 0x7F21, 0, EveryoneReadAdminWriteAc, OPENPGP_FILE_NULL_LENGHT_EQUALS_MISSING | OPENPGP_FILE_CONF_IS_AUTH},
	{szBASE_CSP_DIR, "ksc02", StoredOnSmartCard, 0x7F21, 0, EveryoneReadAdminWriteAc, OPENPGP_FILE_NULL_LENGHT_EQUALS_MISSING},

};

DWORD dwFileCount = ARRAYSIZE(Files);

DWORD OCardDirectoryList(__in PCARD_DATA  pCardData, 
					__in PBYTE* pbResponse, __in_opt PDWORD pdwResponseSize)
{
	// hardcoded
	*pdwResponseSize = 16;
	*pbResponse = pCardData->pfnCspAlloc(*pdwResponseSize);
	if (!*pbResponse)
	{
		return SCARD_E_NO_MEMORY;
	}
	memcpy(*pbResponse, "openpgp\0mscp\0\0\0\0", *pdwResponseSize);
	return 0;
}


// read file
DWORD OCardReadFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile,
					__in PBYTE* ppbResponse, __in PDWORD pdwResponseSize)
{
	DWORD dwI;
	DWORD dwReturn = 0;
	BOOL fDirectoryFound = FALSE;
	BOOL fFileFound = FALSE;
	BYTE pbCmd[] = {0x00, 0xCA, 0x00, 0x00, 0x00, 0x00,0x00};
	DWORD dwCmdSize = ARRAYSIZE(pbCmd);
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	PBYTE pbData = NULL;
	__try
	{
		*pdwResponseSize = 0;
		for(dwI = 0; dwI < dwFileCount; dwI++)
		{
			BOOL fMatch = FALSE;
			if (szDirectory == NULL)
			{
				if (!Files[dwI].szDirectory) fMatch = TRUE;
			}
			else
			{
				if (Files[dwI].szDirectory && _stricmp(szDirectory, Files[dwI].szDirectory) == 0) fMatch = TRUE;
			}
			if (fMatch)
			{
				fDirectoryFound = TRUE;
				if (_stricmp(szFile, Files[dwI].szFile) == 0)
				{
					fFileFound = TRUE;
					break;
				}
			}
		}
		if (!fFileFound)
		{
			if (fDirectoryFound)
			{
				dwReturn = SCARD_E_FILE_NOT_FOUND;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S",szFile);
			}
			else
			{
				dwReturn = SCARD_E_DIR_NOT_FOUND;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_DIR_NOT_FOUND %S",szDirectory);
			}	
			__leave;
		}
		if (Files[dwI].dwFileType == StoredOnSmartCard)
		{
			pbCmd[2] = (BYTE) (Files[dwI].dwTag / 0x100);
			pbCmd[3] = (BYTE) (Files[dwI].dwTag % 0x100);
			dwReturn = OCardGetData(pCardData, pbCmd, dwCmdSize, &pbData, pdwResponseSize);
			if (dwReturn)
			{
				__leave;
			}
			if (Files[dwI].dwTlv)
			{
				PBYTE pbPointer;
				//TraceDump(0,pbData,*pdwResponseSize);
				if (find_tlv(pbData, Files[dwI].dwTlv, *pdwResponseSize, &pbPointer, pdwResponseSize))
				{
					*ppbResponse = pCardData->pfnCspAlloc(*pdwResponseSize);
					if (!*ppbResponse )
					{
						Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
						dwReturn = SCARD_E_NO_MEMORY;
						__leave;
					}
					memcpy(*ppbResponse, pbPointer, *pdwResponseSize);
				}
				else
				{
					dwReturn = SCARD_E_FILE_NOT_FOUND;
					Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S",szFile);
					__leave;
				}
			}
			else
			{
				*ppbResponse = pbData;
				// do not free the data !
				pbData = NULL;
			}
			if (Files[dwI].dwFlag & OPENPGP_FILE_NULL_LENGHT_EQUALS_MISSING)
			{
				if (*pdwResponseSize == 0)
				{
					pCardData->pfnCspFree(*ppbResponse);
					*pdwResponseSize = 0;
					*ppbResponse = NULL;
					dwReturn = SCARD_E_FILE_NOT_FOUND;
					Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S OPENPGP_FILE_NULL_LENGHT_EQUALS_MISSING",szFile);
					__leave;
				}
			}
			if (Files[dwI].dwFlag & OPENPGP_FILE_CONF_IS_AUTH)
			{
				DWORD dwTempReturn = OCardIsConfidentialityKeyTheSameThanAuthentication(pCardData);
				if (dwTempReturn)
				{
					pCardData->pfnCspFree(*ppbResponse);
					*pdwResponseSize = 0;
					*ppbResponse = NULL;
					dwReturn = SCARD_E_FILE_NOT_FOUND;
					Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S OPENPGP_FILE_CONF_IS_AUTH",szFile);
					__leave;
				}
			}
		}
		else
		{
			if (szDirectory == NULL)
			{
				if (_stricmp(szFile, szCARD_APPLICATION_FILE) == 0)
				{
					dwReturn = OCardDirectoryList(pCardData, ppbResponse, pdwResponseSize);
				}
				else if (_stricmp(szFile, szCACHE_FILE) == 0)
				{
					*pdwResponseSize = sizeof(CARD_CACHE_FILE_FORMAT);
					*ppbResponse = pCardData->pfnCspAlloc(*pdwResponseSize);
					memset(*ppbResponse,0,*pdwResponseSize);
				}
				else
				{
					dwReturn = SCARD_E_FILE_NOT_FOUND;
					Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S",szFile);
				}
			}
			else if (_stricmp(szDirectory,szBASE_CSP_DIR) == 0)
			{
				if (_stricmp(szFile, szCONTAINER_MAP_FILE) == 0)
				{
					dwReturn = OCardReadContainerMapFile(pCardData, ppbResponse, pdwResponseSize);
				}
				else
				{
					dwReturn = SCARD_E_FILE_NOT_FOUND;
					Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S",szFile);
				}
			}
			else
			{
				dwReturn = SCARD_E_DIR_NOT_FOUND;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_DIR_NOT_FOUND %S",szDirectory);
			}
		}
		if (dwReturn)
		{
			__leave;
		}
		// add to the cache
		dwReturn = 0;

	}
	__finally
	{
		if( pbData)
			pCardData->pfnCspFree(pbData);
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"%S\\%S dwReturn = 0x%08X size = %d",szDirectory, szFile, dwReturn, *pdwResponseSize);
	return dwReturn;
}

DWORD OCardEnumFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory,
					__in PBYTE* pbResponse, __in PDWORD pdwResponseSize)
{
	DWORD dwReturn = 0, dwTempReturn;
	DWORD dwI, dwSize;
	BOOL fDirectoryFound = FALSE;
	BOOL fAddToOuput;
	__try
	{
		*pbResponse = NULL;
		*pdwResponseSize = 0;
		
		// compute the max size of the buffer
		dwSize = 0;
		for(dwI = 0; dwI < dwFileCount; dwI++)
		{
			BOOL fMatch = FALSE;
			if (szDirectory == NULL)
			{
				if (!Files[dwI].szDirectory) fMatch = TRUE;
			}
			else
			{
				if (Files[dwI].szDirectory && _stricmp(szDirectory, Files[dwI].szDirectory) == 0) fMatch = TRUE;
			}
			if (fMatch && !(Files[dwI].dwFileType & OPENPGP_FILE_WRITE_ONLY))
			{
				dwSize += (DWORD) strlen( Files[dwI].szFile) + 1;
			}
		}
		dwSize += 1;
		*pbResponse = pCardData->pfnCspAlloc(dwSize);
		if (!*pbResponse)
		{
			dwReturn = SCARD_E_NO_MEMORY;
			__leave;
		}
		for(dwI = 0; dwI < dwFileCount; dwI++)
		{
			BOOL fMatch = FALSE;
			if (szDirectory == NULL)
			{
				if (!Files[dwI].szDirectory) fMatch = TRUE;
			}
			else
			{
				if (Files[dwI].szDirectory && _stricmp(szDirectory, Files[dwI].szDirectory) == 0) fMatch = TRUE;
			}
			if (fMatch)
			{
				fDirectoryFound = TRUE;
				fAddToOuput = TRUE;
				if (Files[dwI].dwFlag & OPENPGP_FILE_WRITE_ONLY)
				{
					fAddToOuput = FALSE;
				}
				if (fAddToOuput && (Files[dwI].dwFlag & OPENPGP_FILE_NULL_LENGHT_EQUALS_MISSING))
				{
					PBYTE pbData = NULL;
					DWORD dwSize;
					fAddToOuput = FALSE;
					// check if the file exists and be read
					dwTempReturn = OCardReadFile(pCardData, szDirectory, Files[dwI].szFile, &pbData, &dwSize);
					if (!dwTempReturn)
					{
						pCardData->pfnCspFree(pbData);
						if (dwSize > 0)
						{
							fAddToOuput = TRUE;
						}
					}
				}
				if (fAddToOuput && (Files[dwI].dwFlag & OPENPGP_FILE_CONF_IS_AUTH))
				{
					dwTempReturn = OCardIsConfidentialityKeyTheSameThanAuthentication(pCardData);
					if (dwTempReturn)
					{
						fAddToOuput = FALSE;
					}
				}
				if (fAddToOuput)
				{
					dwSize = (DWORD) strlen( Files[dwI].szFile) + 1;
					memcpy(*pbResponse + *pdwResponseSize,  Files[dwI].szFile, dwSize);
					*pdwResponseSize += dwSize;
				}
			}
		}
		if (!fDirectoryFound)
		{
			dwReturn = SCARD_E_DIR_NOT_FOUND;
			__leave;
		}
		(*pbResponse)[*pdwResponseSize] = '\0';
		*pdwResponseSize += 1;
		dwReturn = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

// read file
DWORD OCardGetFileInfo(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile,
					 __inout PCARD_FILE_INFO  pCardFileInfo)
{
	DWORD dwReturn = 0;
	PBYTE pbData = NULL;
	DWORD dwSize, dwI;
	__try
	{
		dwReturn = OCardReadFile(pCardData, szDirectory, szFile, &pbData, &dwSize);
		if (dwReturn)
		{
			__leave;
		}
		pCardData->pfnCspFree(pbData);
		pCardFileInfo->cbFileSize = dwSize;
		pCardFileInfo->AccessCondition = InvalidAc;
		for(dwI = 0; dwI < dwFileCount; dwI++)
		{
			BOOL fMatch = FALSE;
			if (szDirectory == NULL)
			{
				if (!Files[dwI].szDirectory) fMatch = TRUE;
			}
			else
			{
				if (Files[dwI].szDirectory && _stricmp(szDirectory, Files[dwI].szDirectory) == 0) fMatch = TRUE;
			}
			if (fMatch)
			{
				if (_stricmp(szFile, Files[dwI].szFile) == 0)
				{
					pCardFileInfo->AccessCondition = Files[dwI].dwAccess;
					break;
				}
			}
		}
		dwReturn = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;	
}

DWORD OCardWriteFileOnSmartCard(__in PCARD_DATA  pCardData, 
					__in OPENPGP_FILE File,
					__in PBYTE pbData, __in DWORD dwSize)
{
	DWORD dwReturn = 0;
	BYTE pbCmd[5 + 256] = {0x00, 0xDA, 0x00, 0x00, 0x00};
	DWORD dwCmdSize = 0;
	PBYTE pbCmdExtended = NULL;
	__try
	{
		if (dwSize > 0xFFFF)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"dwSize %d",dwSize);
			__leave;
		}
		if (dwSize < 256)
		{
			if (File.dwTlv > 0)
			{
				pbCmd[2] = (BYTE) (File.dwTlv / 0x100);
				pbCmd[3] = (BYTE) (File.dwTlv % 0x100);
			}
			else
			{
				pbCmd[2] = (BYTE) (File.dwTag / 0x100);
				pbCmd[3] = (BYTE) (File.dwTag % 0x100);
			}
			pbCmd[4] = (BYTE) dwSize;
			if (dwSize)
			{
				memcpy(pbCmd + 5, pbData, dwSize);
			}
			dwCmdSize = dwSize + 5;
			dwReturn = OCardSendCommand(pCardData, pbCmd, dwCmdSize);
			if (dwReturn)
			{
				__leave;
			}
		}
		else
		{
			dwCmdSize = dwSize + 7;
			pbCmdExtended = pCardData->pfnCspAlloc(dwCmdSize);
			if (!pbCmdExtended)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
				dwReturn = SCARD_E_NO_MEMORY;
				__leave;
			}
			pbCmdExtended[0] = 0;
			pbCmdExtended[1] = 0xDA;
			if (File.dwTlv > 0)
			{
				pbCmdExtended[2] = (BYTE) (File.dwTlv / 0x100);
				pbCmdExtended[3] = (BYTE) (File.dwTlv % 0x100);
			}
			else
			{
				pbCmdExtended[2] = (BYTE) (File.dwTag / 0x100);
				pbCmdExtended[3] = (BYTE) (File.dwTag % 0x100);
			}
			pbCmdExtended[4] = 0;
			pbCmdExtended[5] = (BYTE)(dwSize / 0x100);
			pbCmdExtended[6] = (BYTE)(dwSize % 0x100);
			memcpy(pbCmdExtended + 7, pbData, dwSize);
			dwReturn = OCardSendCommand(pCardData, pbCmdExtended, dwCmdSize);
			if (dwReturn)
			{
				__leave;
			}
		}
	}
	__finally
	{
		if(pbCmdExtended)
			pCardData->pfnCspFree(pbCmdExtended);
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardWriteFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile,
					__in PBYTE pbData, __in DWORD dwSize)
{
	DWORD dwI;
	DWORD dwReturn = 0;
	BOOL fDirectoryFound = FALSE;
	BOOL fFileFound = FALSE;
	__try
	{

		for(dwI = 0; dwI < dwFileCount; dwI++)
		{
			BOOL fMatch = FALSE;
			if (szDirectory == NULL)
			{
				if (!Files[dwI].szDirectory) fMatch = TRUE;
			}
			else
			{
				if (Files[dwI].szDirectory && _stricmp(szDirectory, Files[dwI].szDirectory) == 0) fMatch = TRUE;
			}
			if (fMatch)
			{
				fDirectoryFound = TRUE;
				if (_stricmp(szFile, Files[dwI].szFile) == 0)
				{
					fFileFound = TRUE;
					break;
				}
			}
		}
		if (!fFileFound)
		{
			if (fDirectoryFound)
			{
				dwReturn = SCARD_E_FILE_NOT_FOUND;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %S",szFile);
			}
			else
			{
				dwReturn = SCARD_E_DIR_NOT_FOUND;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_DIR_NOT_FOUND %S",szDirectory);
			}	
			__leave;
		}
		if (Files[dwI].dwFileType == StoredOnSmartCard)
		{
			dwReturn = OCardWriteFileOnSmartCard(pCardData, Files[dwI], pbData, dwSize);
		}
		else
		{
			dwReturn = SCARD_W_SECURITY_VIOLATION;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION %S",szFile);
			__leave;
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardDeleteFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile)
{
	return OCardWriteFile(pCardData, szDirectory, szFile, NULL, 0);
}

// just change the flag in Files
DWORD OCardCreateFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile)
{
	DWORD dwI;
	DWORD dwReturn = 0;
	BOOL fDirectoryFound = FALSE;
	BOOL fFileFound = FALSE;
	__try
	{
		for(dwI = 0; dwI < dwFileCount; dwI++)
		{
			BOOL fMatch = FALSE;
			if (szDirectory == NULL)
			{
				if (!Files[dwI].szDirectory) fMatch = TRUE;
			}
			else
			{
				if (Files[dwI].szDirectory && _stricmp(szDirectory, Files[dwI].szDirectory) == 0) fMatch = TRUE;
			}
			if (fMatch)
			{
				fDirectoryFound = TRUE;
				if (_stricmp(szFile, Files[dwI].szFile) == 0)
				{
					fFileFound = TRUE;
					break;
				}
			}
		}
		if (!fDirectoryFound)
		{
			dwReturn = SCARD_E_DIR_NOT_FOUND;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_DIR_NOT_FOUND %S",szFile);
			__leave;
		}
		if (!fFileFound)
		{
			dwReturn = SCARD_W_SECURITY_VIOLATION;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION %S",szFile);
			__leave;
		}
		
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}
