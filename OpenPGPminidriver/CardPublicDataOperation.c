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
#include "PublicDataOperations.h"

// 4.3 Public Data Operations

/** This function creates a subdirectory from the root in the file system of 
the card and applies the provided access condition. Directories are generally 
created for segregating the files that belong to a single application on the card.
As an example, the files that belong to the Microsoft cryptographic application 
are in the “mscp” directory.*/

DWORD WINAPI CardCreateDirectory(
    __in PCARD_DATA  pCardData,
    __in LPSTR  pszDirectoryName,
    __in CARD_DIRECTORY_ACCESS_CONDITION  AccessCondition
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function deletes a directory from the card. This operation fails if it violates
permissions on the directory or if the directory is not empty. */
DWORD WINAPI CardDeleteDirectory(
    __in CARD_DATA  *pCardData,
    __in LPSTR  pszDirectoryName
)
{
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardReadFile function reads the entire file at the specified location into the 
user-supplied buffer.*/
DWORD WINAPI CardReadFile(
    __in PCARD_DATA  pCardData,
    __in_opt LPSTR  pszDirectoryName,
    __in LPSTR  pszFileName,
    __in DWORD  dwFlags,
    __deref_out_bcount_opt(*pcbData) PBYTE  *ppbData,
    __out PDWORD  pcbData
)
{
	DWORD dwReturn = 0;	
	PSTR szFiles = NULL;
	
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter %S\\%S",pszDirectoryName,pszFileName);
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pszFileName == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pszFileName == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( *pszFileName == 0 )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pszFileName empty");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (ppbData == NULL)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"ppbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pcbData == NULL)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pcbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags != 0)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = OCardReadFile(pCardData, pszDirectoryName, pszFileName, ppbData, pcbData);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardCreateFile function creates a file on the card with a specified name and
access permission. This function cannot be used to create directories. If the directory 
that is named by pszDirectoryName does not exist, the function fails with SCARD_E_DIR_NOT_FOUND.*/
DWORD WINAPI CardCreateFile(
    __in PCARD_DATA  pCardData,
    __in_opt LPSTR  pszDirectoryName,
    __in LPSTR  pszFileName,
    __in DWORD  cbInitialCreationSize,
    __in CARD_FILE_ACCESS_CONDITION  AccessCondition
)
{
	DWORD dwReturn = 0;	
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pszFileName == NULL || pszFileName[0] == 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pszFileName == NULL or empty");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
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
		dwReturn = OCardCreateFile(pCardData, pszDirectoryName, pszFileName);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** This function retrieves information about a file, specifically its size and ACL information.*/

DWORD WINAPI CardGetFileInfo(
    __in PCARD_DATA  pCardData,
    __in_opt LPSTR  pszDirectoryName,
    __in LPSTR  pszFileName,
    __inout PCARD_FILE_INFO  pCardFileInfo
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
		if ( pszFileName == NULL || pszFileName[0] == 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pszFileName == NULL or empty");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pCardFileInfo == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardFileInfo == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwVersion = (pCardFileInfo->dwVersion == 0) ? 1 : pCardFileInfo->dwVersion;
		if ( dwVersion != CARD_CAPABILITIES_CURRENT_VERSION )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion %d", dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = OCardGetFileInfo(pCardData, pszDirectoryName, pszFileName, pCardFileInfo);

	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardWriteFile function writes the entire contents of a data buffer to a file. 
The file contents are replaced, starting at the beginning of the file. The file must 
exist, or CardWriteFile fails.*/

DWORD WINAPI CardWriteFile(
    __in PCARD_DATA  pCardData,
    __in_opt LPSTR  pszDirectoryName,
    __in LPSTR  pszFileName,
    __in DWORD  dwFlags,
    __in_bcount(cbData) PBYTE  pbData,
    __in DWORD  cbData
)
{
	DWORD dwReturn = 0;	
	POPENPGP_CONTEXT pContext = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pszFileName == NULL || pszFileName[0] == 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pszFileName == NULL or empty");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pbData == NULL)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pbData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( cbData == 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"cbData == 0");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == %d", dwFlags);
			dwReturn  = SCARD_E_INVALID_PARAMETER;
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
		dwReturn = OCardWriteFile(pCardData, pszDirectoryName, pszFileName, pbData, cbData);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardDeleteFile function deletes the specified file. If the file does not exist,
the returned Status value should indicate that the file did not exist.*/

DWORD WINAPI CardDeleteFile(
    __in PCARD_DATA  pCardData,
    __in_opt LPSTR  pszDirectoryName,
    __in LPSTR  pszFileName,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	POPENPGP_CONTEXT pContext = NULL;
	PBYTE pbData = NULL;
	DWORD dwSize = 0;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pszFileName == NULL || pszFileName[0] == 0)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pszFileName == NULL or empty");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
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
		dwReturn = OCardDeleteFile(pCardData, pszDirectoryName, pszFileName);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardEnumFiles function returns name information about available files in a 
directory as a multistring list.*/

DWORD WINAPI CardEnumFiles(
    __in PCARD_DATA  pCardData,
    __in_opt LPSTR  pszDirectoryName,
    __deref_out_ecount(*pdwcbFileName) LPSTR  *pmszFileNames,
    __out LPDWORD  pdwcbFileName,
    __in DWORD  dwFlags
)
{
	DWORD dwReturn = 0;	
	PSTR szFiles = NULL;
	Trace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	__try
	{
		if ( pCardData == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardData == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pmszFileNames == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pmszFileNames == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if ( pdwcbFileName == NULL )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pmszFileNames == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (dwFlags != 0)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		if (pszDirectoryName != NULL)
		{
			DWORD dwLen = (DWORD) strlen(pszDirectoryName);
			if (dwLen > 8 || dwLen == 0)
			{
				dwReturn = SCARD_E_INVALID_PARAMETER;
				Trace(WINEVENT_LEVEL_ERROR, L"Invalid directory %S", pszDirectoryName);
				__leave;
			}
		}
		dwReturn = CheckContext(pCardData);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = OCardEnumFile(pCardData, pszDirectoryName, pmszFileNames, pdwcbFileName);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

/** The CardQueryFreeSpace function determines the amount of available card storage space.*/
DWORD WINAPI CardQueryFreeSpace(
    __in PCARD_DATA  pCardData,
    __in DWORD  dwFlags,
    __inout PCARD_FREE_SPACE_INFO  pCardFreeSpaceInfo
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
		if ( pCardFreeSpaceInfo == NULL)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"pCardFreeSpaceInfo == NULL");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		dwVersion = (pCardFreeSpaceInfo->dwVersion == 0) ? 1 : pCardFreeSpaceInfo->dwVersion;
		if ( dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION )
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwVersion %d", dwVersion);
			dwReturn  = ERROR_REVISION_MISMATCH;
			__leave;
		}
		if (dwFlags)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"dwFlags == 0");
			dwReturn  = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
		pCardFreeSpaceInfo->dwMaxKeyContainers = 3;
		pCardFreeSpaceInfo->dwKeyContainersAvailable = CARD_DATA_VALUE_UNKNOWN;
		pCardFreeSpaceInfo->dwBytesAvailable = CARD_DATA_VALUE_UNKNOWN;
		dwReturn = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

