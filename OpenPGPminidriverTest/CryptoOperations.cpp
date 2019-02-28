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

DWORD GenerateNewKey(DWORD dwIndex)
{
	DWORD dwReturn, dwKeySpec;
	PIN_ID  PinId;
	__try
	{
		 if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		switch(dwIndex)
		{
		case 0:	//Signature,
			dwKeySpec = AT_SIGNATURE;
			PinId = ROLE_USER;
			break;
		case 2: //Authentication,
			dwKeySpec = AT_SIGNATURE;
			PinId = 3;
			break;
		case 1: // Confidentiality,
			dwKeySpec = AT_KEYEXCHANGE;
			PinId = 4;
			break;
		default:
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		dwReturn = pCardData->pfnCardCreateContainerEx(pCardData, (BYTE) dwIndex, 
											CARD_CREATE_CONTAINER_KEY_GEN, 
											dwKeySpec, 1024, NULL, PinId);
	}
	__finally
	{
	}
	return dwReturn;
}

#pragma pack(push,1)
typedef struct _RSAPUBLICKEYBLOB
{
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
	BYTE modulus[sizeof(DWORD)];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;
#pragma pack(pop)

DWORD ImportKey(DWORD dwIndex)
{
	DWORD dwReturn, dwKeySpec;
	PIN_ID  PinId;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	TCHAR szContainerName[] = OPENPGP_TEST_CONTAINER;
	BYTE pbData[4096];
	BYTE pbDataControl[4096];
	BYTE pbBlobRef[4096];
	DWORD dwDataSize = ARRAYSIZE(pbData);
	DWORD dwBlobRefSize = ARRAYSIZE(pbBlobRef);
	BOOL bStatus;
	CONTAINER_INFO  ContainerInfo;
	PRSAPUBLICKEYBLOB pBlob, pBlobRef;
	DWORD dwAglLen, dwSize;
	__try
	{
		 if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		switch(dwIndex)
		{
		case 0:	//Signature,
			dwKeySpec = AT_SIGNATURE;
			PinId = ROLE_USER;
			break;
		case 2: //Authentication,
			dwKeySpec = AT_SIGNATURE;
			PinId = 3;
			break;
		case 1: // Confidentiality,
			dwKeySpec = AT_KEYEXCHANGE;
			PinId = 4;
			break;
		default:
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		bStatus = CryptAcquireContext(&hProv, szContainerName, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			if (dwReturn == NTE_BAD_KEYSET)
			{
				bStatus = CryptAcquireContext(&hProv, szContainerName, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
			}
			if (!bStatus) 
			{
				dwReturn = GetLastError();
				__leave;
			}
		}
		bStatus = CryptGenKey(hProv, dwKeySpec, CRYPT_EXPORTABLE, &hKey);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptExportKey(hKey,  NULL, PRIVATEKEYBLOB, 0, pbData, &dwDataSize);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			__leave;
		}
		memcpy(pbDataControl, pbData, ARRAYSIZE(pbData));
		dwSize = sizeof(DWORD);
		bStatus = CryptGetKeyParam(hKey, KP_KEYLEN, (PBYTE) &dwAglLen,&dwSize , 0);
		dwReturn = pCardData->pfnCardCreateContainerEx(pCardData, (BYTE) dwIndex, 
											CARD_CREATE_CONTAINER_KEY_IMPORT, 
											dwKeySpec, dwAglLen, pbData, PinId);
		if (dwReturn)
		{
			__leave;
		}
		// check if the buffer has been altered
		if (memcmp(pbDataControl,pbData, ARRAYSIZE(pbData)) != 0)
		{
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}

		memset(&ContainerInfo,0,sizeof(CONTAINER_INFO));
		ContainerInfo.dwVersion = 0;
		dwReturn = pCardData->pfnCardGetContainerInfo(pCardData, (BYTE) dwIndex, 0, &ContainerInfo);
		if (dwReturn)
		{
			__leave;
		}
		bStatus = CryptExportKey(hKey,  NULL, PUBLICKEYBLOB, 0, pbBlobRef, &dwBlobRefSize);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			__leave;
		}
		pBlobRef = (PRSAPUBLICKEYBLOB) pbBlobRef;
		pBlob = (PRSAPUBLICKEYBLOB) (dwKeySpec==AT_SIGNATURE ? ContainerInfo.pbSigPublicKey : ContainerInfo.pbKeyExPublicKey);
		//if (memcmp(pBlobRef, pBlob, ContainerInfo.cbSigPublicKey) != 0)
		for (DWORD dwI = 0; dwI < pBlobRef->rsapubkey.bitlen / 8; dwI++)
		{
			if ( pBlobRef->modulus[dwI] != pBlob->modulus[dwI])
			{
				dwReturn = SCARD_E_UNEXPECTED;
				__leave;
			}
		}
		dwReturn = 0;

	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		//CryptAcquireContext(&hProv, szContainerName, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		if (hProv)
			CryptReleaseContext(hProv,0);
	}
	return dwReturn;
}

DWORD SetTheSameKeyForAllContainers()
{
	DWORD dwReturn, dwKeySpec;
	PIN_ID  PinId;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	TCHAR szContainerName[] = OPENPGP_TEST_CONTAINER;
	BYTE pbData[4096];
	BYTE pbDataControl[4096];
	BYTE pbBlobRef[4096];
	DWORD dwDataSize = ARRAYSIZE(pbData);
	DWORD dwBlobRefSize = ARRAYSIZE(pbBlobRef);
	BOOL bStatus;
	CONTAINER_INFO  ContainerInfo;
	PRSAPUBLICKEYBLOB pBlob, pBlobRef;
	DWORD dwAglLen, dwSize, dwIndex;
	__try
	{
		 if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		bStatus = CryptAcquireContext(&hProv, szContainerName, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			if (dwReturn == NTE_BAD_KEYSET)
			{
				bStatus = CryptAcquireContext(&hProv, szContainerName, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
			}
			if (!bStatus) 
			{
				dwReturn = GetLastError();
				__leave;
			}
		}
		bStatus = CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			__leave;
		}
		bStatus = CryptExportKey(hKey,  NULL, PRIVATEKEYBLOB, 0, pbData, &dwDataSize);
		if (!bStatus) 
		{
			dwReturn = GetLastError();
			__leave;
		}
		memcpy(pbDataControl, pbData, ARRAYSIZE(pbData));
		dwSize = sizeof(DWORD);
		bStatus = CryptGetKeyParam(hKey, KP_KEYLEN, (PBYTE) &dwAglLen,&dwSize , 0);

		for(dwIndex = 0; dwIndex < 3; dwIndex++)
		{
			switch(dwIndex)
			{
			case 0:	//Signature,
				dwKeySpec = AT_SIGNATURE;
				PinId = ROLE_USER;
				break;
			case 2: //Authentication,
				dwKeySpec = AT_SIGNATURE;
				PinId = 3;
				break;
			case 1: // Confidentiality,
				dwKeySpec = AT_KEYEXCHANGE;
				PinId = 4;
				break;
			default:
				dwReturn = SCARD_E_UNEXPECTED;
				__leave;
			}

			dwReturn = pCardData->pfnCardCreateContainerEx(pCardData, (BYTE) dwIndex, 
												CARD_CREATE_CONTAINER_KEY_IMPORT, 
												dwKeySpec, dwAglLen, pbData, PinId);
			if (dwReturn)
			{
				__leave;
			}
			// check if the buffer has been altered
			if (memcmp(pbDataControl,pbData, ARRAYSIZE(pbData)) != 0)
			{
				dwReturn = SCARD_E_UNEXPECTED;
				__leave;
			}

			memset(&ContainerInfo,0,sizeof(CONTAINER_INFO));
			ContainerInfo.dwVersion = 0;
			dwReturn = pCardData->pfnCardGetContainerInfo(pCardData, (BYTE) dwIndex, 0, &ContainerInfo);
			if (dwReturn)
			{
				__leave;
			}
			bStatus = CryptExportKey(hKey,  NULL, PUBLICKEYBLOB, 0, pbBlobRef, &dwBlobRefSize);
			if (!bStatus) 
			{
				dwReturn = GetLastError();
				__leave;
			}
			pBlobRef = (PRSAPUBLICKEYBLOB) pbBlobRef;
			pBlob = (PRSAPUBLICKEYBLOB) (dwKeySpec==AT_SIGNATURE ? ContainerInfo.pbSigPublicKey : ContainerInfo.pbKeyExPublicKey);
			//if (memcmp(pBlobRef, pBlob, ContainerInfo.cbSigPublicKey) != 0)
			for (DWORD dwI = 0; dwI < pBlobRef->rsapubkey.bitlen / 8; dwI++)
			{
				if ( pBlobRef->modulus[dwI] != pBlob->modulus[dwI])
				{
					dwReturn = SCARD_E_UNEXPECTED;
					__leave;
				}
			}
		}
		dwReturn = 0;

	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		//CryptAcquireContext(&hProv, szContainerName, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		if (hProv)
			CryptReleaseContext(hProv,0);
	}
	return dwReturn;
}
DWORD SetReadOnly(BOOL fSet)
{
	DWORD dwReturn;
	__try
	{
		if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		dwReturn = pCardData->pfnCardSetProperty(pCardData, CP_CARD_READ_ONLY, (PBYTE) &fSet, sizeof(BOOL),0);
	}
	__finally
	{
	}
	return dwReturn;
}