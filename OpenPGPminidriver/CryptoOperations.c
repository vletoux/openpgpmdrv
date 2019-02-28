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
#include "CryptoOperations.h"
#include "PinOperations.h"
#include "PublicDataOperations.h"
#include "tlv.h"

OPENPGP_KEY_INFO Keys[] = 
{
	{0xB6, 0xCE, 0xC7, CALG_RSA_SIGN}, // signature
 	{0xB8, 0xCF, 0xC8, CALG_RSA_KEYX}, // confidentiality
	{0xA4, 0xD0, 0xC9, CALG_RSA_SIGN}  // authentication
};

OPENPGP_CONTAINER_INFO Containers[] = 
{
	{ROLE_SIGNATURE, AT_SIGNATURE},
	{ROLE_AUTHENTICATION, AT_KEYEXCHANGE},
	{ROLE_AUTHENTICATION, AT_SIGNATURE}
};
typedef struct _OPENPGP_SUPPORTED_SIGNATURE_ALGORITHM
{
	ALG_ID aiHashAlg;
	DWORD  dwHashSize;
	PBYTE pbEncodedOid;
	DWORD dwEncodedOidSize;
	PWSTR szAlgId;
} OPENPGP_SUPPORTED_SIGNATURE_ALGORITHM, *POPENPGP_SUPPORTED_SIGNATURE_ALGORITHM;

BYTE dwSHA1EncodedOid[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
			0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
BYTE dwSHA256EncodedOid[] = {0x30, 0x31, 0x30, 0x0D,0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
			0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
BYTE dwSHA384EncodedOid[] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
			0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
BYTE dwSHA512EncodedOid[] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
			0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

#define OPENPGP_NO_OID 0xFFFFFFFF
OPENPGP_SUPPORTED_SIGNATURE_ALGORITHM SignatureAlgorithm[] = 
{
	{CALG_SHA1,20, 
			dwSHA1EncodedOid,
			ARRAYSIZE(dwSHA1EncodedOid), BCRYPT_SHA1_ALGORITHM},
	{CALG_SHA-256,32,
			dwSHA256EncodedOid,
			ARRAYSIZE(dwSHA256EncodedOid), BCRYPT_SHA256_ALGORITHM},
	{CALG_SHA-384,48,
			dwSHA384EncodedOid,
			ARRAYSIZE(dwSHA384EncodedOid), BCRYPT_SHA384_ALGORITHM},
	{CALG_SHA-512,64,
			dwSHA512EncodedOid,
			ARRAYSIZE(dwSHA512EncodedOid), BCRYPT_SHA512_ALGORITHM},
};

DWORD dwSignatureAlgorithmCount = ARRAYSIZE(SignatureAlgorithm);



typedef struct _RSAPUBLICKEYBLOB
{
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
	BYTE modulus[sizeof(DWORD)];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;


DWORD OCardGetKeyAlgorithmAttributes(__in PCARD_DATA pCardData, 
								__in OPENPGP_KEY dwKey,
								__out POPENPGP_ALGORITHM_ATTRIBUTE pAttributes)
{
	DWORD dwReturn;
	PSTR szAlgorithmAttributes = NULL;
	PBYTE pbData = NULL;
	DWORD dwResponseSize;
	WORD wTemp;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKey);
		switch(dwKey)
		{
		case KeySignature:
			szAlgorithmAttributes = szOpenPGPAlgoAttributesSignature;
			break;
		case KeyAuthentication:
			szAlgorithmAttributes = szOpenPGPAlgoAttributesAuthentication;
			break;
		case KeyConfidentiality:
			szAlgorithmAttributes = szOpenPGPAlgoAttributesDecryption;
			break;
		default:
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		dwReturn = OCardReadFile(pCardData, szOpenPGPDir, szAlgorithmAttributes, &pbData, &dwResponseSize);
		if (dwReturn)
		{
			__leave;
		}
		if (dwResponseSize != sizeof(OPENPGP_ALGORITHM_ATTRIBUTE))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_UNEXPECTED");
			__leave;
		}
		memcpy(pAttributes, pbData, dwResponseSize);
		// big endian, little endian ...
		wTemp = pAttributes->wExponentLengthInBit;
		pAttributes->wExponentLengthInBit = (wTemp % 0x100) * 0x100 + (wTemp / 0x100);
		wTemp = pAttributes->wModulusLengthInBit;
		pAttributes->wModulusLengthInBit = (wTemp % 0x100) * 0x100 + (wTemp / 0x100);
		
		dwReturn = 0;
	}
	__finally
	{
		if (pbData)
			pCardData->pfnCspFree(pbData);
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardSetKeyAlgorithmAttributes(__in PCARD_DATA pCardData, 
								__in OPENPGP_KEY dwKey,
								__out POPENPGP_ALGORITHM_ATTRIBUTE pAttributes)
{
	DWORD dwReturn;
	PSTR szAlgorithmAttributes = NULL;
	OPENPGP_ALGORITHM_ATTRIBUTE TempAttributes;
	WORD wTemp;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKey);
		switch(dwKey)
		{
		case KeySignature:
			szAlgorithmAttributes = szOpenPGPAlgoAttributesSignature;
			break;
		case KeyAuthentication:
			szAlgorithmAttributes = szOpenPGPAlgoAttributesAuthentication;
			break;
		case KeyConfidentiality:
			szAlgorithmAttributes = szOpenPGPAlgoAttributesDecryption;
			break;
		default:
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		memcpy(&TempAttributes, pAttributes, sizeof(OPENPGP_ALGORITHM_ATTRIBUTE));
		wTemp = TempAttributes.wExponentLengthInBit;
		TempAttributes.wExponentLengthInBit = (wTemp % 0x100) * 0x100 + (wTemp / 0x100);
		wTemp = TempAttributes.wModulusLengthInBit;
		TempAttributes.wModulusLengthInBit = (wTemp % 0x100) * 0x100 + (wTemp / 0x100);

		dwReturn = OCardWriteFile(pCardData, szOpenPGPDir, szAlgorithmAttributes, (PBYTE) &TempAttributes, sizeof(OPENPGP_ALGORITHM_ATTRIBUTE));
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn, dwKey);
	return dwReturn;
}

DWORD BuildSingleTlv(__in PBYTE buffer, __in BYTE bTlv, __in DWORD dwTlvSize, __inout PDWORD pdwOffset)
{
	DWORD dwSize = 1;
	buffer[(*pdwOffset)++] = bTlv;
	// truncate if too long
	if (dwTlvSize > 0xFFFF) dwTlvSize = 0xFFFF;
	if (dwTlvSize < 0x7F)
	{
		buffer[(*pdwOffset)++] = (BYTE) dwTlvSize;
		dwSize++;
	}
	else if (dwTlvSize < 0xFF)
	{
		buffer[(*pdwOffset)++] = 0x81;
		buffer[(*pdwOffset)++] = (BYTE) dwTlvSize;
		dwSize+=2;
	}
	else
	{
		buffer[(*pdwOffset)++] = 0x82;
		buffer[(*pdwOffset)++] = (BYTE) (dwTlvSize / 0x100);
		buffer[(*pdwOffset)++] = (BYTE) (dwTlvSize % 0x100);
		dwSize+=3;
	}
	return dwSize;
}

DWORD BuildPrivateKeyTlv(__in PCARD_DATA pCardData, __in PRSAPUBLICKEYBLOB pbPublicKeyBlob, 
						  __in OPENPGP_KEY dwKey, __in BYTE bFormat,
						 __out PBYTE * ppbTlv, __out PDWORD pdwTlvSize)
{
	// structure of the keyblob
	//BLOBHEADER blobheader;
	//RSAPUBKEY rsapubkey;
	//BYTE modulus[rsapubkey.bitlen/8];
	//BYTE prime1[rsapubkey.bitlen/16];
	//BYTE prime2[rsapubkey.bitlen/16];
	//BYTE exponent1[rsapubkey.bitlen/16];
	//BYTE exponent2[rsapubkey.bitlen/16];
	//BYTE coefficient[rsapubkey.bitlen/16];
	//BYTE privateExponent[rsapubkey.bitlen/8];
	DWORD dwReturn = 0;
	
	DWORD bitlen = pbPublicKeyBlob->rsapubkey.bitlen;
	PBYTE pbPublicKeyData = (PBYTE) &(pbPublicKeyBlob->modulus);
	// 7F48 len is < 7F so its encoded len is 1 bytes
	// 3 bytes max + length * 7 potential plv
	BYTE b7F48Header[(3 +1) * 7 + 3] = {0x7F, 0x48}; 
	BYTE b5F48Header[3 + 2] = {0x5F, 0x48};
	BYTE b4DHeader[3 + 1] = {0x4D};
	DWORD dwOffset = 0;
	DWORD dw7F48HeaderSize, dw5F48HeaderSize, dw4DHeaderSize;
	DWORD dwKeyDataSize, dwExtendedHeaderListSize;
	DWORD dwI;
	__try
	{
		// build the 7F48 header + the data into a buffer
		dwOffset = 3;
		dw7F48HeaderSize = 0;
		dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x91, sizeof(DWORD), &dwOffset);
		dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x92, bitlen / 16, &dwOffset);
		dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x93, bitlen / 16, &dwOffset);
		if (bFormat & 2)
		{
			// add crt (chineese reminder theorem) template
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x94, bitlen / 16, &dwOffset);
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x95, bitlen / 16, &dwOffset);
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x96, bitlen / 16, &dwOffset);
		}
		if (bFormat & 1)
		{
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x97, bitlen / 8, &dwOffset);
		}
		b7F48Header[2] = (BYTE) dw7F48HeaderSize;
		dw7F48HeaderSize += 3; // before = only content, after += header size
		// build 5F48 header in a buffer
		// size of the data
		dwKeyDataSize = sizeof(DWORD) // e
										+ bitlen / 16 //prime1
										+ bitlen / 16 //prime2
										;
		if (bFormat & 2)
		{
			dwKeyDataSize+= bitlen / 16 //coefficient
										+ bitlen / 16 //exp1
										+ bitlen / 16 //exp2
										;
		}
		if (bFormat & 1)
		{
			dwKeyDataSize+= bitlen / 8 ; //modulus
		}
		dwOffset = 1;
		dw5F48HeaderSize = 1 + BuildSingleTlv(b5F48Header, 0x48, dwKeyDataSize, &dwOffset);
		// build the extended header list in a buffer
		dwExtendedHeaderListSize = 2 // for the crt to indicate the private key
								+ dw7F48HeaderSize
								+ dw5F48HeaderSize
								+ dwKeyDataSize;
		dwOffset = 0;
		dw4DHeaderSize = BuildSingleTlv(b4DHeader, 0x4D, dwExtendedHeaderListSize, &dwOffset);

		// allocate the memory
		*pdwTlvSize = dw4DHeaderSize + dwExtendedHeaderListSize;
		*ppbTlv = pCardData->pfnCspAlloc(*pdwTlvSize);
		if (! *ppbTlv)
		{
			dwReturn = SCARD_E_NO_MEMORY;
			__leave;
		}
		// 4D header
		dwOffset = 0;
		memcpy(*ppbTlv + dwOffset, b4DHeader, dw4DHeaderSize);
		dwOffset += dw4DHeaderSize;
		// control reference templace
		(*ppbTlv)[dwOffset++] = Keys[dwKey].bKeyTag;
		(*ppbTlv)[dwOffset++] = 0;
		// cardholder private key template
		memcpy(*ppbTlv + dwOffset, b7F48Header, dw7F48HeaderSize);
		dwOffset += dw7F48HeaderSize;
		// Concatenation of key data header
		memcpy(*ppbTlv + dwOffset, b5F48Header, dw5F48HeaderSize);
		dwOffset += dw5F48HeaderSize;
		// Concatenation of key data
		// exponent little => big endian
		(*ppbTlv)[dwOffset++] = (BYTE) (pbPublicKeyBlob->rsapubkey.pubexp / 0x1000000);
		(*ppbTlv)[dwOffset++] = (BYTE) ((pbPublicKeyBlob->rsapubkey.pubexp % 0x1000000) / 0x10000);
		(*ppbTlv)[dwOffset++] = (BYTE) ((pbPublicKeyBlob->rsapubkey.pubexp % 0x10000) / 0x100);
		(*ppbTlv)[dwOffset++] = (BYTE) ((pbPublicKeyBlob->rsapubkey.pubexp % 0x100) / 0x1);
		// prime1
		//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2*bitlen)/16, bitlen / 16);
		for(dwI = 0; dwI < bitlen / 16; dwI++)
		{
			(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(3*bitlen)/16 - 1 - dwI];
		}
		dwOffset += bitlen / 16;
		
		// prime2
		for(dwI = 0; dwI < bitlen / 16; dwI++)
		{
			(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(4*bitlen)/16 - 1 - dwI];
		}
		//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (3*bitlen)/16, bitlen / 16);
		dwOffset += bitlen / 16;
		if (bFormat & 2)
		{
			// coeff
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2+1 + 3) * bitlen / 16 , bitlen / 16);
			for(dwI = 0; dwI < bitlen / 16; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(7*bitlen)/16 - 1 - dwI];
			}
			dwOffset += bitlen / 16;
			// exponent1
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2+1 + 1) * bitlen / 16 , bitlen / 16);
			for(dwI = 0; dwI < bitlen / 16; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(5*bitlen)/16 - 1 - dwI];
			}
			dwOffset += bitlen / 16;
			// exponent2
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2+1 + 2) * bitlen / 16 , bitlen / 16);
			for(dwI = 0; dwI < bitlen / 16; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(6*bitlen)/16 - 1 - dwI];
			}
			dwOffset += bitlen / 16;
		}
		if (bFormat & 1)
		{
			// modulus
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData, bitlen / 8);
			for(dwI = 0; dwI < bitlen / 8; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[bitlen / 8 - 1 - dwI];
			}
		}
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d", dwReturn, dwKey);
	return dwReturn;
}

DWORD CreateGenerationDateTime(__in PCARD_DATA pCardData,
							   __out PDWORD pdwSecondsSince1970)
{
	LARGE_INTEGER UnixZeroTime = {0}, WindowsTime;
	SYSTEMTIME WindowsSystemTime;
	FILETIME WindowsFileTime;
	UnixZeroTime.QuadPart = 116444736000000000I64; // january 1st 1970
	GetSystemTime(&WindowsSystemTime);
	SystemTimeToFileTime(&WindowsSystemTime, &WindowsFileTime);
	/* It is not recommended that you add and subtract values from the FILETIME
	structure to obtain relative times. Instead, you should copy the low- and high-order
	parts of the file time to a ULARGE_INTEGER  structure, perform 64-bit arithmetic
	on the QuadPart member, and copy the LowPart and HighPart  members into the 
	FILETIME structure.

	Do not cast a pointer to a FILETIME structure to either a ULARGE_INTEGER* 
	or __int64* value because it can cause alignment faults on 64-bit Windows.
	*/
	WindowsTime.HighPart = WindowsFileTime.dwHighDateTime;
	WindowsTime.LowPart = WindowsFileTime.dwLowDateTime;
	*pdwSecondsSince1970 = (DWORD)((WindowsTime.QuadPart - UnixZeroTime.QuadPart) / 10000000);
	return 0;
}


DWORD UpdateGenerationDateTime(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey,
							   __out DWORD dwSecondsSince1970)
{
	DWORD dwReturn = 0;
	
	BYTE pbCommand[] = {0x00, 0xDA, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
	DWORD dwCommandSize = ARRAYSIZE(pbCommand);
	__try
	{
		
		
		pbCommand[3] = Keys[dwKey].bDateTimeTag;
		pbCommand[5] = (BYTE) (dwSecondsSince1970 / 0x1000000);
		pbCommand[6] = (BYTE) ((dwSecondsSince1970 % 0x1000000) / 0x10000);
		pbCommand[7] = (BYTE) ((dwSecondsSince1970 % 0x10000) / 0x100);
		pbCommand[8] = (BYTE) ((dwSecondsSince1970 % 0x100) / 0x1);
		dwReturn = OCardSendCommand(pCardData, pbCommand, dwCommandSize);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn,dwKey);
	return dwReturn;
}

DWORD CreateFingerPrint(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey, 
						__in DWORD dwSecondsSince1970,
						__inout BYTE pbFingerPrint[20])
{
	// modulus in input are in big endian
	// rfc4880 12.2
	DWORD dwReturn = 0;
	PBYTE pbBuffer = NULL;
	DWORD dwBufferSize;
	DWORD dwOffset = 0;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	DWORD dwHashLen = 0x14, dwModulusSizeInBytes, dwModulusSizeInBit, dwExponent;
	DWORD dwI;
	__try
	{
		dwModulusSizeInBytes = pContext->dwModulusSizeInBytes[dwKey];
		dwModulusSizeInBit = dwModulusSizeInBytes * 8;
		dwExponent = pContext->dwExponent[dwKey];
		dwBufferSize = dwModulusSizeInBytes + sizeof(DWORD) + 10  + 3;
		pbBuffer = (PBYTE) pCardData->pfnCspAlloc(dwBufferSize);
		if (!pbBuffer)
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			__leave;
		}
		
		pbBuffer[dwOffset++] = 0x99;
		// -3 because of the header size
		pbBuffer[dwOffset++] = (BYTE) ((dwBufferSize-3) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwBufferSize-3) % 0x100);
		// rfc4880 5.5.2
		// version
		pbBuffer[dwOffset++] = 4;
		// timestamp
		pbBuffer[dwOffset++] = (BYTE) (dwSecondsSince1970 / 0x1000000);
		pbBuffer[dwOffset++] = (BYTE) ((dwSecondsSince1970 % 0x1000000) / 0x10000);
		pbBuffer[dwOffset++] = (BYTE) ((dwSecondsSince1970 % 0x10000) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwSecondsSince1970 % 0x100) / 0x1);
		// RSA
		pbBuffer[dwOffset++] = 1;
		// size of modulus
		pbBuffer[dwOffset++] = (BYTE) ((dwModulusSizeInBit % 0x10000) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwModulusSizeInBit % 0x100) / 0x1);
		// little endian => big endian
		for(dwI = 0; dwI < dwModulusSizeInBytes; dwI++)
		{
			pbBuffer[dwOffset + dwI] = pContext->pbModulusInLittleEndian[dwKey][dwModulusSizeInBytes - 1 - dwI];
		}
		// size of exponent
		pbBuffer[dwOffset++] = 0;
		pbBuffer[dwOffset++] = sizeof(DWORD);
		// exponent
		pbBuffer[dwOffset++] = (BYTE) (dwExponent / 0x1000000);
		pbBuffer[dwOffset++] = (BYTE) ((dwExponent % 0x1000000) / 0x10000);
		pbBuffer[dwOffset++] = (BYTE) ((dwExponent % 0x10000) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwExponent % 0x100) / 0x1);

		// hash using SHA1
		if (!CryptAcquireContext(&hProv,  NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			dwReturn = GetLastError();
			Trace(WINEVENT_LEVEL_ERROR, L"CryptAcquireContext 0x%08X", dwReturn);
			__leave;
		}
		if(!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) 
		{
			dwReturn = GetLastError();
			Trace(WINEVENT_LEVEL_ERROR, L"CryptCreateHash 0x%08X", dwReturn);
			__leave;
		}
		if(!CryptHashData(hHash, pbBuffer, dwBufferSize, 0)) 
		{
			dwReturn = GetLastError();
			Trace(WINEVENT_LEVEL_ERROR, L"CryptHashData 0x%08X", dwReturn);
			__leave;
		}
		if(!CryptGetHashParam(hHash, HP_HASHVAL, pbFingerPrint, &dwHashLen, 0)) {
			dwReturn = GetLastError();
			Trace(WINEVENT_LEVEL_ERROR, L"CryptGetHashParam 0x%08X", dwReturn);
			__leave;
		}
		

	}
	__finally
	{
		if (pbBuffer)
			pCardData->pfnCspFree(pbBuffer);
		if(hHash) 
			 CryptDestroyHash(hHash);
		if(hProv) 
			CryptReleaseContext(hProv,0);

	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn, dwKey);
	return dwReturn;

}

DWORD UpdateFingerPrint(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey, 
						__inout BYTE pbFingerPrint[20])
{
	BYTE pbCommand[25] = {0x00, 0xDA, 0x00, 0x00, 0x14};
	DWORD dwCommandSize = ARRAYSIZE(pbCommand), dwReturn;
	__try
	{
		pbCommand[3] = Keys[dwKey].bSignatureTag;
		memcpy(pbCommand + 5, pbFingerPrint, 20);
		dwReturn = OCardSendCommand(pCardData, pbCommand, dwCommandSize);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn,dwKey);
	return dwReturn;
}
DWORD OCardUpdateCachedPublicKey(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey)
{
	PBYTE pbData = NULL;
	DWORD dwResponseSize = 0, dwReturn;
	BYTE pbCmd[] = {0x00, 
				    0x47,
					0x81,
					0x00,
					0x00,
					0x00,
					0x02,
					0x00,
					0x00,
					0x00,
					0x00
					};
	DWORD dwCmdSize;
	DWORD dwTotalTlvSize, dwOffset;
	DWORD dwModulusSizeInBytes;
	PBYTE pbModulus;
	DWORD dwI;
	PBYTE pbExponent;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKey);
		if (dwKey >= KeyMax)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_INFO, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		if (pContext->pbModulusInLittleEndian[dwKey] != NULL)
		{
			pCardData->pfnCspFree(pContext->pbModulusInLittleEndian[dwKey]);
			pContext->pbModulusInLittleEndian[dwKey] = NULL;
		}
		pbCmd[7] = Keys[dwKey].bKeyTag;
		dwCmdSize = 9;
		if (pContext->fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = 0xFF;
		}

		dwReturn = OCardGetData(pCardData, pbCmd, dwCmdSize, &pbData, &dwResponseSize);
		if (dwReturn)
		{
			__leave;
		}
		dwOffset = 2;
		dwTotalTlvSize = getTlvSize(pbData + 2,&dwOffset) + 2;
		if (!find_tlv(pbData + dwOffset,0x81,dwTotalTlvSize,&pbModulus,&dwModulusSizeInBytes))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x81");
			__leave;
		}
		if (!find_tlv(pbData + dwOffset,0x82,dwTotalTlvSize, (PBYTE*)&pbExponent,NULL))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x81");
			__leave;
		}
		Trace(WINEVENT_LEVEL_INFO, L"dwModulusSize %d bits", dwModulusSizeInBytes * 8);
		
		pContext->dwExponent[dwKey] = pbExponent[0] * 0x1000000  + pbExponent[1] * 0x10000  + pbExponent[2] * 0x100 + pbExponent[3];
		pContext->pbModulusInLittleEndian[dwKey] = pCardData->pfnCspAlloc(dwModulusSizeInBytes);
		if (!pContext->pbModulusInLittleEndian[dwKey])
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(WINEVENT_LEVEL_INFO, L"SCARD_E_NO_MEMORY");
			__leave;
		}
		// convert big endian into little endian
		for (dwI = 0; dwI < dwModulusSizeInBytes; dwI++)
		{
			pContext->pbModulusInLittleEndian[dwKey][dwI] = pbModulus[dwModulusSizeInBytes - 1 - dwI];
		}
		pContext->dwModulusSizeInBytes[dwKey] = (WORD) dwModulusSizeInBytes;
		dwReturn = 0;
	}
	__finally
	{
		if (pbData)
			pCardData->pfnCspFree(pbData);
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardUpdateCachedPublicKeyIfNeeded(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey)
{
	PBYTE pbFingerPrint = NULL;
	DWORD dwFingerPrintSize, dwReturn;
	BOOL fHasToUpdateTheCache;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	LARGE_INTEGER Now;
	SYSTEMTIME WindowsSystemTime;
	FILETIME WindowsFileTime;
	__try
	{
		GetSystemTime(&WindowsSystemTime);
		SystemTimeToFileTime(&WindowsSystemTime, &WindowsFileTime);
		Now.HighPart = WindowsFileTime.dwHighDateTime;
		Now.LowPart = WindowsFileTime.dwLowDateTime;
		// last read less than 0,2 s
		if ((Now.QuadPart - pContext->LastCacheCheck[dwKey].QuadPart) < 2000000)
		{
			Trace(WINEVENT_LEVEL_INFO, L"Cache up to date");
			pContext->LastCacheCheck[dwKey] = Now;
			dwReturn = 0;
			__leave;
		}
		Trace(WINEVENT_LEVEL_INFO, L"Updating cache");
		// try to use the cache
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
		// determine if we have to retrieve the modulus from the card
		if (memcmp(pbFingerPrint + dwKey * 20, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20) == 0)
		{
			// no public key => why want to read it ?
			Trace(WINEVENT_LEVEL_ERROR, L"pbFingerPrint null for key %d", dwKey);
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			if (pContext->pbModulusInLittleEndian[dwKey])
			{
				pCardData->pfnCspFree(pContext->pbModulusInLittleEndian[dwKey]);
				pContext->pbModulusInLittleEndian[dwKey] = NULL;
			}
			pContext->fHasKey[dwKey] = FALSE;
			__leave;
		}
		if (memcmp(pbFingerPrint + dwKey * 20, pContext->bFingerPrint + dwKey * 20, 20) == 0)
		{
			if (pContext->pbModulusInLittleEndian[dwKey])
			{
				fHasToUpdateTheCache = FALSE;
			}
			else
			{
				fHasToUpdateTheCache = TRUE;
			}
		}
		else
		{
			fHasToUpdateTheCache = TRUE;
		}
		if (fHasToUpdateTheCache)
		{
			dwReturn = OCardUpdateCachedPublicKey(pCardData, dwKey);
			if (dwReturn)
			{
				__leave;
			}
		}
		pContext->LastCacheCheck[dwKey] = Now;
	}
	__finally
	{
		if (pbFingerPrint)
			pCardData->pfnCspFree(pbFingerPrint);
	}
	return dwReturn;
}

DWORD OCardGetKeyLengthInBytes(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey, __out PDWORD pdwLengthInBytes)
{
	DWORD dwReturn;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKey);
		if (dwKey >= KeyMax)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_INFO, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		dwReturn = OCardUpdateCachedPublicKeyIfNeeded(pCardData, dwKey);
		if (dwReturn)
		{
			__leave;
		}
		*pdwLengthInBytes = pContext->dwModulusSizeInBytes[dwKey];
		Trace(WINEVENT_LEVEL_VERBOSE, L"modulus size in bits= %d",*pdwLengthInBytes*8);
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardReadPublicKey(PCARD_DATA pCardData, OPENPGP_KEY dwKey, PBYTE *pbPublicKey, PDWORD pdwPublicKeySize)
{
	DWORD dwReturn;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	PRSAPUBLICKEYBLOB pbBlob = NULL;
	DWORD dwModulusSizeInBytes;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKey);
		if (dwKey >= KeyMax)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_INFO, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		dwReturn = OCardUpdateCachedPublicKeyIfNeeded(pCardData, dwKey);
		if (dwReturn)
		{
			__leave;
		}
		dwModulusSizeInBytes = pContext->dwModulusSizeInBytes[dwKey];
		Trace(WINEVENT_LEVEL_INFO, L"dwModulusSize %d bits", dwModulusSizeInBytes * 8);
		*pdwPublicKeySize = sizeof(RSAPUBLICKEYBLOB) + dwModulusSizeInBytes - sizeof(DWORD);
		*pbPublicKey = pCardData->pfnCspAlloc(*pdwPublicKeySize);
		if (!*pbPublicKey)
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY %d", dwKey);
			__leave;
		}
		pbBlob = (PRSAPUBLICKEYBLOB) *pbPublicKey;
		memset(pbBlob,0,*pdwPublicKeySize);
		pbBlob->blobheader.bType = PUBLICKEYBLOB;
		pbBlob->blobheader.bVersion = CUR_BLOB_VERSION;
		pbBlob->blobheader.reserved = 0;
		pbBlob->blobheader.aiKeyAlg = Keys[dwKey].aiKeyAlg;
		pbBlob->rsapubkey.magic = 0x31415352; //'RSA1';
		pbBlob->rsapubkey.bitlen = dwModulusSizeInBytes*8;
		pbBlob->rsapubkey.pubexp = pContext->dwExponent[dwKey];
		memcpy(pbBlob->modulus, pContext->pbModulusInLittleEndian[dwKey], dwModulusSizeInBytes);
		dwReturn = 0;
	}
	__finally
	{
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardCreateKey(PCARD_DATA pCardData, OPENPGP_KEY dwKey, DWORD dwBitLen)
{
	DWORD dwReturn;
	PBYTE pbData = NULL;
	DWORD dwResponseSize = 0, dwCmdSize;
	OPENPGP_ALGORITHM_ATTRIBUTE Attributes;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	DWORD dwSecondsSince1970;
	PBYTE pbModulus, pbExponent;
	DWORD dwModulusSizeInBytes, dwExponent, dwI;
	BYTE pbCmd[] = {0x00, 
				    0x47,
					0x80,
					0x00,
					0x00,
					0x00,
					0x02,
					0x00,
					0x00,
					0x00,
					0x00
					};
	DWORD dwTotalTlvSize, dwOffset;
	BYTE pbFingerPrint[20];
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKey);
		if (dwKey >= KeyMax)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_INFO, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		// key len
		Attributes.wModulusLengthInBit = (unsigned short)dwBitLen;
		Attributes.wExponentLengthInBit = 4 * 8;
		Attributes.bAlgoId = 1;
		Attributes.bFormat = 0;
		dwReturn = OCardSetKeyAlgorithmAttributes(pCardData, dwKey, &Attributes);
		if (dwReturn)
		{
			__leave;
		}

		pbCmd[7] = Keys[dwKey].bKeyTag;
		dwCmdSize = 9;
		if (pContext->fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = 0xFF;
		}
		
		dwReturn = OCardGetData(pCardData, pbCmd, dwCmdSize, &pbData, &dwResponseSize);
		if (dwReturn)
		{
			__leave;
		}
		dwOffset = 2;
		dwTotalTlvSize = getTlvSize(pbData + 2,&dwOffset) + 2;
		if (!find_tlv(pbData + dwOffset,0x81,dwTotalTlvSize, &pbModulus,&dwModulusSizeInBytes))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x81");
			__leave;
		}
		if (!find_tlv(pbData + dwOffset,0x82,dwTotalTlvSize, (PBYTE*)&pbExponent,NULL))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x82");
			__leave;
		}
		dwExponent = pbExponent[0] * 0x1000000  + pbExponent[1] * 0x10000  + pbExponent[2] * 0x100 + pbExponent[3];
		// save in the cache
		pContext->fHasKey[dwKey] = TRUE;
		pContext->dwExponent[dwKey] = dwExponent;
		pContext->dwModulusSizeInBytes[dwKey] = (WORD) dwModulusSizeInBytes;
		if (pContext->pbModulusInLittleEndian[dwKey])
		{
			pCardData->pfnCspFree(pContext->pbModulusInLittleEndian[dwKey]);
		}
		pContext->pbModulusInLittleEndian[dwKey] = pCardData->pfnCspAlloc(dwModulusSizeInBytes);
		if (!pContext->pbModulusInLittleEndian[dwKey])
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			__leave;
		}
		for (dwI = 0; dwI < dwModulusSizeInBytes; dwI++)
		{
			pContext->pbModulusInLittleEndian[dwKey][dwI] = pbModulus[dwModulusSizeInBytes - 1 - dwI];
		}
		dwReturn = CreateGenerationDateTime(pCardData, &dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = CreateFingerPrint(pCardData, dwKey, dwSecondsSince1970, pbFingerPrint);
		if (dwReturn)
		{
			__leave;
		}
		// avoid two key having the same fingerprint if generated too fast
		while (memcmp(pbFingerPrint, pContext->bFingerPrint, 20) == 0
			|| memcmp(pbFingerPrint, pContext->bFingerPrint + 20, 20) == 0
			|| memcmp(pbFingerPrint, pContext->bFingerPrint + 40, 20) == 0)
		{
			dwSecondsSince1970++;
			dwReturn = CreateFingerPrint(pCardData, dwKey, dwSecondsSince1970, pbFingerPrint);
			if (dwReturn)
			{
				__leave;
			}
		}
		dwReturn = UpdateGenerationDateTime(pCardData, dwKey, dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = UpdateFingerPrint(pCardData, dwKey, pbFingerPrint);
		if (dwReturn)
		{
			__leave;
		}
		memcpy(pContext->bFingerPrint + 20 * dwKey, pbFingerPrint, 20);
	}
	__finally
	{
		if (pbData)
			pCardData->pfnCspFree(pbData);
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardImportKey(PCARD_DATA pCardData, 
					 OPENPGP_KEY dwKey,
					 PBYTE pBlob,
					 DWORD dwKeySize)
{
	DWORD dwReturn;
	PSTR szAlgorithmAttributes = NULL;
	PBYTE pbTlv = NULL;
	DWORD dwTlvSize;
	PBYTE pbCommand = NULL;
	DWORD dwCommandSize;
	OPENPGP_ALGORITHM_ATTRIBUTE Attributes;
	PRSAPUBLICKEYBLOB pbPublicKeyBlob = (PRSAPUBLICKEYBLOB) pBlob;
	BYTE bCommand[] = {0x00,0xDB,0x3F,0xFF};
	DWORD dwSecondsSince1970;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	BYTE pbFingerPrint[20];
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKey);
		// check blob
		if (pbPublicKeyBlob->blobheader.aiKeyAlg != CALG_RSA_SIGN &&
			pbPublicKeyBlob->blobheader.aiKeyAlg != CALG_RSA_KEYX)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Wrong aiKeyAlg %d", pbPublicKeyBlob->blobheader.aiKeyAlg);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pbPublicKeyBlob->blobheader.bType != PRIVATEKEYBLOB)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Wrong bType %d", pbPublicKeyBlob->blobheader.bType);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pbPublicKeyBlob->rsapubkey.magic != 0x32415352)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Wrong magic");
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		
		Attributes.wModulusLengthInBit = (WORD) pbPublicKeyBlob->rsapubkey.bitlen;
		Attributes.wExponentLengthInBit = 4 * 8;
		Attributes.bAlgoId = 1;
		Attributes.bFormat = 0;
		dwReturn = OCardSetKeyAlgorithmAttributes(pCardData, dwKey, &Attributes);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = BuildPrivateKeyTlv(pCardData, pbPublicKeyBlob, dwKey, Attributes.bFormat, &pbTlv, &dwTlvSize);
		if (dwReturn)
		{
			__leave;
		}
		if (dwTlvSize > 0xFF)
		{
			dwCommandSize = 7 + dwTlvSize;
			
		}
		else
		{
			dwCommandSize = 5 + dwTlvSize;
		}
		pbCommand = pCardData->pfnCspAlloc(dwCommandSize);
		if (!pbCommand)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			dwReturn = SCARD_E_NO_MEMORY;
			__leave;
		}
		memcpy(pbCommand, bCommand, 4);
		if (dwTlvSize > 0xFF)
		{
			pbCommand[4] = 0;
			pbCommand[5] = (BYTE)(dwTlvSize / 0x100);
			pbCommand[6] = (BYTE)(dwTlvSize % 0x100);
			memcpy(pbCommand + 7, pbTlv, dwTlvSize);
		}
		else
		{
			pbCommand[4] = (BYTE) dwTlvSize;
			memcpy(pbCommand + 5, pbTlv, dwTlvSize);
		}
		dwReturn = OCardSendCommand(pCardData, pbCommand, dwCommandSize);
		if (dwReturn)
		{
			__leave;
		}
		// save in the cache
		pContext->fHasKey[dwKey] = TRUE;
		pContext->dwExponent[dwKey] = pbPublicKeyBlob->rsapubkey.pubexp;
		pContext->dwModulusSizeInBytes[dwKey] = (WORD) pbPublicKeyBlob->rsapubkey.bitlen / 8;
		if (pContext->pbModulusInLittleEndian[dwKey])
		{
			pCardData->pfnCspFree(pContext->pbModulusInLittleEndian[dwKey]);
		}
		pContext->pbModulusInLittleEndian[dwKey] = pCardData->pfnCspAlloc(pContext->dwModulusSizeInBytes[dwKey]);
		if (!pContext->pbModulusInLittleEndian[dwKey])
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			__leave;
		}
		memcpy(pContext->pbModulusInLittleEndian[dwKey],&(pbPublicKeyBlob->modulus),pContext->dwModulusSizeInBytes[dwKey]);
		dwReturn = CreateGenerationDateTime(pCardData, &dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = CreateFingerPrint(pCardData, dwKey, dwSecondsSince1970, pbFingerPrint);
		if (dwReturn)
		{
			__leave;
		}
		// avoid two key having the same fingerprint if generated too fast
		while (memcmp(pbFingerPrint, pContext->bFingerPrint, 20) == 0
			|| memcmp(pbFingerPrint, pContext->bFingerPrint + 20, 20) == 0
			|| memcmp(pbFingerPrint, pContext->bFingerPrint + 40, 20) == 0)
		{
			dwSecondsSince1970++;
			dwReturn = CreateFingerPrint(pCardData, dwKey, dwSecondsSince1970, pbFingerPrint);
			if (dwReturn)
			{
				__leave;
			}
		}
		dwReturn = UpdateGenerationDateTime(pCardData, dwKey, dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = UpdateFingerPrint(pCardData, dwKey, pbFingerPrint);
		if (dwReturn)
		{
			__leave;
		}
		memcpy(pContext->bFingerPrint + 20 * dwKey, pbFingerPrint, 20);
	}
	__finally
	{
		if (pbCommand)
		{
			SecureZeroMemory(pbCommand, dwCommandSize);
			pCardData->pfnCspFree(pbCommand);
		}
		if (pbTlv)
		{
			SecureZeroMemory(pbTlv, dwTlvSize);
			pCardData->pfnCspFree(pbTlv);
		}
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn, dwKey);
	return dwReturn;
}

DWORD OCardCheckSigningInfo(__in PCARD_SIGNING_INFO  pInfo, __in BOOL fAllowNoOid, __out PDWORD pdwIndex)
{
	DWORD dwReturn, dwI;
	__try
	{
		if (pInfo->dwSigningFlags & ~(CARD_PADDING_INFO_PRESENT | CARD_BUFFER_SIZE_ONLY | CRYPT_NOHASHOID | CRYPT_TYPE2_FORMAT))
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wrong flag %d", pInfo->dwSigningFlags);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pInfo->cbData > 256)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"Error failure pInfo->cbData = %d",pInfo->cbData);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pInfo->dwSigningFlags & CARD_PADDING_INFO_PRESENT)
		{
			if ( pInfo->dwPaddingType == CARD_PADDING_PKCS1)
			{
				BCRYPT_PKCS1_PADDING_INFO* padding = (BCRYPT_PKCS1_PADDING_INFO*) pInfo->pPaddingInfo;
				if (padding->pszAlgId == NULL)
				{
					if (fAllowNoOid)
					{
						*pdwIndex = OPENPGP_NO_OID;
						dwReturn = 0;
						__leave;
					}
					else
					{
						Trace(WINEVENT_LEVEL_ERROR, L"alg not found %s", padding->pszAlgId);
						dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
						__leave;
					}
				}
				for(dwI = 0 ; dwI < dwSignatureAlgorithmCount ; dwI++)
				{
					if (wcscmp(SignatureAlgorithm[dwI].szAlgId,padding->pszAlgId) == 0)
					{
						// found
						break;
					}
				}
				if (dwI >= dwSignatureAlgorithmCount)
				{
					Trace(WINEVENT_LEVEL_ERROR, L"alg not found %s", padding->pszAlgId);
					dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
					__leave;
				}
			}
			else if (pInfo->dwPaddingType == CARD_PADDING_PSS)
			{
				dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
				Trace(WINEVENT_LEVEL_ERROR, L"CARD_PADDING_PSS");
				__leave;
			}
			else
			{
				dwReturn = SCARD_E_INVALID_PARAMETER;
				Trace(WINEVENT_LEVEL_ERROR, L"pInfo->dwPaddingType = %d", pInfo->dwPaddingType);
				__leave;
			}
		}
		else
		{
			if (!(pInfo->aiHashAlg & ALG_CLASS_HASH))
			{
				dwReturn = SCARD_E_INVALID_PARAMETER;
				Trace(WINEVENT_LEVEL_ERROR, L"pInfo->aiHashAlg == %d", pInfo->aiHashAlg);
				__leave;
			}
			for(dwI = 0 ; dwI < dwSignatureAlgorithmCount ; dwI++)
			{
				if (SignatureAlgorithm[dwI].aiHashAlg == pInfo->aiHashAlg)
				{
					// found
					break;
				}
			}
			if (dwI >= dwSignatureAlgorithmCount)
			{
				Trace(WINEVENT_LEVEL_ERROR, L"alg not found %d", pInfo->aiHashAlg);
				dwReturn = SCARD_E_UNSUPPORTED_FEATURE;
				__leave;
			}
		}
		if (SignatureAlgorithm[dwI].dwHashSize != pInfo->cbData)
		{
			Trace(WINEVENT_LEVEL_ERROR, L"wrong hash size %d", pInfo->cbData);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		*pdwIndex = dwI;
		dwReturn = 0;
	}
	__finally
	{
	}
	return dwReturn;
}

DWORD OCardSign(PCARD_DATA pCardData,
				PCARD_SIGNING_INFO  pInfo)
{
	DWORD dwReturn;
	PBYTE pbData = NULL;
	DWORD dwCmdSize = 0, dwIndex, dwI;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	BYTE pbCmd[6 + 256 + 256] = {0x00, 
				    0x2A,
					0x9E,
					0x9A,
					0x00,
					0x00,
					};
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwContainer=%d",pInfo->bContainerIndex);
		if (pInfo->bContainerIndex != ContainerSignature)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", pInfo->bContainerIndex);
			__leave;
		}
		dwReturn = OCardCheckSigningInfo(pInfo, FALSE, &dwIndex);
		if (dwReturn)
		{
			__leave;
		}
		if (pInfo->dwSigningFlags & CARD_BUFFER_SIZE_ONLY)
		{
			// optimisation :
			// return the buffer size only
			dwReturn = OCardGetKeyLengthInBytes(pCardData, pInfo->bContainerIndex, &pInfo->cbSignedData);
			__leave;
		}

		dwCmdSize = 5;
		if (pContext->fExtentedLeLcFields)
		{
			dwCmdSize++;
		}
		pbCmd[dwCmdSize++] = (BYTE) (SignatureAlgorithm[dwIndex].dwEncodedOidSize + pInfo->cbData);
		memcpy(pbCmd + dwCmdSize , SignatureAlgorithm[dwIndex].pbEncodedOid,SignatureAlgorithm[dwIndex].dwEncodedOidSize);
		dwCmdSize += SignatureAlgorithm[dwIndex].dwEncodedOidSize;
		/*for(dwI = 0 ; dwI < pInfo->cbData ; dwI++)
		{
			pbCmd[dwCmdSize + dwI] = pInfo->pbData[pInfo->cbData - dwI -1];
		}*/
		memcpy(pbCmd + dwCmdSize, pInfo->pbData,pInfo->cbData);
		dwCmdSize += pInfo->cbData;

		
		if (pContext->fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}
		dwReturn = OCardGetData(pCardData, pbCmd, dwCmdSize, &(pInfo->pbSignedData), &(pInfo->cbSignedData));
		if (dwReturn == SCARD_W_WRONG_CHV)
		{
			dwReturn = SCARD_W_SECURITY_VIOLATION;
			__leave;
		}
		if (dwReturn)
		{
			__leave;
		}
		// revert the BYTES
		for(dwI = 0 ; dwI < pInfo->cbSignedData / 2 ; dwI++)
		{
			BYTE bTemp = pInfo->pbSignedData[dwI];
			pInfo->pbSignedData[dwI] = pInfo->pbSignedData[pInfo->cbSignedData - 1 - dwI];
			pInfo->pbSignedData[pInfo->cbSignedData - 1 - dwI] = bTemp;
		}
	}
	__finally
	{
		if (dwReturn)
		{
			if (pInfo->pbSignedData)
				pCardData->pfnCspFree(pInfo->pbSignedData);
		}
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}
DWORD OCardIsConfidentialityKeyTheSameThanAuthentication(__in PCARD_DATA pCardData)
{
	DWORD dwReturn;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	__try
	{
	// see if the confidentiality key is the same than the authentication key
			// if yes, confidentiality key can sign
			// else ... we don't follow ms guidelines which requiers every container
			// to be able to sign data
			dwReturn = OCardUpdateCachedPublicKeyIfNeeded(pCardData, ContainerAuthentication);
			if (dwReturn)
			{
				__leave;
			}
			dwReturn = OCardUpdateCachedPublicKeyIfNeeded(pCardData, ContainerConfidentiality);
			if (dwReturn)
			{
				__leave;
			}
			if (pContext->dwModulusSizeInBytes[ContainerAuthentication]
							!= pContext->dwModulusSizeInBytes[ContainerConfidentiality])
			{
				dwReturn = SCARD_E_NO_KEY_CONTAINER;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER");
				__leave;
			}
			if (memcmp(pContext->pbModulusInLittleEndian[ContainerAuthentication],
				pContext->pbModulusInLittleEndian[ContainerConfidentiality],
				pContext->dwModulusSizeInBytes[ContainerConfidentiality]) != 0)
			{
				dwReturn = SCARD_E_NO_KEY_CONTAINER;
				Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER");
				__leave;
			}
			// if we are here, then the confidentiality key can sign using the authentication key
			dwReturn = 0;
	}
	__finally
	{
	}
	return dwReturn;
}
DWORD OCardAuthenticate(PCARD_DATA pCardData,
				PCARD_SIGNING_INFO  pInfo)
{
	DWORD dwReturn;
	PBYTE pbData = NULL;
	DWORD dwCmdSize = 0, dwIndex, dwI;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	BYTE pbCmd[6 + 256 + 256] = {0x00, 
				    0x88,
					0x00,
					0x00,
					0x00,
					0x00,
					};
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwContainer=%d",pInfo->bContainerIndex);
		
		if (pInfo->bContainerIndex != ContainerAuthentication && pInfo->bContainerIndex != ContainerConfidentiality)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", pInfo->bContainerIndex);
			__leave;
		}
		if (pInfo->bContainerIndex == ContainerConfidentiality)
		{
			dwReturn = OCardIsConfidentialityKeyTheSameThanAuthentication(pCardData);
			if (dwReturn)
			{
				__leave;
			}
		}
		dwReturn = OCardCheckSigningInfo(pInfo, TRUE, &dwIndex);
		if (dwReturn)
		{
			__leave;
		}
		if (pInfo->dwSigningFlags & CARD_BUFFER_SIZE_ONLY)
		{
			// optimisation :
			// return the buffer size only
			dwReturn = OCardGetKeyLengthInBytes(pCardData, pInfo->bContainerIndex, &pInfo->cbSignedData);
			__leave;
		}

		dwCmdSize = 5;
		if (pContext->fExtentedLeLcFields)
		{
			dwCmdSize++;
		}
		if (dwIndex == OPENPGP_NO_OID)
		{
			pbCmd[dwCmdSize++] = (BYTE) (pInfo->cbData);
		}
		else
		{
			pbCmd[dwCmdSize++] = (BYTE) (SignatureAlgorithm[dwIndex].dwEncodedOidSize + pInfo->cbData);
			memcpy(pbCmd + dwCmdSize , SignatureAlgorithm[dwIndex].pbEncodedOid,SignatureAlgorithm[dwIndex].dwEncodedOidSize);
			dwCmdSize += SignatureAlgorithm[dwIndex].dwEncodedOidSize;
		}
		memcpy(pbCmd + dwCmdSize, pInfo->pbData,pInfo->cbData);
		dwCmdSize += pInfo->cbData;
		
		if (pContext->fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}
		dwReturn = OCardGetData(pCardData, pbCmd, dwCmdSize, &(pInfo->pbSignedData), &(pInfo->cbSignedData));
		if (dwReturn == SCARD_W_WRONG_CHV)
		{
			dwReturn = SCARD_W_SECURITY_VIOLATION;
			__leave;
		}
		if (dwReturn)
		{
			__leave;
		}
		// revert the BYTES
		for(dwI = 0 ; dwI < pInfo->cbSignedData / 2 ; dwI++)
		{
			BYTE bTemp = pInfo->pbSignedData[dwI];
			pInfo->pbSignedData[dwI] = pInfo->pbSignedData[pInfo->cbSignedData - 1 - dwI];
			pInfo->pbSignedData[pInfo->cbSignedData - 1 - dwI] = bTemp;
		}
	}
	__finally
	{
		if (dwReturn)
		{
			if (pInfo->pbSignedData)
				pCardData->pfnCspFree(pInfo->pbSignedData);
		}
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OCardDecrypt(PCARD_DATA pCardData,
				PCARD_RSA_DECRYPT_INFO  pInfo)
{
	DWORD dwReturn;
	PBYTE pbData = NULL;
	DWORD dwCmdSize = 0, dwResponseSize;
	BYTE pbCmd[6 + 256 + 256] = {0x00, 
				    0x2A,
					0x80,
					0x86,
					0x00,
					};
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	DWORD dwI, dwModulusSizeInBytes;
	__try
	{
		Trace(WINEVENT_LEVEL_VERBOSE, L"Enter dwContainer=%d",pInfo->bContainerIndex);
		if (pInfo->bContainerIndex >= ContainerMax)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", pInfo->bContainerIndex);
			__leave;
		}
		if (pInfo->bContainerIndex != ContainerConfidentiality)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", pInfo->bContainerIndex);
			__leave;
		}
		// check the buffer size
		dwModulusSizeInBytes = pContext->dwModulusSizeInBytes[pInfo->bContainerIndex];
		if (pInfo->cbData < dwModulusSizeInBytes)
		{
			dwReturn = SCARD_E_INSUFFICIENT_BUFFER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_INSUFFICIENT_BUFFER %d", pInfo->cbData);
			__leave;
		}
		dwCmdSize = 5;
		if (pContext->fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)((pInfo->cbData +1) / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)((pInfo->cbData +1) % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = (BYTE)((pInfo->cbData +1) % 0x100);
		}
		pbCmd[dwCmdSize++] = 0;
		//little endian => big endian
		for(dwI = 0; dwI < pInfo->cbData; dwI++)
		{
			pbCmd[dwCmdSize + dwI] = pInfo->pbData[pInfo->cbData -1 -dwI];
		}
		dwCmdSize += pInfo->cbData;
		if (pContext->fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)(pContext->dwMaxCommandDataLength % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}
		dwReturn = OCardGetData(pCardData, pbCmd, dwCmdSize, &pbData, &dwResponseSize);
		if (dwReturn)
		{
			__leave;
		}
		
		if ( pInfo->cbData < dwResponseSize + 3 + 11)
		{
			dwReturn = SCARD_E_INSUFFICIENT_BUFFER;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_INSUFFICIENT_BUFFER %d expected = %d", pInfo->cbData, dwResponseSize);
			__leave;
		}
		if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		{
			// data field in reverse order (big endian => little endian)
			for(dwI = 0; dwI < dwResponseSize; dwI++)
			{
				pInfo->pbData[dwI] = pbData[dwResponseSize - 1 - dwI];
			}
			pInfo->cbData = dwResponseSize;
		}
		else
		{
			// CryptDecrypt expects the data decrypted using rsa (only the mathematical computation)
			// this means the data with the padding (removed by the card)
			// and in little endian (while the card return the data in big endian)
			// so we rebuilt the padding in reverse order
			
			pInfo->pbData[pInfo->cbData - 1] = 0; // start byte
			pInfo->pbData[pInfo->cbData - 2] = 02; // block type
			// padding
			memset(pInfo->pbData + dwResponseSize + 1,1,pInfo->cbData - 3 - dwResponseSize);
			pInfo->pbData[dwResponseSize] = 0; // separator
			// data field in reverse order
			for(dwI = 0; dwI < dwResponseSize; dwI++)
			{
				pInfo->pbData[dwI] = pbData[dwResponseSize - 1 - dwI];
			}
		}
		
	}
	__finally
	{
		if (pbData)
		{
			SecureZeroMemory(pbData, dwResponseSize);
			pCardData->pfnCspFree(pbData);
		}
	}
	Trace(WINEVENT_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}


DWORD OCardReadContainerMapFile(__in PCARD_DATA  pCardData, 
					__in PBYTE* ppbResponse, __in PDWORD pdwResponseSize)
{
	DWORD dwReturn = 0;
	POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;
	DWORD dwSizeInBits;
	__try
	{
		PCONTAINER_MAP_RECORD pContainer = NULL;
		BOOL fIsDefaultContainerSet = FALSE;
		*pdwResponseSize = sizeof(CONTAINER_MAP_RECORD) * ContainerMax;
		*ppbResponse = pCardData->pfnCspAlloc(*pdwResponseSize);
		if (! *ppbResponse )
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(WINEVENT_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			__leave;
		}
		pContainer = (PCONTAINER_MAP_RECORD) *ppbResponse;
		memset(pContainer,0,sizeof(CONTAINER_MAP_RECORD) * ContainerMax);
		
		dwReturn = OCardGetKeyLengthInBytes(pCardData, KeyAuthentication, &dwSizeInBits);
		if (dwReturn)
		{
			__leave;
		}
		pContainer[ContainerAuthentication].wSigKeySizeBits = (WORD)dwSizeInBits * 8;
		swprintf_s(pContainer[ContainerAuthentication].wszGuid,MAX_CONTAINER_NAME_LEN + 1,
			L"OPENPGP_%02X%02X_%02X%02X_%02X%02X%02X%02X_Authenticate",
			pContext->Aid.AidVersion[0],pContext->Aid.AidVersion[1],
			pContext->Aid.AidManufacturer[0],pContext->Aid.AidManufacturer[1],
			pContext->Aid.AidSerialNumber[0],pContext->Aid.AidSerialNumber[1],
			pContext->Aid.AidSerialNumber[2],pContext->Aid.AidSerialNumber[3]);
		if (pContext->fHasKey[KeyAuthentication])
		{
			pContainer[ContainerAuthentication].bFlags = CONTAINER_MAP_VALID_CONTAINER | CONTAINER_MAP_DEFAULT_CONTAINER;
			fIsDefaultContainerSet = TRUE;
		}

		dwReturn = OCardGetKeyLengthInBytes(pCardData, KeyConfidentiality, &dwSizeInBits);
		if (dwReturn)
		{
			__leave;
		}
		pContainer[ContainerConfidentiality].wKeyExchangeKeySizeBits = (WORD)dwSizeInBits * 8;
		swprintf_s(pContainer[ContainerConfidentiality].wszGuid,MAX_CONTAINER_NAME_LEN + 1,
			L"OPENPGP_%02X%02X_%02X%02X_%02X%02X%02X%02X_Confidential",
			pContext->Aid.AidVersion[0],pContext->Aid.AidVersion[1],
			pContext->Aid.AidManufacturer[0],pContext->Aid.AidManufacturer[1],
			pContext->Aid.AidSerialNumber[0],pContext->Aid.AidSerialNumber[1],
			pContext->Aid.AidSerialNumber[2],pContext->Aid.AidSerialNumber[3]);
		if (pContext->fHasKey[KeyConfidentiality])
		{
			pContainer[ContainerConfidentiality].bFlags = CONTAINER_MAP_VALID_CONTAINER;
			if (!fIsDefaultContainerSet)
			{
				pContainer[ContainerConfidentiality].bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;
				fIsDefaultContainerSet = TRUE;
			}
		}

		dwReturn = OCardGetKeyLengthInBytes(pCardData, KeySignature, &dwSizeInBits);
		if (dwReturn)
		{
			__leave;
		}
		pContainer[ContainerSignature].wSigKeySizeBits = (WORD)dwSizeInBits * 8;
		swprintf_s(pContainer[ContainerSignature].wszGuid,MAX_CONTAINER_NAME_LEN + 1,
			L"OPENPGP_%02X%02X_%02X%02X_%02X%02X%02X%02X_Signature",
			pContext->Aid.AidVersion[0],pContext->Aid.AidVersion[1],
			pContext->Aid.AidManufacturer[0],pContext->Aid.AidManufacturer[1],
			pContext->Aid.AidSerialNumber[0],pContext->Aid.AidSerialNumber[1],
			pContext->Aid.AidSerialNumber[2],pContext->Aid.AidSerialNumber[3]);
		if (pContext->fHasKey[KeySignature])
		{
			pContainer[ContainerSignature].bFlags = CONTAINER_MAP_VALID_CONTAINER;
			if (!fIsDefaultContainerSet)
			{
				pContainer[ContainerSignature].bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;
				fIsDefaultContainerSet = TRUE;
			}
		}
	}
	__finally
	{
	}
	return dwReturn;
}