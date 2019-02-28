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

typedef enum _OPENPGP_CONTAINER
{
	ContainerSignature,
	ContainerConfidentiality,
	ContainerAuthentication,
	ContainerMax
} OPENPGP_CONTAINER;

typedef enum _OPENPGP_KEY
{
	KeySignature,
	KeyConfidentiality,
	KeyAuthentication,
	KeyMax
} OPENPGP_KEY;

typedef struct _OPENPGP_KEY_INFO
{
	BYTE    bKeyTag;
	BYTE    bDateTimeTag;
	BYTE    bSignatureTag;
	ALG_ID  aiKeyAlg;
} OPENPGP_KEY_INFO, *POPENPGP_KEY_INFO;

extern OPENPGP_KEY_INFO Keys[];

typedef struct _OPENPGP_CONTAINER_INFO
{
	PIN_ID  PinId;
	DWORD dwKeySpec;
} OPENPGP_CONTAINER_INFO, *POPENPGP_CONTAINER_INFO;

extern OPENPGP_CONTAINER_INFO Containers[];

#define OPENPGP_SUPPORTED_CYPHER_ALGORITHM L"\0"
#define OPENPGP_SUPPORTED_ASYMETRIC_ALGORITHM L"RSA\0"

#pragma pack(push,1)
typedef struct _OPENPGP_ALGORITHM_ATTRIBUTE
{
	BYTE bAlgoId;
	unsigned short wModulusLengthInBit;
	unsigned short wExponentLengthInBit;
	BYTE bFormat;
} OPENPGP_ALGORITHM_ATTRIBUTE, *POPENPGP_ALGORITHM_ATTRIBUTE;
#pragma pack(pop)

DWORD OCardReadPublicKey(PCARD_DATA  pCardData, 
						 OPENPGP_KEY dwKey, 
						 PBYTE *pbPublicKey, PDWORD pdwPublicKeySize);

DWORD OCardCreateKey(PCARD_DATA pCardData, OPENPGP_KEY dwKey, DWORD dwBitLen);

DWORD OCardImportKey(PCARD_DATA pCardData, 
					 OPENPGP_KEY dwKey,
					 PBYTE pBlob,
					 DWORD dwKeySize);

DWORD OCardSign(PCARD_DATA  pCardData,
				PCARD_SIGNING_INFO  pInfo);

DWORD OCardAuthenticate(PCARD_DATA pCardData,
				PCARD_SIGNING_INFO  pInfo);

DWORD OCardDecrypt(PCARD_DATA  pCardData,
				PCARD_RSA_DECRYPT_INFO  pInfo);

DWORD OCardReadContainerMapFile(__in PCARD_DATA  pCardData, 
					__in PBYTE* ppbResponse, __in PDWORD pdwResponseSize);

DWORD OCardGetKeyLengthInBytes(__in PCARD_DATA pCardData, __in OPENPGP_KEY dwKey,
							   __out PDWORD pdwLengthInBytes);

DWORD OCardIsConfidentialityKeyTheSameThanAuthentication(__in PCARD_DATA pCardData);