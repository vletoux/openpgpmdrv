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


typedef struct _OPENPGP_AID
{
	BYTE					AidRid[5];
	BYTE					AidApplication[1];
	BYTE					AidVersion[2];
	BYTE					AidManufacturer[2];
	BYTE					AidSerialNumber[4];
	BYTE					AidRFU[2];
} OPENPGP_AID;

#define FEATURE_VERIFY_PIN_START         0x01 
#define FEATURE_VERIFY_PIN_FINISH        0x02 
#define FEATURE_MODIFY_PIN_START         0x03 
#define FEATURE_MODIFY_PIN_FINISH        0x04 
#define FEATURE_GET_KEY_PRESSED          0x05 
#define FEATURE_VERIFY_PIN_DIRECT        0x06 
#define FEATURE_MODIFY_PIN_DIRECT        0x07 
#define FEATURE_MCT_READERDIRECT         0x08 
#define FEATURE_MCT_UNIVERSAL            0x09 
#define FEATURE_IFD_PIN_PROPERTIES       0x0A 
#define FEATURE_ABORT                    0x0B 

typedef struct _FEATURES
{
	DWORD VERIFY_PIN_START;
	DWORD VERIFY_PIN_FINISH;
	DWORD VERIFY_PIN_DIRECT;
	DWORD MODIFY_PIN_START;
	DWORD MODIFY_PIN_FINISH;
	DWORD MODIFY_PIN_DIRECT;
	DWORD ABORT;
	DWORD GET_KEY_PRESSED;
} FEATURES, *PFEATURES;

#define KEYMAX 3
typedef struct _OPENPGP_CONTEXT
{
	OPENPGP_AID				Aid;
	FEATURES				SmartCardReaderFeatures;
	BOOL					fSupportCommandChaining;
	BOOL					fExtentedLeLcFields;
	DWORD					dwMaxChallengeLength;
	DWORD					dwMaxCertificateLength;
	DWORD					dwMaxCommandDataLength;
	DWORD					dwMaxResponseLength;
	BOOL					fHasKey[KEYMAX];
	BOOL					fIsReadOnly;
	BYTE					bFingerPrint[60];
	PBYTE					pbModulusInLittleEndian[KEYMAX];
	WORD					dwModulusSizeInBytes[KEYMAX];
	DWORD					dwExponent[KEYMAX];
	LARGE_INTEGER			LastCacheCheck[KEYMAX];
	BOOL					fDoesTheAdminHasBeenAuthenticatedAtLeastOnce;
	ALG_ID					aiSecureMessagingAlg;
} OPENPGP_CONTEXT, *POPENPGP_CONTEXT ;

DWORD CreateContext(__in PCARD_DATA pCardData, __in DWORD dwFlags);
DWORD CheckContext(__in PCARD_DATA pCardData);
DWORD CleanContext(__in PCARD_DATA pCardData);