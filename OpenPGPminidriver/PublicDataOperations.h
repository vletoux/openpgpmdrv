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

// max len = 8 bytes
#define szOpenPGPDir "openpgp"
#define szOpenPGPFingerprint "fingerpr"
#define szOpenPGPStatus "status"
#define szOpenPGPStatusPW1 "statusP1"
#define szOpenPGPApplicationIdentifier "aid"
#define szOpenPGPLogin "logindat"
#define szOpenPGPName "name"
#define szOpenPGPLanguage "language"
#define szOpenPGPSex "sex"
#define szOpenPGPUrl "url"
#define szOpenPGPHistoricalBytes "histo"
#define szOpenPGPCertificate "certific"
#define szOpenPGPExtendedCap "extcapab"
#define szOpenPGPAlgoAttributesSignature "algsign"
#define szOpenPGPAlgoAttributesDecryption "algcryp"
#define szOpenPGPAlgoAttributesAuthentication "algauth"
#define szOpenPGPPUK "puk"
#define szOpenPGPSecureMessaging "sm"
#define szOpenPGPSecureMessagingCryptographicCheksum "smmac"
#define szOpenPGPSecureMessagingCryptogram "smenc"


DWORD OCardReadFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR file,
					__in PBYTE* pbResponse, __in PDWORD pdwResponseSize);

DWORD OCardEnumFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory,
					__in PBYTE* pbResponse, __in PDWORD pdwResponseSize);

DWORD OCardGetFileInfo(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile,
					 __inout PCARD_FILE_INFO  pCardFileInfo);

DWORD OCardWriteFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile,
					__in PBYTE pbData, __in DWORD dwSize);

DWORD OCardDeleteFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile);

DWORD OCardCreateFile(__in PCARD_DATA  pCardData, 
					__in_opt PSTR szDirectory, __in PSTR szFile);