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



LPBYTE AllocateAndEncodeObject(LPVOID pvStruct, LPCSTR lpszStructType, LPDWORD pdwSize )
{
   // Get Key Usage blob size   
   LPBYTE pbEncodedObject = NULL;
   BOOL bResult = TRUE;
   DWORD dwError;
	__try
   {
	   *pdwSize = 0;	
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   NULL, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();
		  __leave;   
	   }   

	   // Allocate Memory for Key Usage Blob   
	   pbEncodedObject = (LPBYTE)LocalAlloc(0,*pdwSize);   
	   if (!pbEncodedObject)   
	   {   
		  bResult = FALSE;
		  dwError = GetLastError();   
		  __leave;   
	   }   

	   // Get Key Usage Extension blob   
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   pbEncodedObject, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();  
		  __leave;   
	   }   
   }
   __finally
   {
		if (pbEncodedObject && !bResult)
		{
			LocalFree(pbEncodedObject);
		}
   }
   return pbEncodedObject;
}

DWORD Personnalize()
{
	DWORD dwReturn;
	BOOL fSet;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	TCHAR szContainerName[] = OPENPGP_TEST_CONTAINER;
	BYTE pbData[4096];
	DWORD dwDataSize = ARRAYSIZE(pbData);
	BOOL bStatus;
	BYTE One = 1;
	CERT_NAME_BLOB SubjectIssuerBlob = {0};
	CERT_INFO CertInfo = {0};
	CertInfo.rgExtension = 0;
	CRYPT_BIT_BLOB KeyUsage;  
	BYTE ByteData; 
	LPBYTE pbKeyUsage = NULL; 
	DWORD dwSize;
	CERT_BASIC_CONSTRAINTS2_INFO BasicConstraints;
	LPBYTE pbBasicConstraints = NULL;
	CERT_ENHKEY_USAGE CertEnhKeyUsage = { 0, NULL };  
	LPBYTE pbEnhKeyUsage = NULL;
	CERT_EXTENSIONS CertExtensions = {0} ;
	PCCERT_CONTEXT pNewCertificateContext = NULL;
	SYSTEMTIME StartTime;
	SYSTEMTIME EndTime;
	HCERTSTORE hCertStore = NULL;
	BYTE pbCertificateBlob[4096];
	CERT_BLOB dbStore = {ARRAYSIZE(pbCertificateBlob),pbCertificateBlob};
	__try
	{
		 if (!pCardData)
		{
			dwReturn = SCARD_E_COMM_DATA_LOST;
			__leave;
		}
		fSet = FALSE;
		dwReturn = pCardData->pfnCardSetProperty(pCardData, CP_CARD_READ_ONLY, (PBYTE) &fSet, sizeof(BOOL),0);
		if (dwReturn) __leave;
		dwReturn = pCardData->pfnCardWriteFile(pCardData, "openpgp", "statusP1", 0, &One, 1);
		if (dwReturn) __leave;
		dwReturn = pCardData->pfnCardCreateContainerEx(pCardData, (BYTE) 0, 
											CARD_CREATE_CONTAINER_KEY_GEN, 
											AT_SIGNATURE, 1024, NULL, 1);
		if (dwReturn) __leave;
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
		// WARNING : AT_SIGNATURE is used implicitely when creating a new certificate
		// if you use AT_KEYEXCHANGE, the public key of the container
		// won't match the public key of the certificate
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
		dwReturn = pCardData->pfnCardCreateContainerEx(pCardData, (BYTE) 1, 
											CARD_CREATE_CONTAINER_KEY_IMPORT, 
											AT_KEYEXCHANGE, 1024, pbData, 3);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = pCardData->pfnCardCreateContainerEx(pCardData, (BYTE) 2, 
											CARD_CREATE_CONTAINER_KEY_IMPORT, 
											AT_SIGNATURE, 1024, pbData, 3);
		if (dwReturn)
		{
			__leave;
		}
		// create the cert data
		if (!CertStrToName(X509_ASN_ENCODING,TEXT("CN=test"),CERT_X500_NAME_STR,NULL,NULL,&SubjectIssuerBlob.cbData,NULL))
		{
			dwReturn = GetLastError();
			__leave;
		}
		SubjectIssuerBlob.pbData = (PBYTE) LocalAlloc(0,SubjectIssuerBlob.cbData);
		if (!SubjectIssuerBlob.pbData)
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CertStrToName(X509_ASN_ENCODING,TEXT("CN=test"),CERT_X500_NAME_STR,NULL,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,NULL))
		{
			dwReturn = GetLastError();
			__leave;
		}
		// max 10 extensions => we don't count them
		CertInfo.rgExtension = (PCERT_EXTENSION) LocalAlloc(0,sizeof(CERT_EXTENSION) * 10);
		CertInfo.cExtension = 0;
		if (!CertInfo.rgExtension) __leave;


		       // Set Key Usage according to Public Key Type   
		ZeroMemory(&KeyUsage, sizeof(KeyUsage));   
		KeyUsage.cbData = 1;   
		KeyUsage.pbData = &ByteData;   
		ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE |   
                     CERT_DATA_ENCIPHERMENT_KEY_USAGE|   
                     CERT_KEY_ENCIPHERMENT_KEY_USAGE |   
                     CERT_KEY_AGREEMENT_KEY_USAGE;   
		pbKeyUsage = AllocateAndEncodeObject(&KeyUsage,X509_KEY_USAGE,&dwSize);
		if (!pbKeyUsage) __leave;

		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_KEY_USAGE;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbKeyUsage;   
		// Increase extension count   
		CertInfo.cExtension++; 
		//////////////////////////////////////////////////

		// Zero Basic Constraints structure   
		ZeroMemory(&BasicConstraints, sizeof(BasicConstraints));   

		BasicConstraints.fCA = TRUE;   
		BasicConstraints.fPathLenConstraint = TRUE;   
		BasicConstraints.dwPathLenConstraint = 1;   
		pbBasicConstraints = AllocateAndEncodeObject(&BasicConstraints,X509_BASIC_CONSTRAINTS2,&dwSize);
		if (!pbBasicConstraints) __leave;

		// Set Basic Constraints extension   
		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_BASIC_CONSTRAINTS2;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbBasicConstraints;   
		// Increase extension count   
		CertInfo.cExtension++;  
		//////////////////////////////////////////////////
		CertEnhKeyUsage.cUsageIdentifier+=4;

		CertEnhKeyUsage.rgpszUsageIdentifier = (LPSTR*) LocalAlloc(0,sizeof(LPSTR)*CertEnhKeyUsage.cUsageIdentifier);
		if (!CertEnhKeyUsage.rgpszUsageIdentifier) __leave;
		CertEnhKeyUsage.cUsageIdentifier = 0;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_CLIENT_AUTH;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_SERVER_AUTH;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_SMARTCARD_LOGON;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_EFS;
		pbEnhKeyUsage = AllocateAndEncodeObject(&CertEnhKeyUsage,X509_ENHANCED_KEY_USAGE,&dwSize);
		if (!pbEnhKeyUsage) __leave;

		// Set Basic Constraints extension   
		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_ENHANCED_KEY_USAGE;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbEnhKeyUsage;   
		// Increase extension count   
		CertInfo.cExtension++; 
 
		//////////////////////////////////////////////////

		CertExtensions.cExtension = CertInfo.cExtension;
		CertExtensions.rgExtension = CertInfo.rgExtension;

		GetSystemTime(&StartTime);
		GetSystemTime(&EndTime);
		EndTime.wYear += 10;
		pNewCertificateContext = CertCreateSelfSignCertificate(hProv,&SubjectIssuerBlob,
			0,NULL,NULL,&StartTime,&EndTime,&CertExtensions);
		if (!pNewCertificateContext)
		{
			dwReturn = GetLastError();
			__leave;
		}
		/*hCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY,0,(HCRYPTPROV)NULL,0,NULL);
		if (!hCertStore)
		{
			dwReturn = GetLastError();
			__leave;
		}
		if( !CertAddCertificateContextToStore(hCertStore,                // Store handle
                                        pNewCertificateContext,                // Pointer to a certificate
                                        CERT_STORE_ADD_REPLACE_EXISTING, NULL) )
		{
			dwReturn = GetLastError();
			__leave;
		}
		if (!CertSaveStore(	hCertStore,
				PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
				  CERT_STORE_SAVE_AS_PKCS7,
				    CERT_STORE_SAVE_TO_MEMORY,
				      &dbStore,
				0))
		{
			dwReturn = GetLastError();
			__leave;
		}
		dwReturn = pCardData->pfnCardWriteFile(pCardData, szBASE_CSP_DIR, "kxc01", 0,
			dbStore.pbData,
			dbStore.cbData);
		if (dwReturn)
		{
			__leave;
		}*/
		dwReturn = pCardData->pfnCardWriteFile(pCardData, szBASE_CSP_DIR, "kxc01", 0,
			pNewCertificateContext->pbCertEncoded,
			pNewCertificateContext->cbCertEncoded);
		if (dwReturn)
		{
			__leave;
		}
		ViewCertificate(NULL, pNewCertificateContext);
		fSet = TRUE;
		dwReturn = pCardData->pfnCardSetProperty(pCardData, CP_CARD_READ_ONLY, (PBYTE) &fSet, sizeof(BOOL),0);
		if (dwReturn) __leave;

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