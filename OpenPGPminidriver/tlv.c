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



DWORD getTlvSize(__in PBYTE pbPointer, __in PDWORD pdwOffset)
{
	DWORD dwSize;
	switch(*pbPointer)
	{
	case 0x81:
		*pdwOffset+=2;
		dwSize = pbPointer[1];
		break;
	case 0x82:
		*pdwOffset+=3;
		dwSize = pbPointer[1] * 0x100 + pbPointer[2];
		break;
	default:
		dwSize = *pbPointer;
		*pdwOffset+=1;
		break;
	}
	return dwSize;
}

/** used to parse tlv data returned when reading the public certificate */
BOOL find_tlv(__in PBYTE pbData, __in  DWORD dwTlvSearched, __in DWORD dwTotalSize, __out PBYTE *pbDataOut, __out_opt PDWORD pdwSize)
{
	DWORD dwOffset = 0, dwTlv ;
	DWORD dwSize;
	BOOL bFound = FALSE;
	while (dwOffset < dwTotalSize)
	{
		// check the tlv
		// if it begins with 0x5F => tlv of 2 bytes.
		// else 1 byte
		dwTlv = 0;
		if (pbData[dwOffset] == 0x5F)
		{
			dwTlv = pbData[dwOffset] * 0x100;
			dwOffset++;
		}
		dwTlv += pbData[dwOffset];
		dwOffset++;
		

		if (dwTlv == dwTlvSearched)
		{
			// size sequence
			dwSize = getTlvSize(pbData + dwOffset,&dwOffset);
			if (pdwSize)
			{
				*pdwSize = dwSize;
			}
			*pbDataOut = pbData + dwOffset;
			return TRUE;
		}
		else
		{
			dwSize = getTlvSize(pbData + dwOffset,&dwOffset);
			if (dwTlv != 0x73)
			{
				dwOffset += dwSize;
			}
		}
	}
	return FALSE;
}
