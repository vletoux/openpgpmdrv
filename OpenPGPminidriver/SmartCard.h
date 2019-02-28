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

DWORD OCardSendCommand(__in PCARD_DATA  pCardData, __in PBYTE pbCmd, __in DWORD dwCmdSize);
DWORD SelectOpenPGPApplication(__in PCARD_DATA  pCardData);

DWORD OCardGetData(__in PCARD_DATA  pCardData, 
					__in PBYTE pbCmd, __in DWORD dwCmdSize,
					__in PBYTE* pbResponse, __in_opt PDWORD pdwResponseSize);

DWORD CCIDgetFeatures(__in PCARD_DATA  pCardData) ;