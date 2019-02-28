DWORD getTlvSize(__in PBYTE pbPointer, __in PDWORD pdwOffset);
BOOL find_tlv(__in PBYTE pbData, __in  DWORD dwTlv, __in DWORD dwTotalSize, __out PBYTE *pbDataOut, __out_opt PDWORD pdwSize);
