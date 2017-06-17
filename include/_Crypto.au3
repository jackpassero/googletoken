#include-once
; #INDEX# ========================================================================
; Title .........: _Crypto.au3
; AutoIt Version : 3.3.12.0
; Language ......: English
; Description ...: More functions for encrypting and hashing data.
; Author ........: inververs
; Modified ......:
; URL ...........: https://github.com/inververs
; Remarks .......: For new versions see my github page https://github.com/inververs
; Remarks .......: This UDF used Microsoft CryptoAPI
; Date ..........: 2017/06/01
; Version .......: 1.0.0
; ================================================================================

; #CURRENT# =====================================================================================================================
; _Crypto_Signing_SHA256RSA
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; __Crypto_CryptDecodeObjectEx
; __Crypto_StringToBinary
; __Crypto_BinaryToString
; __Crypto_Base64Encode
; ===============================================================================================================================


; #FUNCTION# ====================================================================================================================
; Name ..........: _Crypto_Signing_SHA256RSA
; Description ...: Sign input string using SHA256withRSA (also known as RSASSA-PKCS1-V1_5-SIGN with the SHA-256 hash function) with the private key
; Syntax ........: _Crypto_Signing_SHA256RSA($vIn, $sRSA_PRIVATE_KEY[, $asOpenSSL = True])
; Parameters ....: $vIn                 - A variant value. Input string, binary or struct
;                  $sRSA_PRIVATE_KEY    - A string value. PKCS#8 or PKCS#1 rsa private key
;                  $asOpenSSL           - [optional] A bool value. The signature must be compatible with OpenSSL. Default is True.
; Return values .: Base64 string on success. Or false and set @error flag on failure.
; Author ........: inververs
; Modified ......:
; Remarks .......: Rsa private key -----BEGIN PRIVATE KEY----- or  -----BEGIN RSA PRIVATE KEY----- supported
; Related .......:
; Link ..........:
; Example .......: _Crypto_Signing_SHA256RSA('eyJhbGciOiJSUzI1NiJ9.MQ', FileRead('private.key.txt'))
; ===============================================================================================================================
Func _Crypto_Signing_SHA256RSA($vIn, $sRSA_PRIVATE_KEY, $asOpenSSL = True)
    Local Const $CRYPT_STRING_BASE64HEADER = 0x00000000, $CRYPT_STRING_BASE64 = 0x00000001, $CRYPT_STRING_NOCRLF = 0x40000000
    Local Const $CRYPT_VERIFYCONTEXT = 0xF0000000
    Local Const $X509_ASN_ENCODING = 0x00000001, $PKCS_7_ASN_ENCODING = 0x00010000
    Local Const $PKCS_RSA_PRIVATE_KEY = 43, $PKCS_PRIVATE_KEY_INFO = 44
    Local Const $CALG_SHA_256 = 0x0000800C
    Local Const $AT_KEYEXCHANGE = 1, $PROV_RSA_AES = 24

    Local $hProv, $hHash, $szDataToSign, $sOut = False, $hAdvapi32 = DllOpen('Advapi32.dll')
    Select
        Case IsDllStruct($vIn)
            $szDataToSign = $vIn
        Case IsString($vIn)
            $vIn = StringToBinary($vIn, 4)
            ContinueCase
        Case Else
            $szDataToSign = DllStructCreate('byte[' & BinaryLen($vIn) & ']')
            DllStructSetData($szDataToSign, 1, $vIn)
    EndSelect

    Do
        Local $szPemPrivKey = DllStructCreate('char[' & StringLen($sRSA_PRIVATE_KEY) + 1 & ']')
        DllStructSetData($szPemPrivKey, 1, $sRSA_PRIVATE_KEY & Null)

        ;Decode PEM data to DER
        Local $tDER = __Crypto_StringToBinary($szPemPrivKey, $CRYPT_STRING_BASE64HEADER)
        If @error Then ExitLoop SetError(1, @error, 1)

        ;Decode object as rsa private key
        If StringInStr($sRSA_PRIVATE_KEY, 'BEGIN PRIVATE KEY') Then ;-----BEGIN PRIVATE KEY-----
            Local $pbPrivateKeyInfo = __Crypto_CryptDecodeObjectEx($tDER, $PKCS_PRIVATE_KEY_INFO, _
                    BitOR($X509_ASN_ENCODING, $PKCS_7_ASN_ENCODING))
            If @error Then ExitLoop SetError(2, @error, 1)
            Local $dtag_crypt_private_key_info = 'dword;ptr;dword;ptr;dword cbData;ptr pbData;'
            Local $tInfo = DllStructCreate($dtag_crypt_private_key_info, DllStructGetPtr($pbPrivateKeyInfo))
            $tDER = DllStructCreate( _
                    'byte[' & DllStructGetData($tInfo, 'cbData') & ']', _
                    DllStructGetData($tInfo, 'pbData'))
        EndIf
        ;-----BEGIN RSA PRIVATE KEY----- default format

        Local $pbPrivateKeyBlob = __Crypto_CryptDecodeObjectEx($tDER, $PKCS_RSA_PRIVATE_KEY, _
                BitOR($X509_ASN_ENCODING, $PKCS_7_ASN_ENCODING))
        If @error Then ExitLoop SetError(3, @error, 1)

        ;Create a CSP
        Local $aData = DllCall($hAdvapi32, "bool", "CryptAcquireContext", _
                "handle*", Null, _;_Out_ HCRYPTPROV *phProv,
                "ptr", Null, _;    _In_opt_ LPCSTR szContainer,
                "str", 'Microsoft Enhanced RSA and AES Cryptographic Provider', _; _In_opt_ LPCSTR szProvider,
                "dword", $PROV_RSA_AES, _;_In_ DWORD dwProvType,
                "dword", $CRYPT_VERIFYCONTEXT);_In_ DWORD dwFlags
        If @error Or Not $aData[0] Then ExitLoop SetError(4, @error, 1)
        $hProv = $aData[1]

        ;Import key
        $aData = DllCall($hAdvapi32, "bool", "CryptImportKey", _
                "handle", $hProv, _;            _In_ HCRYPTPROV hProv,
                "struct*", $pbPrivateKeyBlob, _;_In_reads_bytes_(dwDataLen) CONST BYTE *pbData,
                "dword", DllStructGetSize($pbPrivateKeyBlob), _;  _In_ DWORD       dwDataLen,
                "handle", 0, _;                 _In_ HCRYPTKEY   hPubKey, , Ключ не зашифрован, поэтому 0
                "dword", 0, _;                  _In_ DWORD       dwFlags,
                "handle*", Null);               _Out_ HCRYPTKEY *phKey
        If @error Or Not $aData[0] Then ExitLoop SetError(5, @error, 1)
        ;not need
        If $aData[6] Then DllCall($hAdvapi32, "bool", "CryptDestroyKey", "handle", $aData[6])

        ;Create hash SHA256
        $aData = DllCall($hAdvapi32, "bool", "CryptCreateHash", _
                "handle", $hProv, _;     _In_  HCRYPTPROV  hProv,
                "uint", $CALG_SHA_256, _;_In_  ALG_ID      Algid,
                "handle", 0, _;          _In_  HCRYPTKEY   hKey,
                "dword", 0, _;           _In_  DWORD       dwFlags,
                "handle*", 0);           _Out_ HCRYPTHASH *phHash
        If @error Or Not $aData[0] Then ExitLoop SetError(6, @error, 1)
        $hHash = $aData[5]

        ;Hash the data
        $aData = DllCall($hAdvapi32, "bool", "CryptHashData", _
                "handle", $hHash, _;                        _In_ HCRYPTHASH  hHash,
                "struct*", $szDataToSign, _;                _In_reads_bytes_(dwDataLen) CONST BYTE *pbData,
                "dword", DllStructGetSize($szDataToSign), _;_In_ DWORD       dwDataLen,
                "dword", 0);                                _In_ DWORD       dwFlags
        If @error Or Not $aData[0] Then ExitLoop SetError(7, @error, 1)

        ;Sign the hash using our imported key
        Local $aSize = DllCall($hAdvapi32, "bool", "CryptSignHash", _
                "handle", $hHash, _;        _In_ HCRYPTHASH hHash,
                "dword", $AT_KEYEXCHANGE, _;_In_ DWORD      dwKeySpec,
                "ptr", Null, _;             _In_opt_ LPCSTR szDescription,
                "dword", 0, _;              _In_ DWORD      dwFlags,
                "struct*", Null, _; _Out_writes_bytes_to_opt_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
                "dword*", Null);            _Inout_ DWORD *pdwSigLen
        If @error Or Not $aSize[0] Then ExitLoop SetError(8, @error, 1)
        Local $pbSignature = DllStructCreate('byte[' & $aSize[6] & ']')
        $aData = DllCall($hAdvapi32, "bool", "CryptSignHash", _
                "handle", $hHash, _;        _In_ HCRYPTHASH hHash,
                "dword", $AT_KEYEXCHANGE, _;_In_     DWORD  dwKeySpec,
                "ptr", Null, _;             _In_opt_ LPCSTR szDescription,
                "dword", 0, _;              _In_     DWORD  dwFlags,
                "struct*", $pbSignature, _ ;_Out_writes_bytes_to_opt_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
                "dword*", DllStructGetSize($pbSignature));     _Inout_ DWORD  *pdwSigLen
        If @error Or Not $aData[0] Then ExitLoop SetError(9, @error, 1)

        ;OpenSSL is big-endian by a nature, Microsoft CryptoAPI — little-endian
        If $asOpenSSL Then
            ;convert little-endian to big-endian
            Local $bOut = DllStructGetData($pbSignature, 1)
            Local $bigEndian = Binary('')
            For $i = 1 To BinaryLen($bOut)
                $bigEndian = BinaryMid($bOut, $i, 1) & $bigEndian
            Next
            $pbSignature = DllStructCreate('byte[' & BinaryLen($bigEndian) & ']')
            DllStructSetData($pbSignature, 1, $bigEndian)
        EndIf

        ;to Base64
        Local $tOut = __Crypto_BinaryToString($pbSignature)
        If @error Then ExitLoop SetError(10, @error, 1)
        $sOut = DllStructGetData($tOut, 1)
    Until 1
    Local $iErr = @error, $iExt = @extended
    Local $aExt = DllCall("kernel32.dll", "dword", "GetLastError")
    If IsArray($aExt) Then $iExt = $aExt[0]

    If $hHash Then DllCall($hAdvapi32, "bool", "CryptDestroyHash", "handle", $hHash)
    If $hProv Then DllCall($hAdvapi32, "bool", "CryptReleaseContext", "handle", $hProv, "dword", 0)
    If $hAdvapi32 <> -1 Then DllClose($hAdvapi32)

    Return SetError($iErr, $iExt, $sOut)
EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __Crypto_CryptDecodeObjectEx
; Description ...:
; Syntax ........: __Crypto_CryptDecodeObjectEx($tData, $vType, $iEncoding)
; Parameters ....: $tData               - A dll struct value.
;                  $vType               - A variant value.
;                  $iEncoding           - An integer value.
; Return values .: struct
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx
; Example .......: No
; ===============================================================================================================================
Func __Crypto_CryptDecodeObjectEx($tData, $vType, $iEncoding)
    Local $iOut = Null, $tOut = Null, $aRet, $cbEncoded = DllStructGetSize($tData)
    For $i = 0 To 1
        $aRet = DllCall('Crypt32.dll', 'bool', 'CryptDecodeObjectEx', _
                'dword', $iEncoding, _;_In_ DWORD dwCertEncodingType,
                'ptr', $vType, _;      _In_ LPCSTR lpszStructType,
                'struct*', $tData, _;  _In_reads_bytes_(cbEncoded) const BYTE *pbEncoded,
                'dword', $cbEncoded, _;_In_ DWORD cbEncoded,
                'dword', 0, _;         _In_ DWORD dwFlags,
                'struct*', Null, _;    _In_opt_ PCRYPT_DECODE_PARA pDecodePara,
                'struct*', $tOut, _;   _Out_opt_ void *pvStructInfo,
                'dword*', $iOut) ;     _Inout_ DWORD *pcbStructInfo
        If @error Or Not $aRet[0] Then Return SetError(1, @error, False)
        If $i Then ExitLoop
        $iOut = $aRet[8]
        $tOut = DllStructCreate('byte[' & $iOut & ']')
    Next
    Return SetExtended($iOut, $tOut)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __Crypto_StringToBinary
; Description ...:
; Syntax ........: __Crypto_StringToBinary($tData[, $iFlags = 0x00000000])
; Parameters ....: $tData               - A dll struct value.
;                  $iFlags              - [optional] An integer value. Default is 0x00000000.
; Return values .: struct
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx
; Example .......: No
; ===============================================================================================================================
Func __Crypto_StringToBinary($tData, $iFlags = 0x00000000)
    Local $iOut = Null, $tOut = Null, $aRet, $iSize = DllStructGetSize($tData)
    For $i = 0 To 1
        $aRet = DllCall('Crypt32.dll', 'bool', 'CryptStringToBinary', _
                'struct*', $tData, _;      _In_reads_(cchString) LPCSTR pszString,
                'dword', DllStructGetSize($tData), _;             _In_ DWORD cchString,
                'dword', $iFlags, _;       _In_ DWORD dwFlags,
                'struct*', $tOut, _;       _Out_writes_bytes_to_opt_(*pcbBinary, *pcbBinary) BYTE *pbBinary,
                'dword*', $iOut, _;        _Inout_ DWORD  *pcbBinary,
                'dword*', Null, _;         _Out_opt_ DWORD *pdwSkip,
                'dword*', Null);           _Out_opt_ DWORD *pdwFlags
        If @error Or Not $aRet[0] Then Return SetError(1, @error, False)
        If $i Then ExitLoop
        $iOut = $aRet[5]
        $tOut = DllStructCreate('byte[' & $iOut & ']')
    Next
    Return SetExtended($iOut, $tOut)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __Crypto_BinaryToString
; Description ...:
; Syntax ........: __Crypto_BinaryToString($tData[, $iFlags = 0x40000001])
; Parameters ....: $tData               - A dll struct value.
;                  $iFlags              - [optional] An integer value. Default is 0x40000001.
; Return values .: struct
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx
; Example .......: No
; ===============================================================================================================================
Func __Crypto_BinaryToString($tData, $iFlags = 0x40000001)
    Local $iOut = Null, $tOut = Null, $aRet, $iSize = DllStructGetSize($tData)
    For $i = 0 To 1
        $aRet = DllCall('Crypt32.dll', 'bool', 'CryptBinaryToString', _
                'struct*', $tData, _;      _In_ const BYTE *pbBinary,
                'dword', $iSize, _;        _In_       DWORD cbBinary,
                'dword', $iFlags, _;       _In_       DWORD dwFlags,
                'struct*', $tOut, _;       _Out_opt_  LPTSTR  pszString,
                'dword*', $iOut);          _Inout_    DWORD *pcchString
        If @error Or Not $aRet[0] Then Return SetError(1, @error, False)
        If $i Then ExitLoop
        $iOut = $aRet[5]
        $tOut = DllStructCreate('char[' & $iOut & ']')
    Next
    Return SetExtended($iOut, $tOut)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __Crypto_Base64Encode
; Description ...: Base64 encode
; Syntax ........: __Crypto_Base64Encode($vIn)
; Parameters ....: $vIn                 - A variant value. String or binary
; Return values .: string
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __Crypto_Base64Encode($vIn)
    Local $bData = $vIn
    If IsString($vIn) Then
        $bData = StringToBinary($vIn, 4)
    EndIf
    Local $tData = DllStructCreate('byte[' & BinaryLen($bData) & ']')
    DllStructSetData($tData, 1, $bData)
    Local $tOut = __Crypto_BinaryToString($tData, 0x40000001)
    Return DllStructGetData($tOut, 1)
EndFunc
