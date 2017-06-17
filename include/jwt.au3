#include-once
#include '_Crypto.au3'
; #INDEX# ========================================================================
; Title .........: _JWT.au3
; AutoIt Version : 3.3.12.0
; Language ......: English
; Description ...: Functions for json web tokens
; Author ........: inververs
; Modified ......:
; URL ...........: https://jwt.io
; Remarks .......: For new versions see my github page https://github.com/inververs
; Requires .......: Require _crypto.au3 udf see https://github.com/inververs/Crypto
; Date ..........: 2017/06/01
; Version .......: 1.0.0
; ================================================================================

; #CURRENT# =====================================================================================================================
; _JWT_Sign_RS256
; ===============================================================================================================================

; #FUNCTION# ====================================================================================================================
; Name ..........: _JWT_Sign_RS256
; Description ...: Sign input with SHA256WITHRSA (RS256) (also known as RSASSA-PKCS1-V1_5-SIGN with the SHA-256 hash function) with the private key
; Syntax ........: _JWT_Sign_RS256($sHeader, $sPayload, $rsa_private_key)
; Parameters ....: $sHeader             - A string value.
;                  $sPayload            - A string value.
;                  $rsa_private_key     - An string value. PKCS#8 or PKCS#1 rsa private key
; Return values .: string on success or false on error
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........: https://jwt.io
; Example .......: _JWT_Sign_RS256('{"alg":"RS256","typ":"JWT"}', '{"sub":"1234567890","name":"John Doe","admin":true}', '-----BEGIN RSA PRIVATE KEY-----MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==-----END RSA PRIVATE KEY-----')
; ===============================================================================================================================
Func _JWT_Sign_RS256($sHeader, $sPayload, $rsa_private_key)
    Local $s64UrlH = __jwt_urlsafe(__Crypto_Base64Encode($sHeader))
    Local $s64UrlP = __jwt_urlsafe(__Crypto_Base64Encode($sPayload))
    Local $signature = _Crypto_Signing_SHA256RSA($s64UrlH & '.' & $s64UrlP, $rsa_private_key)
    If @error Then
        Return SetError(1, @error, False)
    EndIf
    Return $s64UrlH & '.' & $s64UrlP & '.' & __jwt_urlsafe($signature)
EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __jwt_urlsafe
; Description ...:
; Syntax ........: __jwt_urlsafe($sIn)
; Parameters ....: $sIn                 - A string value.
; Return values .: string
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: inververs
; ===============================================================================================================================
Func __jwt_urlsafe($sIn)
    Return StringReplace(StringReplace(StringReplace($sIn, '+', '-'), '/', '_'), '=', '')
EndFunc
