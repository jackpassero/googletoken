#include-once
#include <FileConstants.au3>
#include 'include\JSMN.au3'
#include 'include\jwt.au3'

; #INDEX# ========================================================================
; Title .........: googletokens udf
; AutoIt Version : 3.3.12.0
; Language ......: English
; Description ...: This UDF provide functions for using OAuth 2.0 to access google APIs
; Author ........: inververs
; Modified ......:
; URL ...........: https://developers.google.com/identity/protocols/OAuth2
; Remarks .......: For new versions see my github page https://github.com/inververs
; Requires ......: Require jwt.au3 udf see https://github.com/inververs/jwt
; Requires ......: Require Ward jsmn.au3 udf see https://github.com/inververs/jsmn
; Requires ......: Require _Crypto.au3 udf see https://github.com/inververs/crypto
; Date ..........: 2017/06/01
; Version .......: 1.0.0
; ================================================================================

; #CURRENT# =====================================================================================================================
; _googleapis_getToken
; _googleapis_setupServiceOAuth2FromFile
; _googleapis_setupServiceOAuth2FromData
; _googleapis_setupDesktopOAuth2FromFile
; _googleapis_setupDesktopOAuth2FromData
; _googleapis_setScope
; _googleapis_addScope
; _googleapis_getScope
; ===============================================================================================================================

#OnAutoItStartRegister '__googleapis_bootstrap'

; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_getToken
; Description ...: Function retrieve access token
; Syntax ........: _googleapis_getToken([$force = False[, $refresh = True]])
; Parameters ....: $force Always get fresh token  - [optional] A boolean value. Default is False.
;                  $refresh    Use refresh token  - [optional] A boolean value. Default is True.
; Return values .: Access token
; Author ........: inververs
; Modified ......:
; Remarks .......: you should not cache access token. Instead always call this function
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _googleapis_getToken($force = False, $refresh = True)
    Local $cfg = __googleapis_config
    Local $access_token, $refresh_token
    Do
        If $force Then ExitLoop SetError(1, 0, 1)

        Local $object = __googleapis_storage('token')
        If Not IsObj($object) Then
            If Not $cfg('tokens.persist') Then ExitLoop SetError(2, 0, 1)

            Local $storage = $cfg('tokens.storage')
            If Not FileExists($storage) Then ExitLoop SetError(3, 0, 1)

            Local $hFile = FileOpen($storage, BitOR($FO_READ, $FO_UTF8_NOBOM))
            Local $sData = FileRead($storage)
            FileClose($hFile)

            $object = __googleapis_string_decode($sData)
            If @error Or Not IsObj($object) Then ExitLoop SetError(4, 0, 1)

            __googleapis_storage('token', $object)
        EndIf

        Local $scope = __googleapis_object($object, 'scope')
        If $scope And $scope <> _googleapis_getScope() Then ExitLoop SetError(5, 0, 1)

        $refresh_token = __googleapis_object($object, 'refresh_token')
        $access_token = __googleapis_object($object, 'access_token')
        If Not $access_token Then ExitLoop SetError(6, 0, 1)

        Local $exp = __googleapis_object($object, 'exp')
        If Not $access_token Then ExitLoop SetError(7, 0, 1)

        Local $iat = __googleapis_datetime_timestamp(__googleapis_object($object, 'timestamp_method'))
        If $iat >= $exp Then ExitLoop SetError(8, 0, 1)

        Return SetExtended($exp - $iat, $access_token)
    Until 1
    If $refresh And $refresh_token Then
        $access_token = __googleapis_refreshToken($refresh_token)
    EndIf
    If Not $access_token Then
        $access_token = Call($cfg('oauth2.tokenfunc'))
    EndIf
    Return SetError(@error, @extended, $access_token)
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_setupServiceOAuth2FromFile
; Description ...: Setup this udf as service account using file.
; Syntax ........: _googleapis_setupServiceOAuth2FromFile($sFile)
; Parameters ....: $sFile  File with client_email and private_key - A string value.
; Return values .: boolean true of false
; Author ........: inververs
; Modified ......:
; Remarks .......: Create a service account and download the file containing the private key. Use this file to quickly configure this udf.
; Remarks .......: This method is not recommended, because you are responsible for storing it securely.
; Related .......: _googleapis_setupServiceOAuth2FromData
; Link ..........: https://console.developers.google.com/projectselector/iam-admin/serviceaccounts
; Link ..........: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
; Example .......: No
; ===============================================================================================================================
Func _googleapis_setupServiceOAuth2FromFile($sFile)
    If Not FileExists($sFile) Then
        Return SetError(1, 0, False)
    EndIf

    Local $hFile = FileOpen($sFile, BitOR($FO_READ, $FO_UTF8_NOBOM))
    If @error Or $hFile = -1 Then
        Return SetError(2, 0, False)
    EndIf
    Local $sData = FileRead($sFile)
    FileClose($hFile)

    Local $object = __googleapis_string_decode($sData)
    If @error Or Not IsObj($object) Then
        Return SetError(3, 0, False)
    EndIf

    Local $client_email = __googleapis_object($object, 'client_email')
    Local $private_key = __googleapis_object($object, 'private_key')

    If Not ($client_email And $private_key) Then
        Return SetError(4, 0, False)
    EndIf

    _googleapis_setupServiceOAuth2FromData($client_email, $private_key)

    Return True
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_setupServiceOAuth2FromData
; Description ...: Setup this udf as service account using service account id and private key
; Syntax ........: _googleapis_setupServiceOAuth2FromData($client_email, $private_key)
; Parameters ....: $client_email  service account id          - A string value.
;                  $private_key   service account private key - A string value.
; Return values .: boolean true of false
; Author ........: inververs
; Modified ......:
; Remarks .......: Create a service account and load the file containing the private key.
; Remarks .......: Extract and json decode client_email and private_key values and call this function to configure udf
; Related .......: _googleapis_setupServiceOAuth2FromFile
; Link ..........: https://console.developers.google.com/projectselector/iam-admin/serviceaccounts
; Link ..........: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
; Example .......: No
; ===============================================================================================================================
Func _googleapis_setupServiceOAuth2FromData($client_email, $private_key)
    __googleapis_config('crypto.rsakey.private', $private_key)
    __googleapis_config('oauth2.client_email', $client_email)
    If Not _googleapis_getScope() Then
        _googleapis_setScope(__googleapis_config('oauth2.default.scope'))
    EndIf
    __googleapis_config('oauth2.type', 'service')
    __googleapis_config('oauth2.tokenfunc', '__googleapis_serviceOAuth2')
    Return True
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_setupDesktopOAuth2FromFile
; Description ...: Setup this udf as desktop application using file.
; Syntax ........: _googleapis_setupDesktopOAuth2FromFile($sFile)
; Parameters ....: $sFile  File with client_id and  client_secret. - A string value.
; Return values .: boolean true of false
; Author ........: inververs
; Modified ......:
; Remarks .......: Create your application. Than create credentials as OAuth client id. Select Other application type. Set Name
; Remarks .......: Download json file containing the client_id and client_secret. Use this file to quickly configure this udf.
; Remarks .......: This method is not recommended, because you are responsible for storing it securely.
; Related .......: _googleapis_setupDesktopOAuth2FromData
; Link ..........: https://console.developers.google.com/apis/credentials
; Example .......: No
; ===============================================================================================================================
Func _googleapis_setupDesktopOAuth2FromFile($sFile)
    If Not FileExists($sFile) Then
        Return SetError(1, 0, False)
    EndIf

    Local $hFile = FileOpen($sFile, BitOR($FO_READ, $FO_UTF8_NOBOM))
    If @error Or $hFile = -1 Then
        Return SetError(2, 0, False)
    EndIf
    Local $sData = FileRead($sFile)
    FileClose($hFile)

    Local $object = __googleapis_string_decode($sData)
    If @error Or Not IsObj($object) Then
        Return SetError(3, 0, False)
    EndIf

    Local $client_id = __googleapis_object($object, 'installed.client_id')
    Local $client_secret = __googleapis_object($object, 'installed.client_secret')

    If Not ($client_id And $client_secret) Then
        Return SetError(4, 0, False)
    EndIf

    _googleapis_setupDesktopOAuth2FromData($client_id, $client_secret)

    Return True
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_setupDesktopOAuth2FromData
; Description ...: Setup this udf as desktop application using client_id and client_secret
; Syntax ........: _googleapis_setupDesktopOAuth2FromData($client_id, $client_secret)
; Parameters ....: $client_id      Client ID     - A string value.
;                  $client_secret  Client secret - A string value.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......: Create your application. Than create credentials as OAuth client id. Select Other application type. Set Name
; Remarks .......: Extract and json decode client_id and client_secret values and call this function to configure udf
; Related .......: _googleapis_setupDesktopOAuth2FromFile
; Link ..........: https://console.developers.google.com/apis/credentials
; Example .......: No
; ===============================================================================================================================
Func _googleapis_setupDesktopOAuth2FromData($client_id, $client_secret)
    __googleapis_config('oauth2.client_id', $client_id)
    __googleapis_config('oauth2.client_secret', $client_secret)
    If Not _googleapis_getScope() Then
        _googleapis_setScope(__googleapis_config('oauth2.default.scope'))
    EndIf
    __googleapis_config('oauth2.type', 'desktop')
    __googleapis_config('oauth2.tokenfunc', '__googleapis_desktopOAuth2')
    Return True
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_setScope
; Description ...: Set and override the scopes
; Syntax ........: _googleapis_setScope($scope)
; Parameters ....: $scope scope              - A string value.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......: the OAuth 2.0 scopes that you might need to request to access Google APIs, depending on the level of access you need
; Remarks .......: use space delimeter to set many scopes at once
; Related .......: _googleapis_addScope _googleapis_getScope
; Link ..........: https://developers.google.com/identity/protocols/googlescopes
; Example .......: _googleapis_addScope('https://www.googleapis.com/auth/youtube')
; ===============================================================================================================================
Func _googleapis_setScope($scope)
    __googleapis_config('oauth2.scope', $scope)
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_addScope
; Description ...: Add a scope to existing scopes
; Syntax ........: _googleapis_addScope($scope)
; Parameters ....: $scope   scope            - A string value.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: _googleapis_setScope _googleapis_getScope
; Link ..........: https://developers.google.com/identity/protocols/googlescopes
; Example .......: No
; ===============================================================================================================================
Func _googleapis_addScope($scope)
    If _googleapis_getScope() Then
        _googleapis_setScope($scope & ' ' & _googleapis_getScope())
    Else
        _googleapis_setScope($scope)
    EndIf
EndFunc
; #FUNCTION# ====================================================================================================================
; Name ..........: _googleapis_getScope
; Description ...: Get current scopes
; Syntax ........: _googleapis_getScope()
; Parameters ....:
; Return values .: scopes as string
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: _googleapis_setScope _googleapis_addScope
; Link ..........: https://developers.google.com/identity/protocols/googlescopes
; Example .......: No
; ===============================================================================================================================
Func _googleapis_getScope()
    Return __googleapis_config('oauth2.scope')
EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_bootstrap
; Description ...: Configure this udf. This function calls when application start.
; Syntax ........: __googleapis_bootstrap()
; Parameters ....:
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......: see comments
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_bootstrap()
    Local $cfg = __googleapis_config

    ;debug mode enabled. False Or True. Default false
    $cfg('debug.enabled', False)

    ;default timeout for access token
    $cfg('oauth2.exp', 3600)

    ;Additional claims. The email address of the user for which the application is requesting delegated access.
    ;used when configure as service account. Default empty. See https://developers.google.com/identity/protocols/OAuth2ServiceAccount
    $cfg('oauth2.sub', '')

    ;Default scope. Default email profile. See _googleapis_setScope or _googleapis_addScope to specify your own scopes
    $cfg('oauth2.default.scope', 'email profile')

    ;Used when configure as desktop applicaton. Timeout in ms. When Google prompts user for consent we wait this time.
    ;Set to 0 If you want to wait indefinitely. Default 60000.
    $cfg('oauth2.timeout', 60000)

    ;Used when configure as desktop applicaton. If this function return true we stop waiting. See oauth2.timeout.
    ;Can be any existing functions with one parameters (time in ms). Default empty.
    $cfg('oauth2.stop_callback_function', '')

    ;This configure request object. See WinHttp.WinHttpRequest.5.1 documentation
    $cfg('request.timeout.resolve', 2000)
    $cfg('request.timeout.connect', 30000)
    $cfg('request.timeout.send', 30000)
    $cfg('request.timeout.receive', 30000)
    $cfg('request.headers.Accept', "application/json")
    $cfg('request.headers.Accept-Encoding', "deflate")
    $cfg('request.headers.Accept-Language', "en,ru;q=0.8,de;q=0.6")
    $cfg('request.headers.Content-Type', "application/json; charset=UTF-8")
    $cfg('request.options.6', False) ;auto redirect

    ;Save tokens information into file. Can be true or false. Default true.
    $cfg('tokens.persist', True)
    ;File contains tokens information. Default tokens.storage.txt
    $cfg('tokens.storage', 'tokens.storage.txt')

    ;Method to obtain timestamp for token validation and jwt sign.
    ;Can be server or system or ntp or auto. Default auto
    ;ntp - used public ntp servers.
    ;server - used head request to a server and extract Date header.
    ;system - used local machine time.
    ;auto - used order: ntp, then server, then system.
    $cfg('datetime.timestamp.method', 'auto')

    ;Array of ntp servers. This servers used when datetime.timestamp.method set to ntp
    $cfg('datetime.ntpserver.0', '0.pool.ntp.org')
    $cfg('datetime.ntpserver.1', '1.pool.ntp.org')
    $cfg('datetime.ntpserver.2', '2.pool.ntp.org')
    $cfg('datetime.ntpserver.3', '3.pool.ntp.org')
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_desktopOAuth2
; Description ...: Obtain access token. Google prompts user for consent
; Syntax ........: __googleapis_desktopOAuth2([$client_id = Default[, $client_secret = Default[, $stop_callback_function = Default]]])
; Parameters ....: $client_id           -   [optional] A string value. Default get from 'oauth2.client_id'
;                  $client_secret       -   [optional] A string value. Default get from 'oauth2.client_secret'
;                  $stop_callback_function- [optional] A string value. Default is no callback
; Return values .: access token
; Author ........: inververs
; Modified ......:
; Remarks .......: Used default browser.
; Related .......: __googleapis_serviceOAuth2
; Link ..........: https://developers.google.com/identity/protocols/OAuth2InstalledApp
; Example .......: No
; ===============================================================================================================================
Func __googleapis_desktopOAuth2($client_id = Default, $client_secret = Default, $stop_callback_function = Default)
    Local $cfg = __googleapis_config
    If $client_id = Default Then
        $client_id = $cfg('oauth2.client_id')
    EndIf
    If $client_secret = Default Then
        $client_secret = $cfg('oauth2.client_secret')
    EndIf
    If Not ($client_id And $client_secret) Then
        Return SetError(__googleapis_InvalidArgumentException(), 1, False)
    EndIf

    If $stop_callback_function = Default And $cfg('oauth2.stop_callback_function') Then
        $stop_callback_function = $cfg('oauth2.stop_callback_function')
    EndIf

    ;get free port
    Do
        If Not TCPStartup() Or @error Then
            Return SetError(__googleapis_RuntimeException(), 1, False)
        EndIf
        Local $iMainSocket, $iPortStart = 9004, $iPortEnd = 9014
        For $iPort = $iPortStart To $iPortEnd
            $iMainSocket = TCPListen('127.0.0.1', $iPort, 100)
            If Not @error And $iMainSocket > 0 Then ExitLoop
        Next
        If $iMainSocket = -1 Or Not $iMainSocket Then
            TCPShutdown()
            Return SetError(__googleapis_RuntimeException(), 2, False)
        EndIf
        TCPCloseSocket($iMainSocket)
        TCPShutdown()
    Until 1

    ;Step 1: Generate a code verifier and challenge
    ;skipped

    ;Step 2: Send a request to Google's OAuth 2.0 server
    Local $sUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' & _
            '&response_type=code' & _
            '&scope=' & _googleapis_getScope() & _
            '&client_id=' & $client_id & _
            '&redirect_uri=' & 'http://127.0.0.1:' & $iPort
    Local $iPid = ShellExecute($sUrl)
    If @error Or Not $iPid Then Return SetError(__googleapis_RuntimeException(), 3, False)

    ;Step 3: Google prompts user for consent. In this step, the user decides whether to grant your application the requested access
    Local $vRet = False
    Do
        If Not TCPStartup() Or @error Then
            Return SetError(__googleapis_RuntimeException(), 1, False)
        EndIf

        Local $iMainSocket = TCPListen('127.0.0.1', $iPort, 100)
        If @error Or Not $iMainSocket Or $iMainSocket = -1 Then
            TCPShutdown()
            Return SetError(__googleapis_RuntimeException(), 1, False)
        EndIf

        Local $iSocket, $iTimer = TimerInit(), $iTimeOut = $cfg('oauth2.timeout')
        Do
            Sleep(500)
            $iSocket = TCPAccept($iMainSocket)
            If @error Or Not $iSocket Then ExitLoop SetError(1, 0, 1)
            If $stop_callback_function And Call($stop_callback_function, TimerDiff($iTimer)) Then
                ExitLoop SetError(1, @error, 1)
            EndIf
        Until ($iTimeOut And TimerDiff($iTimer) > $iTimeOut) Or $iSocket > 0
        If $iSocket > 0 Then
            $vRet = TCPRecv($iSocket, 2048)
            TCPSend($iSocket, 'HTTP/1.1 200 Ok' & @CRLF _
                     & 'Connection: close' & @CRLF _
                     & 'Content-Type: text/html; charset=utf-8' & @CRLF & @CRLF _
                     & '<html><body>You may close this window</body></html>')
        EndIf
        If $iSocket > 0 Then TCPCloseSocket($iSocket)
        If $iMainSocket > 0 Then TCPCloseSocket($iMainSocket)
        TCPShutdown()
    Until 1
    If Not $vRet Then Return SetError(__googleapis_UnexpectedValueException(), 1, False)

    If $cfg('debug.enabled') Then ConsoleWrite($vRet & @CRLF)
    ;Step 4: Handle the OAuth 2.0 server response
    ;check error
    If StringRegExp($vRet, '(?i)/\?error=(\S+)') Then
        Return SetError(__googleapis_DomainException(), 403, False)
    EndIf
    ;or code
    Local $aCode = StringRegExp($vRet, '(?i)/\?code=(\S+)', 1)
    If @error Or Not IsArray($aCode) Or UBound($aCode) < 1 Then
        Return SetError(__googleapis_UnexpectedValueException(), 2, False)
    EndIf

    ;Step 5: Exchange authorization code for refresh and access tokens
    $sUrl = 'https://www.googleapis.com/oauth2/v4/token?' & _
            'grant_type=authorization_code' & _
            '&client_id=' & $client_id & _
            '&client_secret=' & $client_secret & _
            '&redirect_uri=' & 'http://127.0.0.1:' & $iPort & _
            '&code=' & $aCode[0]
    Local $sResponseText = __googleapis_request('POST', $sUrl, '', 'Content-Type=application/x-www-form-urlencoded')
    If @error Or Not $sResponseText Then
        Return SetError(__googleapis_RuntimeException(), 4, False)
    EndIf
    Local $sResponseCode = @extended

    If $cfg('debug.enabled') Then ConsoleWrite($sResponseText & @CRLF)

    Local $object = __googleapis_string_decode($sResponseText)
    Local $access_token = __googleapis_object($object, 'access_token')
    If Not $access_token Then Return SetError(__googleapis_DomainException(), $sResponseCode, False)

    Local $refresh_token = __googleapis_object($object, 'refresh_token')
    Local $token_type = __googleapis_object($object, 'token_type')
    Local $expires_in = __googleapis_object($object, 'expires_in')
    Local $id_token = __googleapis_object($object, 'id_token')

    Local $iat = __googleapis_datetime_timestamp($cfg('datetime.timestamp.method'))
    __googleapis_storage('token.access_token', $access_token)
    __googleapis_storage('token.refresh_token', $refresh_token)
    __googleapis_storage('token.type', $token_type)
    __googleapis_storage('token.exp', $iat + $expires_in)
    __googleapis_storage('token.timestamp_method', $cfg('datetime.timestamp.method'))
    __googleapis_storage('token.scope', _googleapis_getScope())
    If $id_token Then
        __googleapis_storage('token.id_token', $id_token)
    EndIf

    If $cfg('tokens.persist') Then
        Local $hFile = FileOpen($cfg('tokens.storage'), BitOR($FO_OVERWRITE, $FO_CREATEPATH, $FO_UTF8_NOBOM))
        If @error Or $hFile = -1 Then Return SetError(__googleapis_RuntimeException(), 6, False)
        FileWrite($hFile, __googleapis_object_encode(__googleapis_storage('token')))
        FileClose($hFile)
    EndIf

    Return SetExtended($expires_in, $access_token)
;~ {
;~  "access_token": "ya29.GltoBAtbD1H9Xvcmgd8_8Zlo10Fvan09AYkeuRKIDQe1NJd72C2XN7GhrWCI9sphvbfLzuKGUA75PPF3l-AORY3VJAHXMxiRxOvlPRw7g1HiFl_YRFr-j1BWev-u",
;~  "token_type": "Bearer",
;~  "expires_in": 3600,
;~  "refresh_token": "1/2TFLOZ5LtrGeFZDwA2dWcAySmw38TBK3WxtGtjGMJQc",
;~  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE5MDI3MjhjZjllNTQ0M2YwOGQzYzcwZmUwOTEyMjJjMWE2NjVhMWIifQ.eyJhenAiOiI4Nzg2Nzg1MjA5NjgtaGVocHZsaWNrMGZrazdmMjRmOGtiaHFubDV2ZXA2c28uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4Nzg2Nzg1MjA5NjgtaGVocHZsaWNrMGZrazdmMjRmOGtiaHFubDV2ZXA2c28uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDk0MDgwNjc0NTUyNzM5OTMyMDQiLCJlbWFpbCI6InZ5bmV0Lm1haWxAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJlak1RWUdJYmlxWmI2MzRSZUZzTU9BIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNDk3MzU2ODE2LCJleHAiOjE0OTczNjA0MTYsIm5hbWUiOiLQktC70LDQtNC40LzQuNGAIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS8tQWVKMWExVXFvZEkvQUFBQUFBQUFBQUkvQUFBQUFBQUFBQUEvQUF5WUJGNUtDZXdCQUFKeTUwdDliYkxSQ0FmeEMyUHpYdy9zOTYtYy9waG90by5qcGciLCJnaXZlbl9uYW1lIjoi0JLQu9Cw0LTQuNC80LjRgCIsImxvY2FsZSI6InJ1In0.fQVIGWWdESMjNoYDeZ1OCqXJtz4Oi0AhBiKqQYQBNkhP5ISoqwrjwON6j6QlXSQNA9db5cmFZN4WBWPLTaEB0ft1fYyeLZJB7a5xJq49hhJl63t8rUdAJtuRuz_jVZ5Y7aWTAOvVBKtFJCbFnzl_ZJoIWRoBV_P3_X0O12kZjvngYw3lCA1LBQ0tSpvnfMC_CSr3qSB0i-EfAB4rC41h5ageBK-an2ELV5OQJB2irWMqaX_v9NTXkGMeBmDzm7tRCo3w4OzoIeN2EUzvEvxzJOTHj59puFekj8g90oCjqcyUh5uW9JovV7_YBCDG_81CjpLiX31KJdhFuipmJtoeTw"
;~ }
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_serviceOAuth2
; Description ...: Obtain access token.
; Syntax ........: __googleapis_serviceOAuth2([$client_email = Default[, $rsa_private_key = Default]])
; Parameters ....: $client_email        - [optional] An unknown value. Default is Default.
;                  $rsa_private_key     - [optional] An unknown value. Default is Default.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: __googleapis_desktopOAuth2
; Link ..........: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
; Example .......: No
; ===============================================================================================================================
Func __googleapis_serviceOAuth2($client_email = Default, $rsa_private_key = Default)
    Local $cfg = __googleapis_config

    If $client_email = Default Then
        $client_email = $cfg('oauth2.client_email')
    EndIf
    If $rsa_private_key = Default Then
        $rsa_private_key = $cfg('crypto.rsakey.private')
    EndIf
    If Not ($client_email And $rsa_private_key) Then
        Return SetError(__googleapis_InvalidArgumentException(), 1, False)
    EndIf

    Local $iat = __googleapis_datetime_timestamp($cfg('datetime.timestamp.method'))
    If Not $iat Then Return SetError(__googleapis_RuntimeException(), 3, False)

    Local $aud = 'https://www.googleapis.com/oauth2/v4/token'
    Local $object = __googleapis_object()
    __googleapis_object($object, 'iss', $client_email)
    __googleapis_object($object, 'scope', _googleapis_getScope())
    __googleapis_object($object, 'aud', $aud)
    __googleapis_object($object, 'exp', $iat + $cfg('oauth2.exp'))
    __googleapis_object($object, 'iat', $iat)
    If $cfg('oauth2.sub') Then __googleapis_object($object, 'sub', $cfg('oauth2.sub'))
    Local $sClaimSet = __googleapis_object_encode($object)

;~     ;create Json Web Signature (JWS)
;~     ;base64url header
;~     Local $s64H = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' ;'{"alg":"RS256","typ":"JWT"}'
;~     ;base64url payload
;~     Local $s64P = StringReplace(StringReplace(StringReplace(__Crypto_Base64Encode($sClaimSet), '+', '-'), '/', '_'), '=', '')
;~     ;signing header.payload
;~     Local $signature = _Crypto_Signing_SHA256RSA($s64H & '.' & $s64P, $rsa_private_key)
;~     If @error Then Return SetError(__googleapis_RuntimeException(), 4, False)
;~     ;base64url signature
;~     Local $s64S = StringReplace(StringReplace(StringReplace($signature, '+', '-'), '/', '_'), '=', '')
;~     ;create jwt base64url
;~     Local $sJWT = $s64H & '.' & $s64P & '.' & $s64S
;~  ConsoleWrite($sJWT & @CRLF)
    Local $sJWT = _JWT_Sign_RS256('{"alg":"RS256","typ":"JWT"}', $sClaimSet, $rsa_private_key)
    ;prepare request data
    Local $sData = 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' & $sJWT
    Local $sHead = 'Content-Type=application/x-www-form-urlencoded'
    Local $sResponseText = __googleapis_request('POST', $aud, $sData, $sHead)
    If @error Or Not $sResponseText Then
        Return SetError(__googleapis_RuntimeException(), 5, False)
    EndIf
    Local $sResponseCode = @extended

    If $cfg('debug.enabled') Then ConsoleWrite($sResponseText & @CRLF)

    Local $object = __googleapis_string_decode($sResponseText)
    Local $access_token = __googleapis_object($object, 'access_token')
    If Not $access_token Then Return SetError(__googleapis_DomainException(), $sResponseCode, False)
    Local $token_type = __googleapis_object($object, 'token_type')
    Local $expires_in = __googleapis_object($object, 'expires_in')

    __googleapis_storage('token.access_token', $access_token)
    __googleapis_storage('token.type', $token_type)
    __googleapis_storage('token.exp', $iat + $expires_in)
    __googleapis_storage('token.timestamp_method', $cfg('datetime.timestamp.method'))
    __googleapis_storage('token.scope', _googleapis_getScope())

    If $cfg('tokens.persist') Then
        Local $hFile = FileOpen($cfg('tokens.storage'), BitOR($FO_OVERWRITE, $FO_CREATEPATH, $FO_UTF8_NOBOM))
        If @error Or $hFile = -1 Then Return SetError(__googleapis_RuntimeException(), 6, False)
        FileWrite($hFile, __googleapis_object_encode(__googleapis_storage('token')))
        FileClose($hFile)
    EndIf
    Return SetExtended($expires_in, $access_token)
;~ {
;~  "access_token": "ya29.ElpjBCnVnGyx2Hi9GSQ8eP1dhfvV7-Umj4uwQOgnjNwR_xxK1_zRwuSbuoaYo6W5lFXTDSYBNbOfyte-pi7TWu6C94YHw-z06Ld8hhVSDjxjPHLGR51QAwmNiMY",
;~  "token_type": "Bearer",
;~  "expires_in": 3600
;~ }
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_refreshToken
; Description ...: refresh access token
; Syntax ........: __googleapis_refreshToken($refresh_token)
; Parameters ....: $refresh_token    refresh token   - A string value.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: _googleapis_getToken
; Link ..........: https://developers.google.com/identity/protocols/OAuth2InstalledApp#offline
; Example .......: No
; ===============================================================================================================================
Func __googleapis_refreshToken($refresh_token)
    Local $cfg = __googleapis_config
    Local $sUrl = 'https://www.googleapis.com/oauth2/v4/token?' & _
            'refresh_token=' & $refresh_token & _
            '&client_id=' & $cfg('oauth2.client_id') & _
            '&client_secret=' & $cfg('oauth2.client_secret') & _
            '&grant_type=refresh_token'

    Local $sResponseText = __googleapis_request('POST', $sUrl, '', 'Content-Type=application/x-www-form-urlencoded')
    If @error Or Not $sResponseText Then
        Return SetError(__googleapis_RuntimeException(), 4, False)
    EndIf
    Local $sResponseCode = @extended

    If $cfg('debug.enabled') Then ConsoleWrite($sResponseText & @CRLF)

    Local $object = __googleapis_string_decode($sResponseText)
    Local $access_token = __googleapis_object($object, 'access_token')
    If Not $access_token Then
        Return SetError(__googleapis_DomainException(), $sResponseCode, False)
    EndIf
    Local $token_type = __googleapis_object($object, 'token_type')
    Local $expires_in = __googleapis_object($object, 'expires_in')
    Local $iat = __googleapis_datetime_timestamp($cfg('datetime.timestamp.method'))
    Local $id_token = __googleapis_object($object, 'id_token')
    __googleapis_storage('token.refresh_token', $refresh_token)
    __googleapis_storage('token.access_token', $access_token)
    __googleapis_storage('token.type', $token_type)
    __googleapis_storage('token.exp', $iat + $expires_in)
    __googleapis_storage('token.timestamp_method', $cfg('datetime.timestamp.method'))
    __googleapis_storage('token.scope', _googleapis_getScope())
    If $id_token Then
        __googleapis_storage('token.id_token', $id_token)
    EndIf

    If $cfg('tokens.persist') Then
        Local $hFile = FileOpen($cfg('tokens.storage'), BitOR($FO_OVERWRITE, $FO_CREATEPATH, $FO_UTF8_NOBOM))
        If @error Or $hFile = -1 Then Return SetError(__googleapis_RuntimeException(), 6, False)
        FileWrite($hFile, __googleapis_object_encode(__googleapis_storage('token')))
        FileClose($hFile)
    EndIf

    Return SetExtended($expires_in, $access_token)
;~ {
;~   "access_token":"1/fFAGRNJru1FTz70BzhT3Zg",
;~   "expires_in":3920,
;~   "token_type":"Bearer"
;~ }
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_config
; Description ...: wrapper for __googleapis_object.
; Syntax ........: __googleapis_config([$path = Default[, $value = Default[, $delimiter = '.']]])
; Parameters ....: $path                - [optional] A string value. Default is Default.
;                  $value               - [optional] A variant value. Default is Default.
;                  $delimiter           - [optional] A string value. Default is '.'.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_config($path = Default, $value = Default, $delimiter = '.')
    Return __googleapis_storage('config' & $delimiter & $path, $value, $delimiter)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_storage
; Description ...: wrapper for __googleapis_object.
; Syntax ........: __googleapis_storage([$path = Default[, $value = Default[, $delimiter = '.']]])
; Parameters ....: $path                - [optional] A string value. Default is Default.
;                  $value               - [optional] A variant value. Default is Default.
;                  $delimiter           - [optional] A string value. Default is '.'.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_storage($path = Default, $value = Default, $delimiter = '.')
    Local Static $object = ObjCreate('scripting.dictionary')
    Return __googleapis_object($object, $path, $value, $delimiter)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_object
; Description ...: Used path to set or get value in nested scripting.dictionary object.
; Syntax ........: __googleapis_object([$object = ObjCreate('scripting.dictionary'[, $path = Default[, $value = Default[,
;                  $delimiter = '.']]]])
; Parameters ....: $object              - [optional] An object value. Default is ObjCreate('scripting.dictionary').
;                  $path                - [optional] A string value. Default is Default.
;                  $value    Set value  - [optional] A variant value. Default is Default.
;                  $delimiter           - [optional] A string value. Default is '.'.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: __googleapis_object($object, 'any.long.path.in.nested.scripting.dictionary')
; ===============================================================================================================================
Func __googleapis_object($object = ObjCreate('scripting.dictionary'), $path = Default, $value = Default, $delimiter = '.')
    If Not IsObj($object) Then Return SetError(1, 0, '')
    If $path = Default Then Return $object
    Local $get = $value = Default, $set = Not $get
    Local $item, $current = $object
    Local $split = StringSplit($path, $delimiter, 1)
    For $index = 1 To $split[0]
        $item = $split[$index]
        If StringIsDigit($item) Then $item = Number($item)
        If $index = $split[0] And $set Then
            If IsObj($value) Then
                $current.remove($item)
                $current.add($item, $value)
            Else
                $current.item($item) = $value
            EndIf
            Return SetError(@error, 0, $object)
        EndIf

        If Not IsObj($current) Then Return SetError(3, '', '')

        If Not $current.exists($item) Then
            If $get Then Return SetError(4, '', '')
            $current.add($item, ObjCreate('scripting.dictionary'))
        EndIf
        $current = $current.item($item)
    Next
    Return $current
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_object_encode
; Description ...: object to json encode
; Syntax ........: __googleapis_object_encode($object)
; Parameters ....: $object              - An object value.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......: used JSMN udf
; Related .......: __googleapis_string_decode
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_object_encode($object)
    If __googleapis_config('debug.enabled') Then
        Return Jsmn_Encode($object, BitOR($JSMN_UNESCAPED_SLASHES, $JSMN_UNESCAPED_UNICODE, $JSMN_PRETTY_PRINT))
    Else
        Return Jsmn_Encode($object, BitOR($JSMN_UNESCAPED_SLASHES, $JSMN_UNESCAPED_UNICODE))
    EndIf
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_string_decode
; Description ...: string to json decode
; Syntax ........: __googleapis_string_decode($string)
; Parameters ....: $string json string - A string value.
; Return values .: None
; Author ........: inververs
; Modified ......:
; Remarks .......: used JSMN udf
; Related .......: __googleapis_object_encode
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_string_decode($string)
    Return Jsmn_Decode($string)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_datetime_timestamp
; Description ...: Get timestamp for token validation and jwt sign
; Syntax ........: __googleapis_datetime_timestamp([$method = 'auto'])
; Parameters ....: $method              - [optional] A string value. Default is 'auto'.
; Return values .: unix timestamp
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_datetime_timestamp($method = 'auto')
    Local $iat, $cfg = __googleapis_config
    Switch $method
        Case 'server'
            $iat = __googleapis_datetime_fromServer('https://www.googleapis.com/oauth2/v4/token')
        Case 'system'
            $iat = __googleapis_datetime_fromSystem()
        Case 'ntp'
            Local $ntp = $cfg('datatime.ntpserver')
            If IsObj($ntp) Then
                For $n In $ntp
                    $iat = __googleapis_datetime_fromNtp($ntp.item($n))
                    If $iat Then ExitLoop
                Next
            Else
                $iat = __googleapis_datetime_fromNtp() ;use default
            EndIf
        Case 'auto' ;default
            ContinueCase
        Case Else
            Local $ntp = $cfg('datatime.ntpserver')
            If IsObj($ntp) Then
                For $n In $ntp
                    $iat = __googleapis_datetime_fromNtp($ntp.item($n))
                    If $iat Then ExitLoop
                Next
            Else
                $iat = __googleapis_datetime_fromNtp() ;use default
            EndIf
            If Not $iat Then
                $iat = __googleapis_datetime_fromServer('https://www.googleapis.com/oauth2/v4/token')
            EndIf
            If Not $iat Then
                $iat = __googleapis_datetime_fromSystem()
            EndIf
    EndSwitch
    If Not $iat Then Return SetError(1, @error, False)
    Return $iat
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_datetime_fromServer
; Description ...: timestamp from Date header
; Syntax ........: __googleapis_datetime_fromServer($server)
; Parameters ....: $server              - A string value.
; Return values .: unix timestamp
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: __googleapis_datetime_fromSystem __googleapis_datetime_fromNtp
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_datetime_fromServer($server)
    Local $oHttp = __googleapis_request('HEAD', $server, '', '', True)
    If Not IsObj($oHttp) Then Return SetError(@error, @extended, False)

    Local $sDate = $oHttp.GetResponseHeader('Date') ;Thu, 08 Jun 2017 14:04:48 GMT
    If Not $sDate Then Return SetError(@error, @extended, False)

    Local $aReg = StringRegExp($sDate, '(\w{3}),\s+(\d{2})\s+(\w{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})', 1)
    If Not IsArray($aReg) Then Return SetError(1, 0, False)
    Local $tSYSTEMTIME = DllStructCreate("word Year;word Month;word Dow;word Day;word Hour;word Minute;word Second;word MSeconds;")
    DllStructSetData($tSYSTEMTIME, "Day", $aReg[1])
    DllStructSetData($tSYSTEMTIME, "Year", $aReg[3])
    DllStructSetData($tSYSTEMTIME, "Hour", $aReg[4])
    DllStructSetData($tSYSTEMTIME, "Minute", $aReg[5])
    DllStructSetData($tSYSTEMTIME, "Second", $aReg[6])
    Local $iMonth = @MON
    Switch StringLower($aReg[1])
        Case 'january', 'jan.', 'jan'
            $iMonth = 1
        Case 'february', 'feb.', 'feb'
            $iMonth = 2
        Case 'march', 'mar.', 'mar'
            $iMonth = 3
        Case 'april', 'apr.', 'apr'
            $iMonth = 4
        Case 'may'
            $iMonth = 5
        Case 'june', 'jun.', 'jun'
            $iMonth = 6
        Case 'july', 'jul.', 'jul'
            $iMonth = 7
        Case 'august', 'aug.', 'aug'
            $iMonth = 8
        Case 'september', 'sep.', 'sep', 'sept'
            $iMonth = 9
        Case 'october', 'oct.', 'oct'
            $iMonth = 10
        Case 'november', 'nov.', 'nov'
            $iMonth = 11
        Case 'december', 'dec.', 'dec'
            $iMonth = 12
    EndSwitch
    DllStructSetData($tSYSTEMTIME, "Month", $iMonth)

    Return __googleapis_datetime_epoch_unix($tSYSTEMTIME)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_datetime_fromSystem
; Description ...: timestamp from system time
; Syntax ........: __googleapis_datetime_fromSystem()
; Parameters ....:
; Return values .: unix timestamp
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: __googleapis_datetime_fromServer __googleapis_datetime_fromNtp
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_datetime_fromSystem()
    Local Const $tagSYSTEMTIME = "struct;word Year;word Month;word Dow;word Day;word Hour;word Minute;word Second;word MSeconds;endstruct"

    Local $tLocal = DllStructCreate($tagSYSTEMTIME)
    DllCall("kernel32.dll", "none", "GetLocalTime", "struct*", $tLocal)
    If @error Then Return SetError(@error, @extended, 0)

    Local $tUTC = DllStructCreate($tagSYSTEMTIME)
    DllCall("kernel32.dll", "ptr", "TzSpecificLocalTimeToSystemTime", "ptr", 0, "struct*", $tLocal, "struct*", $tUTC)
    If @error Then Return SetError(@error, @extended, 0)

    Return __googleapis_datetime_epoch_unix($tUTC)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_datetime_fromNtp
; Description ...: timestamp from public ntp servers
; Syntax ........: __googleapis_datetime_fromNtp([$server = 'pool.ntp.org'])
; Parameters ....: $server   ntp server  - [optional] A string value. Default is 'pool.ntp.org'.
; Return values .: unix timestamp
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......: __googleapis_datetime_fromServer __googleapis_datetime_fromSystem
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_datetime_fromNtp($server = 'pool.ntp.org')
    UDPStartup()
    If @error Then Return SetError(1, 0, False)

    Local $tNTP = DllStructCreate('byte Header[4];byte RootDelay[4];byte RootDispersion[4];byte ReferenceIdentifier[4];byte ReferenceTimestamp[8];byte OriginateTimestamp[8];byte ReceiveTimestamp[8];byte TransmitTimestamp[8];byte KeyIdentifier[4];byte MessageDigest[16]')
    Local $tPacket = DllStructCreate('byte Packet[68]', DllStructGetPtr($tNTP))
    Local $bPacket = 0
    $tNTP.Header = Binary('0x1B000000')

    Local $aSocket = UDPOpen(TCPNameToIP($server), 123)
    If Not @error Then
        UDPSend($aSocket, $tPacket.Packet)
        If Not @error Then
            While 1
                $bPacket = UDPRecv($aSocket, 68, 1)
                If @error Or $bPacket Then ExitLoop
                Sleep(100)
            WEnd
        EndIf
    EndIf
    UDPCloseSocket($aSocket)
    UDPShutdown()
    If Not $bPacket Then Return SetError(2, 0, False)

    Local Const $tagFILETIME = "struct;dword Lo;dword Hi;endstruct"
    Local $tFT = DllStructCreate($tagFILETIME)
    Local $tQW = DllStructCreate('uint64 Timestamp', DllStructGetPtr($tFT))
    $tPacket.Packet = $bPacket
    ;it can convert to unixepoch see https://stackoverflow.com/questions/29112071/how-to-convert-ntp-time-to-unix-epoch-time-in-c-language-linux
    ;but i can't, so convert to system time
    $tQW.Timestamp = Dec(StringMid(DllStructGetData($tNTP, 'TransmitTimestamp'), 3, 8), 2) * 10000000 + 94354848000000000

    Local Const $tagSYSTEMTIME = "struct;word Year;word Month;word Dow;word Day;word Hour;word Minute;word Second;word MSeconds;endstruct"
    Local $tSYSTEMTIME = DllStructCreate($tagSYSTEMTIME)
    Local $aResult = DllCall("kernel32.dll", "bool", "FileTimeToSystemTime", "struct*", $tQW, "struct*", $tSYSTEMTIME)
    If @error Or Not $aResult[0] Then Return SetError(3, 0, False)
    Return __googleapis_datetime_epoch_unix($tSYSTEMTIME)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_datetime_epoch_unix
; Description ...: convert SYSTEMTIME struct to unix epoch timestamp
; Syntax ........: __googleapis_datetime_epoch_unix($tSYSTEMTIME)
; Parameters ....: $tSYSTEMTIME         - A dll struct value.
; Return values .: unix timestamp
; Author ........: inververs
; Modified ......:
; Remarks .......: specified as seconds since 00:00:00 UTC, January 1, 1970
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_datetime_epoch_unix($tSYSTEMTIME)
    Local $iDay = DllStructGetData($tSYSTEMTIME, "Day")
    Local $iMonth = DllStructGetData($tSYSTEMTIME, "Month")
    Local $iYear = DllStructGetData($tSYSTEMTIME, "Year")
    Local $iHour = DllStructGetData($tSYSTEMTIME, "Hour")
    Local $iMinute = DllStructGetData($tSYSTEMTIME, "Minute")
    Local $iSecond = DllStructGetData($tSYSTEMTIME, "Second")
    If $iMonth < 3 Then
        $iMonth += 12
        $iYear -= 1
    EndIf
    Local $i_aFactor = Int($iYear / 100)
    Local $i_bFactor = Int($i_aFactor / 4)
    Local $i_cFactor = 2 - $i_aFactor + $i_bFactor
    Local $i_eFactor = Int(1461 * ($iYear + 4716) / 4)
    Local $i_fFactor = Int(153 * ($iMonth + 1) / 5)
    Local $aDaysDiff = $i_cFactor + $iDay + $i_eFactor + $i_fFactor - 2442112
    Local $iTimeDiff = $iHour * 3600 + $iMinute * 60 + $iSecond
    Return $aDaysDiff * 86400 + $iTimeDiff
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_request
; Description ...: do https requests
; Syntax ........: __googleapis_request([$sMethod = 'GET'[, $sUrl = ''[, $vData = ''[, $sHeaders = Default[, $asObject = False]]]]])
; Parameters ....: $sMethod             - [optional] A string value. Default is 'GET'.
;                  $sUrl                - [optional] A string value. Default is ''.
;                  $vData               - [optional] A variant value. Default is ''.
;                  $sHeaders  additional headers (head=value&head2=value) - [optional] A string value. Default is Default.
;                  $asObject   return request object         - [optional] An booalen value.. Default is False.
; Return values .: response text
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_request($sMethod = 'GET', $sUrl = '', $vData = '', $sHeaders = Default, $asObject = False)
    Local $oHttp = ObjCreate("WinHttp.WinHttpRequest.5.1")
    If Not IsObj($oHttp) Then
        Return SetError(1, @error, False)
    EndIf

    Local $cfg = __googleapis_config

    Local $default_headers = $cfg('request.headers')
    If IsObj($default_headers) Then
        For $head In $default_headers
            $oHttp.SetRequestHeader($head, $default_headers.item($head))
        Next
    EndIf

    Local $default_options = $cfg('request.options')
    If IsObj($default_options) Then
        For $item In $default_options
            $oHttp.Option(Int($item), $default_options.item($item))
        Next
    EndIf

    With $oHttp
        .Open($sMethod, $sUrl, False)
        .SetTimeouts( _
                $cfg('request.timeout.resolve'), _
                $cfg('request.timeout.connect'), _
                $cfg('request.timeout.send'), _
                $cfg('request.timeout.receive'))
    EndWith

    Local $aReg
    If $sHeaders Then
        For $head In StringSplit($sHeaders, '&', 2)
            $aReg = StringRegExp($head, '(?m)^([^=]+)=(.*?)$', 1)
            If UBound($aReg) > 1 Then $oHttp.SetRequestHeader($aReg[0], $aReg[1])
        Next
    EndIf
    $oHttp.Send($vData)
    If $asObject Then Return SetError(@error, 0, $oHttp)
    Return SetError(@error, $oHttp.Status, $oHttp.ResponseText)
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_InvalidArgumentException
; Description ...: invalid argument exception in udf.
; Syntax ........: __googleapis_InvalidArgumentException()
; Parameters ....:
; Return values .: 1500
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_InvalidArgumentException()
    Return 1500
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_RuntimeException
; Description ...: runtime exception in udf.
; Syntax ........: __googleapis_RuntimeException()
; Parameters ....:
; Return values .: 1501
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_RuntimeException()
    Return 1501
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_UnexpectedValueException
; Description ...: unexpected value exception in udf.
; Syntax ........: __googleapis_UnexpectedValueException()
; Parameters ....:
; Return values .: 1502
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_UnexpectedValueException()
    Return 1502
EndFunc
; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __googleapis_DomainException
; Description ...: domain exception in udf.
; Syntax ........: __googleapis_DomainException()
; Parameters ....:
; Return values .: 1503
; Author ........: inververs
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func __googleapis_DomainException()
    Return 1503
EndFunc
