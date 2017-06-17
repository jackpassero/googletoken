# GoogleToken udf

## This udf provide functions for using [OAuth 2.0](https://developers.google.com/identity/protocols/OAuth2) to access google APIs

>Google APIs use the [OAuth 2.0 protocol](http://tools.ietf.org/html/rfc6749) for authentication and authorization. Google supports common OAuth 2.0 scenarios such as those for web server, installed, and client-side applications.
>To begin, obtain OAuth 2.0 client credentials from the [Google API Console](https://console.developers.google.com/). Then your client application requests an access token from the Google Authorization Server, extracts a token from the response, and sends the token to the Google API that you want to access.

### Support 2 scenarios:
 1. **Installed applications**
>The Google OAuth 2.0 endpoint supports applications that are installed on devices such as computers, mobile devices, and tablets. When you create a client ID through the Google API Console, specify that this is an Installed application, then select Android, Chrome, iOS, or "Other" as the application type.
 2. **Service accounts**
>Google APIs such as the Prediction API and Google Cloud Storage can act on behalf of your application without accessing user information. In these situations your application needs to prove its own identity to the API, but no user consent is necessary. Similarly, in enterprise scenarios, your application can request delegated access to some resources.

Functions:
```au3
_googleapis_getToken
_googleapis_setupServiceOAuth2FromFile
_googleapis_setupServiceOAuth2FromData
_googleapis_setupDesktopOAuth2FromFile
_googleapis_setupDesktopOAuth2FromData
_googleapis_setScope
_googleapis_addScope
_googleapis_getScope
```

Todo: continue
