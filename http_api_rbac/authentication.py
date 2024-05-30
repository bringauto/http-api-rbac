import urllib.parse as _url

from keycloak import KeycloakOpenID # type: ignore


class Authentication:
    def __init__(self, keycloak_url: str, client_id: str, secret_key: str, realm: str, callback_uri: str,
                 scope: str = "email") -> None:
        """
        Parameters
        ----------
        keycloak_url : str
            Keycloak server URL.
        client_id : str
            Keycloak client ID.
        secret_key : str
            Keycloak client secret key.
        realm : str
            Keycloak realm name.
        callback_uri : str
            URI which keycloak will redirect to after authentication.
        scope : str
            Scopes for authentication are not yet implemented. Default is "email".
        """
        self._keycloak_url = keycloak_url
        self._scope = scope
        self._realm_name = realm
        self._callback = callback_uri
        self._state = "state"

        self._oid = KeycloakOpenID(
            server_url=keycloak_url,
            client_id=client_id,
            realm_name=realm,
            client_secret_key=secret_key
        )


    def get_authentication_url(self) -> str:
        """
        Get keycloak url used for authentication.

        Returns
        -------
        str
            URL for keycloak authentication. After authentication is succesful, keycloak will redirect to the callback URI.
        """

        auth_url = self._oid.auth_url(
            redirect_uri=self._callback,
            scope=self._scope,
            state=self._state
        )
        return auth_url

    
    def device_get_authentication(self) -> dict:
        """
        Get a json for authenticating a device on keycloak.
        
        Returns
        -------
        dict
            JSON containing the device authentication URL and the device code.\n
            'verification_uri_complete' contains the URL to be used by the user to authenticate the device.\n
            'device_code' is then used to get a token for the authenticated device.
        """
        auth_url_device = self._oid.device()
        return auth_url_device


    def token_get(self, state: str|None, session_state: str|None, iss: str|None, code: str|None) -> dict:
        """
        Get token from keycloak using a code returned by keycloak.
        
        Parameters
        ----------
        state : str
            State returned by keycloak.
        session_state : str
            Session state returned by keycloak.
        iss : str
            Issuer returned by keycloak.
        code : str
            Code returned by keycloak.

        Returns
        -------
        dict
            JSON containing the token.\n
            'access_token' contains the generated JWT token.\n
            'refresh_token' contains the refresh token.
        """
        if state != self._state:
            raise Exception("Invalid state")
        
        if _url.urlparse(iss).geturl() != _appended_uri(self._keycloak_url, "realms", self._realm_name):
            raise Exception("Invalid issuer")

        token = self._oid.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=self._callback
        )
        if token["session_state"] != session_state:
            raise Exception("Invalid session state returned in token response")
        return token

    
    def device_token_get(self, device_code: str) -> dict:
        """
        Get token from keycloak using a device code returned by keycloak.
        
        Parameters
        ----------
        device_code : str
            Device code obtained from device authentication.

        Returns
        -------
        dict
            JSON containing the token for the authenticated device.\n
            'access_token' contains the generated JWT token.\n
            'refresh_token' contains the refresh token.
        """
        token = self._oid.token(
            grant_type="urn:ietf:params:oauth:grant-type:device_code",
            device_code=device_code
        )
        return token

    
    def token_refresh(self, refresh_token: str) -> dict:
        """
        Get a new token from keycloak using the refresh token.
        
        Parameters
        ----------
        refresh_token : str
            Refresh token obtained from previous token response.

        Returns
        -------
        dict
            JSON containing the new token.\n
            'access_token' contains the generated JWT token.\n
            'refresh_token' contains the refresh token.
        """
        token = self._oid.refresh_token(
            refresh_token=refresh_token
        )
        return token


def _appended_uri(uri: str, *appended: str) -> str:
    """Join URI parts.

    This function return valid URI composed of multiple parts.
    """
    if uri.endswith("//"):
        raise ValueError("Invalid URI: " + uri)
    if appended and not uri.endswith("/"):
        uri += "/"
    for part in appended:
        uri = _url.urljoin(base=uri+"/", url=part.strip("/"))
    return uri
