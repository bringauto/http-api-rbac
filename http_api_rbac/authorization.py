import jwt


class Authorization:
    def __init__(self, public_key: str) -> None:
        """
        Parameters
        ----------
        public_key : str
            Public key used to decode jwt tokens.
        """
        self._public_key = public_key
        

    def _get_scopes_from_token(self, decoded_token: dict) -> dict:
        """
        Gets scopes contained within a decoded jwt token.
        
        Parameters
        ----------
        decoded_token : dict
            Decoded jwt token.

        Returns
        -------
        dict
            Dictionary containing scopes from decoded token.
        """
        return_list = []
        for scope in decoded_token["group"]:
            return_list.append(scope)
        return {'scopes': return_list}


    def decode_token_and_get_scopes(self, token: str) -> dict|None:
        """
        Decodes a jwt token and gets scopes contained within.
        
        Parameters
        ----------
        token : str
            JWT token to be decoded.

        Returns
        -------
        dict|None
            Dictionary containing scopes from decoded token or None if token is invalid.
        """
        try:
            decoded_token = jwt.decode(token, self._public_key, algorithms=['RS256'], audience='account')
        except:
            return None
        return self._get_scopes_from_token(decoded_token)


    def _validate_scopes(self, required_scopes: list, token_scopes: list) -> bool:
        """
        Checks if all scopes in required_scopes are in token_scopes.
        
        Parameters
        ----------
        required_scopes : list
            List of required scopes.
        token_scopes : list
            List of scopes in a JWT token.

        Returns
        -------
        bool
            True if all required scopes are in token scopes, False otherwise.
        """
        for required_scope in required_scopes:
            scope_found = False
            for token_scope in token_scopes:
                if required_scope.startswith(token_scope):
                    scope_found = True
                    break
            if not scope_found:
                return False
        return True


    def validate_resource(self, token: str, resource_name: str, resource_operation: str, tenant_name: str, environment: str) -> bool:
        """
        Checks if token holder has access to specified resource.
        
        Parameters
        ----------

        Returns
        -------
        bool
            True if token holder has access to resource, False otherwise.
        """
        token = token.replace("Bearer ", "")
        try:
            decoded_token = jwt.decode(token, self._public_key, algorithms=['RS256'], audience='account')
        except:
            return False
        
        required_scopes = [
            "/resources/" + resource_name + "/" + resource_operation,
            "/tenants/" + tenant_name + "/" + environment
        ]

        return self._validate_scopes(required_scopes, self._get_scopes_from_token(decoded_token)['scopes'])
