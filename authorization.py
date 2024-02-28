import jwt


class AuthorizationObj:
    def set_public_key(self, public_key: str) -> None:
        """Set public key for token validation."""
        self._public_key = public_key
        

    def get_scopes_from_token(self, decoded_token: dict) -> dict:
        """Gets scopes contained within a decoded jwt token."""
        return_list = []
        for scope in decoded_token["group"]:
            return_list.append(scope)
        return {'scopes': return_list}


    def decode_token_and_get_scopes(self, token: str) -> dict|None:
        """Decodes a jwt token and gets scopes contained within."""
        try:
            decoded_token = jwt.decode(token, self._public_key, algorithms=['RS256'], audience='account')
        except:
            return None
        return get_scopes_from_token(decoded_token)


    def validate_scopes(self, required_scopes: list, token_scopes: dict) -> bool:
        """Checks if all scopes in required_scopes are in token_scopes."""
        for scope in required_scopes:
            if scope not in token_scopes:
                return False
        return True


    def validate_resource(self, token: str, resource_name: str, resource_operation: str, resource_id: str) -> bool:
        """Checks if token holder has access to specified resource."""
        token = token.replace("Bearer ", "")
        try:
            decoded_token = jwt.decode(token, self._public_key, algorithms=['RS256'], audience='account')
        except:
            return False
        required_scope = "/resources/development/fleet-protocol-http-api/" + resource_name + "/" + resource_operation + "/" + resource_id
        return validate_scopes(required_scope, get_scopes_from_token(decoded_token))
