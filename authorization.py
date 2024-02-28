from typing import Dict
import jwt


def get_scopes_from_token(token) -> Dict:
    return_list = []
    for scope in token["group"]:
        return_list.append(scope)
    return {'scopes': return_list}


def validate_scopes(required_scopes, token_scopes) -> bool:
    for scope in required_scopes:
        if scope not in token_scopes:
            return False
    return True


def validate_resource(token: str, resource_name, resource_operation, resource_id) -> bool:
    token = token.replace("Bearer ", "")
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    required_scope = "/resources/development/fleet-protocol-http-api/" + resource_name + "/" + resource_operation + "/" + resource_id
    return validate_scopes(required_scope, get_scopes_from_token(decoded_token))
