__version__ = "0.1.0"

from http_api_rbac.authentication import Authentication
from http_api_rbac.authorization import Authorization

# Backwards-compatible aliases for the old class names
AuthenticationObj = Authentication
AuthorizationObj = Authorization