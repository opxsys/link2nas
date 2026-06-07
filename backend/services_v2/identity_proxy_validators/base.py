from abc import ABC, abstractmethod

from backend.models.identity_proxy_claims import IdentityProxyClaims
from backend.models.identity_proxy_config import IdentityProxyConfig


class IdentityProxyError(Exception):
    pass


class IdentityProxyConfigError(IdentityProxyError):
    pass


class IdentityProxyValidationError(IdentityProxyError):
    pass


class IdentityProxyUserError(IdentityProxyError):
    pass


class IdentityProxyDisabledError(IdentityProxyError):
    pass


class IdentityProxyValidator(ABC):
    @abstractmethod
    def validate_request(
        self, headers: dict, config: IdentityProxyConfig
    ) -> IdentityProxyClaims: ...
