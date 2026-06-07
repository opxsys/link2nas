import json

import jwt
from jwt import PyJWKClient

from backend.models.identity_proxy_claims import IdentityProxyClaims
from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyConfigError,
    IdentityProxyValidationError,
    IdentityProxyValidator,
)


class CloudflareAccessValidator(IdentityProxyValidator):

    def validate_request(self, headers: dict, config: IdentityProxyConfig) -> IdentityProxyClaims:
        token = (
            headers.get("Cf-Access-Jwt-Assertion")
            or headers.get("cf-access-jwt-assertion")
        )
        if not token:
            raise IdentityProxyValidationError("Missing Cf-Access-Jwt-Assertion header")

        try:
            cfg = json.loads(config.config_json)
        except Exception:
            raise IdentityProxyConfigError("config_json is not valid JSON")

        team_domain = cfg.get("team_domain", "").strip()
        audience = cfg.get("audience", "").strip()

        if not team_domain:
            raise IdentityProxyConfigError("team_domain is missing from config_json")
        if not audience:
            raise IdentityProxyConfigError("audience is missing from config_json")

        issuer = f"https://{team_domain}"
        jwks_url = f"https://{team_domain}/cdn-cgi/access/certs"

        claims = self._decode_token(token, jwks_url, audience, issuer)
        return self._extract_claims(claims, team_domain)

    def _decode_token(self, token: str, jwks_url: str, audience: str, issuer: str) -> dict:
        try:
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
        except Exception as exc:
            raise IdentityProxyValidationError(
                f"JWKS key resolution failed: {type(exc).__name__}"
            ) from exc

        try:
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "RS384", "ES384", "RS512"],
                audience=audience,
                issuer=issuer,
                options={"require": ["sub", "iss", "aud", "exp", "iat"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityProxyValidationError("Token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityProxyValidationError("Token audience mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityProxyValidationError("Token issuer mismatch") from exc
        except jwt.DecodeError as exc:
            raise IdentityProxyValidationError("Token decode error") from exc
        except Exception as exc:
            raise IdentityProxyValidationError(
                f"Token validation failed: {type(exc).__name__}"
            ) from exc

    def _extract_claims(self, claims: dict, team_domain: str) -> IdentityProxyClaims:
        subject = claims.get("sub", "").strip()
        if not subject:
            raise IdentityProxyValidationError("Token missing sub claim")

        email = claims.get("email", "").strip().lower()
        if not email:
            raise IdentityProxyValidationError("Token missing email claim")

        display_name = (claims.get("name") or "").strip() or None

        return IdentityProxyClaims(
            provider_type="cloudflare_access",
            issuer=f"cloudflare_access:{team_domain}",
            subject=subject,
            email=email,
            display_name=display_name,
        )
