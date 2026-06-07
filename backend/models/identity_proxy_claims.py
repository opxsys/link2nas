from dataclasses import dataclass


@dataclass
class IdentityProxyClaims:
    provider_type: str
    issuer: str    # e.g. "cloudflare_access:leang.cloudflareaccess.com"
    subject: str   # sub from the token
    email: str
    display_name: str | None = None
    # raw_claims intentionally excluded: never log or expose
