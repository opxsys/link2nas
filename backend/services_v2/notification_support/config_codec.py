import json


def encode_config(crypto_service, config: dict) -> str:
    raw = json.dumps(config)

    if crypto_service:
        return crypto_service.encrypt(raw)

    return raw


def decode_config(crypto_service, config_json: str) -> dict:
    raw = config_json or "{}"

    if crypto_service:
        try:
            raw = crypto_service.decrypt(raw)
        except Exception:
            raw = "{}"

    try:
        value = json.loads(raw)
    except Exception:
        return {}

    return value if isinstance(value, dict) else {}
