import json


def load_config_json(config, crypto_service=None) -> dict:
    raw = getattr(config, "config_json", None)

    if not raw:
        return {}

    value = str(raw)

    if value.startswith("enc::"):
        if crypto_service is None:
            raise RuntimeError("Crypto service is not configured")

        value = crypto_service.decrypt(value)

    try:
        decoded = json.loads(value)
    except Exception as exc:
        raise ValueError("Invalid notification config JSON") from exc

    if not isinstance(decoded, dict):
        raise ValueError("Notification config JSON must be an object")

    return decoded
