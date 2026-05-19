SUPPORTED_USER_LANGUAGES = ("fr", "en")

DEFAULT_USER_LANGUAGE = "en"


def validate_preferred_language(value):
    if value is None or value == "":
        return None
    lang = str(value).strip().lower()
    if lang not in SUPPORTED_USER_LANGUAGES:
        raise ValueError(f"Unsupported language '{value}'. Supported: fr, en")
    return lang


def resolve_preferred_language(value):
    lang = str(value or "").strip().lower()
    return lang if lang in SUPPORTED_USER_LANGUAGES else DEFAULT_USER_LANGUAGE
