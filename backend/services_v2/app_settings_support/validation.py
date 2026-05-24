class AppSettingsValidationError(ValueError):
    pass


def validate_int(value, name: str, *, min_value: int, max_value: int) -> int:
    try:
        int_value = int(value)
    except (TypeError, ValueError) as exc:
        raise AppSettingsValidationError(f"{name} must be an integer") from exc

    if int_value < min_value:
        raise AppSettingsValidationError(f"{name} must be >= {min_value}")

    if int_value > max_value:
        raise AppSettingsValidationError(f"{name} must be <= {max_value}")

    return int_value
