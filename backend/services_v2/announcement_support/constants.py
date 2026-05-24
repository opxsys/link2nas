VALID_TYPES = frozenset({"news", "maintenance", "incident", "security"})
VALID_SEVERITIES = frozenset({"info", "warning", "critical"})


class AnnouncementEmailUnavailableError(Exception):
    pass
