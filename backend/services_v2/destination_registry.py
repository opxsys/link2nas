DESTINATION_KEYS: frozenset[str] = frozenset({"synology", "local"})

# Accepted input aliases → canonical key
DESTINATION_ALIAS_KEYS: dict[str, str] = {"nas": "synology"}

# All accepted input values (canonical + aliases)
DESTINATION_ALL_KEYS: frozenset[str] = DESTINATION_KEYS | frozenset(DESTINATION_ALIAS_KEYS)

DESTINATION_DISPLAY_NAMES: dict[str, str] = {
    "synology": "Synology NAS",
    "local": "Local",
}
