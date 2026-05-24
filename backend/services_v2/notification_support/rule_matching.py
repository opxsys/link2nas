import json


def match_rules_impl(
    notification_rule_repository,
    notification_config_repository,
    severity_rank_func,
    user_id: str,
    event_type: str,
    severity: str,
    scope: str,
) -> list:
    rules = notification_rule_repository.list_enabled_for_user(user_id, scope=scope)
    matched = []

    event_rank = severity_rank_func(severity)

    for rule in rules:
        if event_rank < severity_rank_func(rule.severity_min):
            continue

        event_types = json.loads(rule.event_types_json or "[]")
        if event_types and event_type not in event_types:
            continue

        config = notification_config_repository.get_by_id(user_id, rule.config_id)
        if not config or not config.is_enabled:
            continue

        matched.append(rule)

    return matched
