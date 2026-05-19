from backend.models.notification_rule import NotificationRule


class PostgresNotificationRuleRepository:
    def __init__(self, db):
        self.db = db

    def _row_to_rule(self, row) -> NotificationRule:
        return NotificationRule(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            scope=row["scope"],
            is_enabled=bool(row["is_enabled"]),
            config_id=row["config_id"],
            severity_min=row["severity_min"],
            event_types_json=row["event_types_json"],
            rate_limit_per_hour=int(row["rate_limit_per_hour"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def create(self, rule: NotificationRule) -> NotificationRule:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO notification_rules (
                        id,
                        user_id,
                        name,
                        scope,
                        is_enabled,
                        config_id,
                        severity_min,
                        event_types_json,
                        rate_limit_per_hour,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        rule.id,
                        rule.user_id,
                        rule.name,
                        rule.scope,
                        bool(rule.is_enabled),
                        rule.config_id,
                        rule.severity_min,
                        rule.event_types_json,
                        rule.rate_limit_per_hour,
                        rule.created_at,
                        rule.updated_at,
                    ),
                )
            conn.commit()

        return rule

    def update(self, rule: NotificationRule) -> NotificationRule:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE notification_rules
                    SET
                        name = %s,
                        scope = %s,
                        is_enabled = %s,
                        config_id = %s,
                        severity_min = %s,
                        event_types_json = %s,
                        rate_limit_per_hour = %s,
                        updated_at = %s
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (
                        rule.name,
                        rule.scope,
                        bool(rule.is_enabled),
                        rule.config_id,
                        rule.severity_min,
                        rule.event_types_json,
                        rule.rate_limit_per_hour,
                        rule.updated_at,
                        rule.id,
                        rule.user_id,
                    ),
                )
            conn.commit()

        return rule

    def delete(self, user_id: str, rule_id: str) -> bool:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM notification_rules
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (rule_id, user_id),
                )
                deleted = cur.rowcount > 0
            conn.commit()

        return deleted

    def get_by_id(self, user_id: str, rule_id: str) -> NotificationRule | None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_rules
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (rule_id, user_id),
                )
                row = cur.fetchone()

        return self._row_to_rule(row) if row else None

    def list_for_user(self, user_id: str) -> list[NotificationRule]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_rules
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                )
                rows = cur.fetchall()

        return [self._row_to_rule(row) for row in rows]

    def list_enabled_for_user(self, user_id: str, scope: str | None = None) -> list[NotificationRule]:
        params = [user_id]
        scope_clause = ""

        if scope:
            scope_clause = "AND scope = %s"
            params.append(scope)

        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT *
                    FROM notification_rules
                    WHERE user_id = %s
                      AND is_enabled = TRUE
                      {scope_clause}
                    ORDER BY created_at DESC
                    """,
                    tuple(params),
                )
                rows = cur.fetchall()

        return [self._row_to_rule(row) for row in rows]
