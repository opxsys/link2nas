from backend.models.notification_rule import NotificationRule


class SQLiteNotificationRuleRepository:
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
            conn.execute(
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.id,
                    rule.user_id,
                    rule.name,
                    rule.scope,
                    1 if rule.is_enabled else 0,
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
            conn.execute(
                """
                UPDATE notification_rules
                SET
                    name = ?,
                    scope = ?,
                    is_enabled = ?,
                    config_id = ?,
                    severity_min = ?,
                    event_types_json = ?,
                    rate_limit_per_hour = ?,
                    updated_at = ?
                WHERE id = ?
                  AND user_id = ?
                """,
                (
                    rule.name,
                    rule.scope,
                    1 if rule.is_enabled else 0,
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
            cursor = conn.execute(
                """
                DELETE FROM notification_rules
                WHERE id = ?
                  AND user_id = ?
                """,
                (rule_id, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_by_id(self, user_id: str, rule_id: str) -> NotificationRule | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM notification_rules
                WHERE id = ?
                  AND user_id = ?
                """,
                (rule_id, user_id),
            ).fetchone()

        return self._row_to_rule(row) if row else None

    def list_for_user(self, user_id: str) -> list[NotificationRule]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM notification_rules
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()

        return [self._row_to_rule(row) for row in rows]

    def list_enabled_for_user(self, user_id: str, scope: str | None = None) -> list[NotificationRule]:
        params = [user_id]
        scope_clause = ""

        if scope:
            scope_clause = "AND scope = ?"
            params.append(scope)

        with self.db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT *
                FROM notification_rules
                WHERE user_id = ?
                  AND is_enabled = 1
                  {scope_clause}
                ORDER BY created_at DESC
                """,
                tuple(params),
            ).fetchall()

        return [self._row_to_rule(row) for row in rows]
