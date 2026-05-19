from dataclasses import dataclass


@dataclass
class AppSetting:
    key: str
    value_json: str
    updated_at: str
