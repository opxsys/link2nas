from typing import Protocol, Any


class Destination(Protocol):
    def send(self, output_links: list[dict[str, Any]]) -> dict[str, Any]:
        ...
