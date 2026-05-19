from typing import Any

from backend.services_v2.destinations.base import Destination


class LinksOnlyDestination(Destination):
    def test_connection(self) -> dict[str, Any]:
        return {
            "ok": True,
            "destination_name": "links_only",
            "message": "Links only destination OK",
        }

    def send(self, output_links: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "destination": "links_only",
            "status": "completed",
            "links_count": len(output_links),
        }