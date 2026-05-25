from flask import jsonify


def _error(message: str, status_code: int = 400):
    return jsonify({"ok": False, "error": message}), status_code
