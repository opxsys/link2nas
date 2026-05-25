from flask import jsonify


def _error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code
