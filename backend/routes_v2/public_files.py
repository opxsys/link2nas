from pathlib import Path
from urllib.parse import quote

from flask import Blueprint, abort, current_app, make_response, send_file

public_files_v2_bp = Blueprint("public_files_v2", __name__)


def _resolve_user_space(slug: str) -> tuple[object, Path]:
    user_repo = current_app.config["USER_REPO_V2"]
    user = user_repo.get_by_public_slug(slug)
    if not user:
        abort(404)

    settings = current_app.config["SETTINGS"]
    userdata_root = Path(settings.USERDATA_DIR).resolve()
    space_path = (userdata_root / user.id / "local").resolve()

    if not str(space_path).startswith(str(userdata_root) + "/"):
        abort(404)

    if not user.can_use_local_space:
        abort(404)

    return user, space_path


def _format_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


_PAGE_CSS = (
    "body{font-family:Inter,system-ui,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:0}"
    ".wrap{max-width:800px;margin:40px auto;padding:0 20px}"
    ".hd{margin-bottom:24px}"
    ".hd h1{font-size:1.25rem;font-weight:600;margin:0 0 6px}"
    ".bc{font-size:0.8rem;color:#64748b;display:flex;gap:4px;align-items:center;flex-wrap:wrap}"
    ".bc a{color:#2563eb;text-decoration:none}"
    ".bc a:hover{text-decoration:underline}"
    ".bc .s{color:#cbd5e1}"
    ".card{background:#fff;border:1px solid #dbe3ee;border-radius:14px;overflow:hidden;"
    "box-shadow:0 8px 24px rgba(15,23,42,.08)}"
    ".row{display:flex;align-items:center;gap:12px;padding:12px 16px;"
    "border-bottom:1px solid #f1f5f9;text-decoration:none;color:inherit}"
    ".row:last-child{border-bottom:none}"
    ".row:hover{background:#f1f5f9}"
    ".ic{width:20px;height:20px;flex-shrink:0;fill:currentColor}"
    ".if{color:#f59e0b}"
    ".id{color:#64748b}"
    ".nm{flex:1;font-size:.9rem;word-break:break-all;color:#0f172a}"
    ".nl{color:#2563eb}"
    ".sz{font-size:.8rem;color:#64748b;white-space:nowrap}"
    ".empty{padding:40px;text-align:center;color:#64748b;font-size:.9rem}"
    ".stats{font-size:.8rem;color:#94a3b8;margin-top:12px}"
)

_ICON_FOLDER = (
    '<svg class="ic if" viewBox="0 0 24 24">'
    '<path d="M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8'
    'a2 2 0 0 0-2-2h-8l-2-2z"/></svg>'
)
_ICON_FILE = (
    '<svg class="ic id" viewBox="0 0 24 24">'
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z'
    'M13 3.5L18.5 9H13V3.5z"/></svg>'
)
_ICON_UP = (
    '<svg class="ic id" viewBox="0 0 24 24">'
    '<path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg>'
)


def _encode_parts(parts) -> str:
    return "/".join(quote(p, safe="") for p in parts)


def _render_listing(slug: str, user, space_path: Path, relative_dir: str = "") -> str:
    if relative_dir:
        path_parts = Path(relative_dir).parts
        if not path_parts or any(p in (".", "..") or p.startswith(".") for p in path_parts):
            abort(400)
        target = (space_path / relative_dir).resolve()
        try:
            target.relative_to(space_path)
        except ValueError:
            abort(400)
        if not target.is_dir():
            abort(404)
    else:
        path_parts = ()
        target = space_path

    dirs, files_list = [], []
    if target.is_dir():
        for entry in target.iterdir():
            if entry.name.startswith("."):
                continue
            if entry.is_symlink():
                try:
                    entry.resolve().relative_to(space_path)
                except ValueError:
                    continue
            if entry.is_dir():
                dirs.append(entry)
            elif entry.is_file():
                files_list.append(entry)

    dirs.sort(key=lambda e: e.name.lower())
    files_list.sort(key=lambda e: e.name.lower())

    display = _escape_html(user.display_name or user.email.split("@")[0])
    base = "/u/" + quote(slug, safe="")

    if path_parts:
        bc_items = ['<a href="%s/">%s</a>' % (base, display)]
        acc: list[str] = []
        for i, part in enumerate(path_parts):
            acc.append(part)
            if i < len(path_parts) - 1:
                bc_items.append(
                    '<a href="%s/browse/%s">%s</a>'
                    % (base, _encode_parts(acc), _escape_html(part))
                )
            else:
                bc_items.append(_escape_html(part))
        breadcrumb = '<span class="s">/</span>'.join(bc_items)
    else:
        breadcrumb = display

    rows = []

    if path_parts:
        if len(path_parts) > 1:
            parent_url = "%s/browse/%s" % (base, _encode_parts(path_parts[:-1]))
        else:
            parent_url = "%s/" % base
        rows.append(
            '<a class="row" href="%s">%s<span class="nm">..</span></a>'
            % (parent_url, _ICON_UP)
        )

    for d in dirs:
        rel_parts = d.relative_to(space_path).parts
        rows.append(
            '<a class="row" href="%s/browse/%s">'
            '%s<span class="nm">%s</span>'
            '<span class="sz">Dossier</span></a>'
            % (base, _encode_parts(rel_parts), _ICON_FOLDER, _escape_html(d.name))
        )

    for f in files_list:
        rel_parts = f.relative_to(space_path).parts
        size = f.stat().st_size
        rows.append(
            '<a class="row" href="%s/files/%s">'
            '%s<span class="nm nl">%s</span>'
            '<span class="sz">%s</span></a>'
            % (base, _encode_parts(rel_parts), _ICON_FILE, _escape_html(f.name), _format_size(size))
        )

    if rows:
        card_body = "".join(rows)
    else:
        msg = "Dossier vide." if path_parts else "Aucun fichier disponible."
        card_body = '<div class="empty">%s</div>' % msg

    stats = "%d dossier(s), %d fichier(s)" % (len(dirs), len(files_list))
    title = "Espace de %s" % display

    return (
        "<!DOCTYPE html>\n"
        '<html lang="fr">\n'
        "<head>\n"
        '  <meta charset="utf-8"/>\n'
        '  <meta name="viewport" content="width=device-width,initial-scale=1"/>\n'
        '  <meta name="robots" content="noindex, nofollow, noarchive"/>\n'
        "  <title>%(title)s</title>\n"
        "  <style>%(css)s</style>\n"
        "</head>\n"
        "<body>\n"
        '  <div class="wrap">\n'
        '    <div class="hd">\n'
        "      <h1>%(title)s</h1>\n"
        '      <div class="bc">%(breadcrumb)s</div>\n'
        "    </div>\n"
        '    <div class="card">%(card_body)s</div>\n'
        '    <div class="stats">%(stats)s</div>\n'
        "  </div>\n"
        "</body>\n"
        "</html>"
    ) % {
        "title": title,
        "css": _PAGE_CSS,
        "breadcrumb": breadcrumb,
        "card_body": card_body,
        "stats": stats,
    }


_NOINDEX = "noindex, nofollow, noarchive"


@public_files_v2_bp.get("/u/<slug>/")
def public_space_index(slug: str):
    user, space_path = _resolve_user_space(slug)
    return _render_listing(slug, user, space_path), 200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Robots-Tag": _NOINDEX,
    }


@public_files_v2_bp.get("/u/<slug>/browse/<path:relative_dir>")
def public_space_browse(slug: str, relative_dir: str):
    user, space_path = _resolve_user_space(slug)
    return _render_listing(slug, user, space_path, relative_dir), 200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Robots-Tag": _NOINDEX,
    }


@public_files_v2_bp.get("/u/<slug>/files/<path:relative_path>")
def public_space_file(slug: str, relative_path: str):
    _, space_path = _resolve_user_space(slug)

    if not relative_path:
        abort(400)

    parts = Path(relative_path).parts
    if not parts or any(p in (".", "..") for p in parts):
        abort(400)

    file_path = (space_path / relative_path).resolve()

    try:
        file_path.relative_to(space_path)
    except ValueError:
        abort(400)

    if not file_path.is_file():
        abort(404)

    response = make_response(send_file(file_path, as_attachment=True))
    response.headers["X-Robots-Tag"] = _NOINDEX
    return response
