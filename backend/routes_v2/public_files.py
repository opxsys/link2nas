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
    # Colour tokens — light mode
    ":root{"
    "--bg:#f8fafc;--fg:#0f172a;--card:#ffffff;--bd:#e2e8f0;"
    "--muted:#64748b;--hover:#f1f5f9;--link:#2563eb;"
    "--shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);"
    "--rad:10px;--brand:#94a3b8;--ic-folder:#f59e0b;--ic-file:#94a3b8"
    "}"
    # Dark mode — automatic via OS/browser preference
    "@media(prefers-color-scheme:dark){"
    ":root{"
    "--bg:#020817;--fg:#f1f5f9;--card:#0f172a;--bd:#1e293b;"
    "--muted:#94a3b8;--hover:#1e293b;--link:#60a5fa;"
    "--shadow:0 1px 3px rgba(0,0,0,.3);"
    "--brand:#475569;--ic-folder:#fbbf24;--ic-file:#64748b"
    "}}"
    # Reset & base
    "*{box-sizing:border-box}"
    "body{font-family:Inter,system-ui,-apple-system,sans-serif;"
    "background:var(--bg);color:var(--fg);margin:0;padding:0;"
    "-webkit-font-smoothing:antialiased}"
    # Layout
    ".wrap{max-width:700px;margin:0 auto;padding:36px 20px 56px}"
    # Branding label
    ".logo{font-size:.65rem;font-weight:700;letter-spacing:.15em;"
    "text-transform:uppercase;color:var(--brand);margin-bottom:14px}"
    # Header
    ".hd{margin-bottom:20px}"
    ".hd h1{font-size:1.3rem;font-weight:700;margin:0 0 5px;line-height:1.3}"
    # Breadcrumb
    ".bc{font-size:.8rem;color:var(--muted);display:flex;gap:4px;"
    "align-items:center;flex-wrap:wrap}"
    ".bc a{color:var(--link);text-decoration:none}"
    ".bc a:hover{text-decoration:underline}"
    ".bc .s{color:var(--bd)}"
    # Card
    ".card{background:var(--card);border:1px solid var(--bd);"
    "border-radius:var(--rad);overflow:hidden;box-shadow:var(--shadow)}"
    # Rows
    ".row{display:flex;align-items:center;gap:12px;padding:10px 16px;"
    "border-bottom:1px solid var(--bd);text-decoration:none;color:inherit;"
    "transition:background .12s}"
    ".row:last-child{border-bottom:none}"
    ".row:hover{background:var(--hover)}"
    # Icons
    ".ic{width:17px;height:17px;flex-shrink:0;fill:currentColor}"
    ".if{color:var(--ic-folder)}"
    ".id{color:var(--ic-file)}"
    # Row text
    ".nm{flex:1;font-size:.875rem;word-break:break-all}"
    ".nl{color:var(--link)}"
    ".sz{font-size:.75rem;color:var(--muted);white-space:nowrap}"
    # Empty state
    ".empty{padding:52px 20px;text-align:center;color:var(--muted)}"
    ".empty svg{display:block;margin:0 auto 14px;opacity:.3}"
    ".empty p{font-size:.875rem;margin:0}"
    # Stats + footer
    ".stats{font-size:.75rem;color:var(--muted);margin-top:10px;padding:0 2px}"
    ".footer{margin-top:44px;text-align:center;font-size:.7rem;"
    "color:var(--brand);letter-spacing:.06em}"
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
_ICON_EMPTY = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24"'
    ' fill="none" stroke="currentColor" stroke-width="1.5"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'
    '</svg>'
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
        card_body = '<div class="empty">%s<p>%s</p></div>' % (_ICON_EMPTY, msg)

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
        '    <div class="logo">Link2NAS</div>\n'
        '    <div class="hd">\n'
        "      <h1>%(title)s</h1>\n"
        '      <div class="bc">%(breadcrumb)s</div>\n'
        "    </div>\n"
        '    <div class="card">%(card_body)s</div>\n'
        '    <div class="stats">%(stats)s</div>\n'
        '    <div class="footer">Espace public · Link2NAS</div>\n'
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
