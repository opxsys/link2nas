import requests


def download_url_get_probe_looks_alive(url: str) -> bool:
    try:
        with requests.get(
            url,
            stream=True,
            allow_redirects=True,
            timeout=5,
        ) as response:
            if response.status_code in {200, 206, 302, 403}:
                return True

            if response.status_code in {404, 410}:
                return False

            return False

    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.RequestException:
        return False


def download_url_looks_alive(url: str) -> bool:
    try:
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=5,
        )

        if response.status_code in {200, 206, 302, 403}:
            return True

        if response.status_code in {404, 410}:
            return False

        if response.status_code in {405, 501}:
            return download_url_get_probe_looks_alive(url)

        return False

    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.TooManyRedirects:
        return False
    except requests.exceptions.RequestException:
        return download_url_get_probe_looks_alive(url)


def links_expired_or_invalid(output_links: list[dict]) -> bool:
    if not output_links:
        return True

    for link in output_links:
        url = link.get("url")
        if not url:
            return True

        if not download_url_looks_alive(url):
            return True

    return False
