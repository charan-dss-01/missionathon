"""Defang utilities for safe rendering of suspicious URLs, domains, and IP addresses."""

import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit


def defang_url(url: Optional[str]) -> str:
    """
    Defangs a URL or hostname:
    - Changes scheme 'http://' -> 'hxxp://' and 'https://' -> 'hxxps://'
    - Replaces '.' with '[.]' in the host / domain
    - Defangs raw IP addresses (e.g. 192.168.1.1 -> 192[.]168[.]1[.]1)
    - Preserves path, query, and anchor fragments while preventing double-defanging
    """
    if not url:
        return ""

    raw = str(url).strip()
    if not raw:
        return ""

    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw))

    if has_scheme:
        # Defang scheme
        defanged_scheme_str = re.sub(r"^http://", "hxxp://", raw, flags=re.IGNORECASE)
        defanged_scheme_str = re.sub(r"^https://", "hxxps://", defanged_scheme_str, flags=re.IGNORECASE)

        try:
            parts = urlsplit(defanged_scheme_str)
            netloc = parts.netloc

            userinfo = ""
            host_port = netloc
            if "@" in netloc:
                userinfo, host_port = netloc.split("@", 1)
                userinfo += "@"

            host = host_port
            port = ""
            if ":" in host_port and not host_port.startswith("["):
                host, port = host_port.split(":", 1)
                port = ":" + port

            # Defang dots in host (avoid double-defanging if already '[.]')
            defanged_host = re.sub(r"(?<!\[)\.(?!\])", "[.]", host)
            defanged_netloc = f"{userinfo}{defanged_host}{port}"

            return urlunsplit((parts.scheme, defanged_netloc, parts.path, parts.query, parts.fragment))
        except Exception:
            return re.sub(r"^https?://", lambda m: "hxxps://" if "s" in m.group(0).lower() else "hxxp://", raw)
    else:
        # No scheme present: defang host part before any path slash
        if "/" in raw:
            host_part, rest = raw.split("/", 1)
            defanged_host = re.sub(r"(?<!\[)\.(?!\])", "[.]", host_part)
            return f"{defanged_host}/{rest}"
        else:
            return re.sub(r"(?<!\[)\.(?!\])", "[.]", raw)
