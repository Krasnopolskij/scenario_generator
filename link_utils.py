import re
from typing import Any, Optional


def external_link_for(label: str, identifier: Any) -> Optional[str]:
    """Возвращает ссылку на карточку объекта по его идентификатору и типу узла."""
    ident = str(identifier or "").strip()
    if not ident:
        return None
    label_norm = (label or "").strip().lower()

    if label_norm == "cve":
        cid = ident.upper()
        if not cid.startswith("CVE-"):
            cid = f"CVE-{cid}"
        return f"https://nvd.nist.gov/vuln/detail/{cid}"

    if label_norm == "cwe":
        match = re.search(r"(\d+)", ident)
        if match:
            return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"
        return None

    if label_norm == "capec":
        match = re.search(r"(\d+)", ident)
        if match:
            return f"https://capec.mitre.org/data/definitions/{match.group(1)}.html"
        return None

    if label_norm == "technique":
        tech_id = ident.upper().replace(".", "/")
        if not tech_id.startswith("T"):
            tech_id = f"T{tech_id}"
        return f"https://attack.mitre.org/techniques/{tech_id}"

    return None
