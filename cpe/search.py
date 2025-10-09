from typing import List, Dict, Optional
from py2neo import Graph

ALLOWED_PARTS = {"a", "o", "h"}

def vendors(graph: Graph, part: str, q: str = "", limit: int = 100, offset: int = 0) -> List[str]:
    if part not in ALLOWED_PARTS:
        return []
    q = (q or "").lower()
    res = graph.run(
        """
        MATCH (p:CPE)
        WHERE p.part = $part AND ("" = $q OR toLower(p.vendor) STARTS WITH $q)
        RETURN DISTINCT p.vendor AS vendor
        ORDER BY vendor
        SKIP $offset
        LIMIT $limit
        """,
        part=part, q=q, limit=limit, offset=max(0, int(offset)),
    ).data()
    return [r["vendor"] for r in res if r.get("vendor")]


def products(graph: Graph, part: str, vendor: str, q: str = "", limit: int = 100, offset: int = 0) -> List[str]:
    if part not in ALLOWED_PARTS or not vendor:
        return []
    q = (q or "").lower()
    res = graph.run(
        """
        MATCH (p:CPE {part: $part})
        WHERE toLower(p.vendor) = toLower($vendor)
          AND ("" = $q OR toLower(p.product) STARTS WITH $q)
        RETURN DISTINCT p.product AS product
        ORDER BY product
        SKIP $offset
        LIMIT $limit
        """,
        part=part, vendor=vendor, q=q, limit=limit, offset=max(0, int(offset)),
    ).data()
    return [r["product"] for r in res if r.get("product")]


def versions(graph: Graph, part: str, vendor: str, product: str, q: str = "", limit: int = 100, offset: int = 0) -> List[str]:
    if part not in ALLOWED_PARTS or not vendor or not product:
        return []
    q = (q or "").lower()
    res = graph.run(
        """
        MATCH (p:CPE {part: $part})
        WHERE toLower(p.vendor) = toLower($vendor)
          AND toLower(p.product) = toLower($product)
          AND ("" = $q OR toLower(p.version) STARTS WITH $q)
        RETURN DISTINCT coalesce(p.version, "*") AS version
        ORDER BY version
        SKIP $offset
        LIMIT $limit
        """,
        part=part, vendor=vendor, product=product, q=q, limit=limit, offset=max(0, int(offset)),
    ).data()
    return [r["version"] for r in res if r.get("version") is not None]


def search(graph: Graph, part: str, vendor: Optional[str] = None, product: Optional[str] = None,
           version: Optional[str] = None, limit: int = 100) -> List[Dict[str, str]]:
    if part not in ALLOWED_PARTS:
        return []
    vendor = vendor or ""
    product = product or ""
    version = version or ""
    data = graph.run(
        """
        MATCH (p:CPE {part: $part})
        WHERE ($vendor = "" OR toLower(p.vendor) = toLower($vendor))
          AND ($product = "" OR toLower(p.product) = toLower($product))
          AND ($version = "" OR toLower(p.version) = toLower($version))
        RETURN DISTINCT p.cpe23Uri AS cpe23Uri, p.vendor AS vendor, p.product AS product, coalesce(p.version,'*') AS version
        ORDER BY vendor, product, version
        LIMIT $limit
        """,
        part=part, vendor=vendor, product=product, version=version, limit=limit,
    ).data()
    return data
