#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse, urljoin

try:
    import requests
except ModuleNotFoundError:
    requests = None


class SimpleResponse:
    def __init__(self, status_code: int, headers: dict[str, str], text: str, url: str) -> None:
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.url = url

    def json(self):
        return json.loads(self.text)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_name_from_url(url: str) -> str:
    p = urlparse(url)
    base = (p.netloc + p.path).strip("/").replace("/", "_")
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", base)[:120]
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    return f"{base}__{h}" if base else f"url__{h}"


MAPVIEW_URL_DEFAULT = "http://www.rainfall.nbro.gov.lk:8080/mapforweb/all/mapview.aspx"
MAP_SHOW_DEFAULT = "http://www.rainfall.nbro.gov.lk:8080/mapforweb/JS/map/map_show.js"


def _parse_mm_value(text: str) -> Optional[float]:
    value_text = text.split(":", 1)[1] if ":" in text else text
    match = re.search(r"[-+]?[0-9]*\.?[0-9]+", value_text)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _split_value(text: str) -> str:
    if ":" not in text:
        return text.strip()
    return text.split(":", 1)[1].strip()


def parse_popup(popup: str) -> dict:
    parts = [p.strip() for p in popup.split("<br>")]
    header_html = parts[0] if parts else ""
    header_text = re.sub(r"<[^>]+>", "", header_html).strip()

    station_id = None
    label = header_text
    match = re.search(r"\(([^)]+)\)\s*$", header_text)
    if match:
        station_id = match.group(1).strip()
        label = header_text[: match.start()].strip()

    station_name = label
    district = None
    if " - " in label:
        chunks = [c.strip() for c in label.split(" - ")]
        if len(chunks) >= 2:
            station_name = " - ".join(chunks[:-1])
            district = chunks[-1]

    data = {
        "id": station_id,
        "label": label,
        "name": station_name,
        "district": district,
        "disabled": False,
        "current_mm": None,
        "diff_mm": None,
        "rain_24h_mm": None,
        "last_data": None,
        "last_update": None,
    }

    extras: list[str] = []
    for part in parts[1:]:
        if not part:
            continue
        lower = part.lower()
        if lower.startswith("station disabled"):
            data["disabled"] = True
            continue
        if lower.startswith("current"):
            data["current_mm"] = _parse_mm_value(part)
            continue
        if lower.startswith("diff"):
            data["diff_mm"] = _parse_mm_value(part)
            continue
        if lower.startswith("24h"):
            data["rain_24h_mm"] = _parse_mm_value(part)
            continue
        if lower.startswith("last data"):
            data["last_data"] = _split_value(part)
            continue
        if lower.startswith("last update on"):
            data["last_update"] = _split_value(part)
            continue
        extras.append(part)

    if extras:
        data["extra"] = extras

    return data


def parse_map_show_js(text: str) -> list[dict]:
    stations: list[dict] = []
    marker_re = re.compile(
        r'L\.marker\(\[(?P<lat>[^,]+),\s*(?P<lon>[^\]]+)\],\s*\{\s*icon:\s*(?P<icon>\w+)\s*\}\)\.bindPopup\("(?P<popup>.*)"\)\.addTo\(map\);'
    )

    for line in text.splitlines():
        match = marker_re.search(line)
        if not match:
            continue
        popup = match.group("popup")
        station = parse_popup(popup)
        try:
            station["lat"] = float(match.group("lat").strip())
        except ValueError:
            station["lat"] = None
        try:
            station["lon"] = float(match.group("lon").strip())
        except ValueError:
            station["lon"] = None
        station["icon"] = match.group("icon")
        station["popup_html"] = popup
        stations.append(station)
    return stations


def find_map_show_url(mapview_url: str, fallback_url: str) -> str:
    try:
        r = http_get(mapview_url)
        if getattr(r, "status_code", 0) and r.status_code >= 400:
            return fallback_url
        match = re.search(r"src=[\"']([^\"']*map_show\.js[^\"']*)[\"']", r.text, re.IGNORECASE)
        if match:
            return urljoin(mapview_url, match.group(1))
    except Exception:
        return fallback_url
    return fallback_url


def fetch_map_show(
    out_path: Path,
    meta_path: Path,
    fetched_at: str,
    fallback_reason: Optional[str] = None,
) -> int:
    mapview_url = os.getenv("MAPVIEW_URL", MAPVIEW_URL_DEFAULT).strip()
    map_show_url = os.getenv("MAP_SHOW_URL", "").strip()
    if not map_show_url:
        map_show_url = find_map_show_url(mapview_url, MAP_SHOW_DEFAULT)

    r = http_get(map_show_url)
    if getattr(r, "status_code", 0) and r.status_code >= 400:
        error = f"Map JS fetch failed (status {r.status_code})"
        write_json(
            out_path,
            {"fetched_at": fetched_at, "error": error, "source_url": map_show_url, "fallback_reason": fallback_reason},
        )
        write_json(
            meta_path,
            {
                "fetched_at": fetched_at,
                "mode": "map_show_js",
                "source_url": map_show_url,
                "mapview_url": mapview_url,
                "status": r.status_code,
                "error": error,
                "fallback_reason": fallback_reason,
            },
        )
        print(error)
        return 1

    stations = parse_map_show_js(r.text)
    if not stations:
        error = "No stations parsed from map_show.js"
        write_json(
            out_path,
            {"fetched_at": fetched_at, "error": error, "source_url": map_show_url, "fallback_reason": fallback_reason},
        )
        write_json(
            meta_path,
            {
                "fetched_at": fetched_at,
                "mode": "map_show_js",
                "source_url": map_show_url,
                "mapview_url": mapview_url,
                "status": r.status_code,
                "error": error,
                "fallback_reason": fallback_reason,
            },
        )
        print(error)
        return 1

    payload = {
        "fetched_at": fetched_at,
        "mode": "map_show_js",
        "source_url": map_show_url,
        "count": len(stations),
        "stations": stations,
    }
    if fallback_reason:
        payload["fallback_reason"] = fallback_reason

    write_json(out_path, payload)
    write_json(
        meta_path,
        {
            "fetched_at": fetched_at,
            "mode": "map_show_js",
            "source_url": map_show_url,
            "mapview_url": mapview_url,
            "status": r.status_code,
            "count": len(stations),
            "fallback_reason": fallback_reason,
        },
    )
    print(f"Wrote {out_path} with {len(stations)} stations (map_show.js).")
    return 0


def load_har_candidates(har_path: Path) -> list[str]:
    try:
        text = har_path.read_text(encoding="utf-8")
    except FileNotFoundError as ex:
        raise ValueError(f"HAR not found: {har_path}") from ex

    if not text.strip():
        raise ValueError(f"HAR file is empty: {har_path}")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as ex:
        raise ValueError(f"Invalid HAR JSON in {har_path}: {ex}") from ex
    entries = data.get("log", {}).get("entries", [])
    urls = []

    for e in entries:
        req = e.get("request", {})
        resp = e.get("response", {})
        url = req.get("url")
        if not url:
            continue

        # Candidate heuristics: JSON-ish URLs OR response content-type mentions JSON
        headers = resp.get("headers", []) or []
        ctype = ""
        for h in headers:
            if str(h.get("name", "")).lower() == "content-type":
                ctype = str(h.get("value", "")).lower()
                break

        url_l = url.lower()
        looks_json = (
            "application/json" in ctype
            or url_l.endswith(".json")
            or "json" in url_l
            or "api" in url_l
            or "data" in url_l
        )

        # Also keep NBRO rainfall host / port 8080 stuff because that’s where the map data usually lives
        looks_relevant_host = ("rainfall.nbro.gov.lk" in url_l) or ("www.rainfall.nbro.gov.lk" in url_l)

        if looks_relevant_host and looks_json:
            urls.append(url)

    # de-dupe, preserve order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def http_get(url: str, timeout: int = 30):
    # Use headers similar to browser to reduce 403 chance
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; nbrodata-bot/1.0)",
        "Accept": "application/json,text/plain,*/*",
        "Referer": "http://www.rainfall.nbro.gov.lk/web/",
    }
    if requests is not None:
        return requests.get(url, headers=headers, timeout=timeout)

    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            text = raw.decode(charset, errors="replace")
            return SimpleResponse(resp.status, dict(resp.headers.items()), text, url)
    except HTTPError as ex:
        raw = ex.read() if hasattr(ex, "read") else b""
        charset = ex.headers.get_content_charset() or "utf-8"
        text = raw.decode(charset, errors="replace") if raw else ""
        return SimpleResponse(ex.code, dict(ex.headers.items()), text, url)
    except URLError:
        raise


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Fetch NBRO rainfall data and write data/latest.json")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_list = sub.add_parser("list", help="List candidate JSON endpoints from a HAR file")
    ap_list.add_argument("--har", required=True, type=Path)

    ap_fetch = sub.add_parser("fetch", help="Fetch endpoint(s) and write data/latest.json")
    ap_fetch.add_argument("--har", required=True, type=Path)
    ap_fetch.add_argument("--out", default=Path("data/latest.json"), type=Path)

    args = ap.parse_args()

    if args.cmd == "list":
        try:
            urls = load_har_candidates(args.har)
        except ValueError as ex:
            print(str(ex))
            return 1
        if not urls:
            print("No JSON candidates found in HAR. (Try exporting HAR with 'Save all as HAR' including content.)")
            return 1
        for u in urls:
            print(u)
        return 0

    if args.cmd == "fetch":
        primary_url = os.getenv("PRIMARY_URL", "").strip()
        fetched_at = utc_now_iso()

        meta_path = Path("data/latest.meta.json")

        if primary_url:
            # Fetch single chosen endpoint and write its JSON directly as latest.json
            r = http_get(primary_url)
            content_type = r.headers.get("content-type", "")
            text = r.text

            try:
                payload = r.json()
                write_json(args.out, payload)
                ok_json = True
            except Exception:
                # If not JSON, still write text wrapped
                write_json(args.out, {"error": "PRIMARY_URL did not return valid JSON", "url": primary_url, "body": text})
                ok_json = False

            meta = {
                "fetched_at": fetched_at,
                "mode": "primary_url",
                "primary_url": primary_url,
                "status": r.status_code,
                "content_type": content_type,
                "ok_json": ok_json,
            }
            write_json(meta_path, meta)
            print(f"Wrote {args.out} from PRIMARY_URL (status={r.status_code})")
            return 0

        # Otherwise: fetch all candidates and write a combined latest.json (safe default)
        try:
            urls = load_har_candidates(args.har)
        except ValueError as ex:
            print(str(ex))
            return fetch_map_show(args.out, meta_path, fetched_at, fallback_reason=str(ex))
        if not urls:
            reason = "No candidate endpoints found in HAR"
            print("No candidates found; falling back to map_show.js.")
            return fetch_map_show(args.out, meta_path, fetched_at, fallback_reason=reason)

        sources = []
        combined = {"fetched_at": fetched_at, "sources": []}

        for url in urls:
            name = safe_name_from_url(url)
            try:
                r = http_get(url)
                ct = r.headers.get("content-type", "")
                status = r.status_code

                # Try parse JSON
                body_obj = None
                ok_json = False
                try:
                    body_obj = r.json()
                    ok_json = True
                except Exception:
                    body_obj = {"note": "non-json response", "body": r.text[:2000]}

                combined["sources"].append(
                    {
                        "name": name,
                        "url": url,
                        "status": status,
                        "content_type": ct,
                        "ok_json": ok_json,
                        "data": body_obj,
                    }
                )
                sources.append({"url": url, "status": status, "ok_json": ok_json})
            except Exception as ex:
                combined["sources"].append({"name": name, "url": url, "error": str(ex)})
                sources.append({"url": url, "error": str(ex)})

        write_json(args.out, combined)
        write_json(meta_path, {"fetched_at": fetched_at, "mode": "har_candidates", "count": len(urls), "results": sources})
        print(f"Wrote {args.out} with {len(urls)} sources (no PRIMARY_URL set).")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
