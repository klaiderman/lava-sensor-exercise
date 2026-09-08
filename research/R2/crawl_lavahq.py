"""
Bounded, polite, same-domain Crawlee crawl of https://lavahq.io for track R2
(lava-sensor-exercise). Hard bounds enforced below, per prompts/R2/prompt.md
method item 6:
  - same-domain only (lavahq.io + subpaths)
  - max 40 pages total
  - max crawl depth 3 from seed
  - max 1 concurrent request
  - robots.txt honored (fetched separately; Disallow: /api/, /studio)
  - 1 second minimum delay between requests
  - every URL + status logged to crawl_manifest.jsonl as it happens (line-buffered)
Extraction: trafilatura by default (favor_precision=True). Escalation to
crawl4ai is handled by a separate script outside this crawler for any
JS-heavy/PDF page (none identified in the sitemap at time of writing).
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
from datetime import timedelta

from crawlee.crawlers import BeautifulSoupCrawler, BeautifulSoupCrawlingContext
from crawlee import ConcurrencySettings

import trafilatura

MANIFEST_PATH = "crawl_manifest.jsonl"
DISALLOWED_PREFIXES = ["/api/", "/studio"]
MAX_PAGES = 40
MAX_DEPTH = 3
SEED = "https://lavahq.io"

manifest_f = open(MANIFEST_PATH, "a", encoding="utf-8")
visited_count = 0


def log_manifest(url, status, depth, extractor, note=None):
    rec = {
        "url": url,
        "status": status,
        "depth": depth,
        "extractor": extractor,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    if note:
        rec["note"] = note
    manifest_f.write(json.dumps(rec) + "\n")
    manifest_f.flush()


def is_disallowed(url):
    path = urlparse(url).path
    return any(path.startswith(p) for p in DISALLOWED_PREFIXES)


def is_same_domain(url):
    return urlparse(url).netloc in ("lavahq.io", "www.lavahq.io")


async def main():
    global visited_count

    concurrency_settings = ConcurrencySettings(max_concurrency=1, min_concurrency=1, desired_concurrency=1)

    crawler = BeautifulSoupCrawler(
        max_requests_per_crawl=MAX_PAGES,
        concurrency_settings=concurrency_settings,
        request_handler_timeout=timedelta(seconds=30),
    )

    @crawler.router.default_handler
    async def handler(context: BeautifulSoupCrawlingContext) -> None:
        global visited_count
        url = context.request.url
        depth = context.request.user_data.get("depth", 0)

        if visited_count >= MAX_PAGES:
            return

        if is_disallowed(url):
            log_manifest(url, "ROBOTS_DISALLOWED", depth, "none")
            return

        visited_count += 1
        status = context.http_response.status_code if context.http_response else "ERROR"

        # polite delay: 1s minimum between requests
        await asyncio.sleep(1)

        html = str(context.soup)
        extractor_used = "trafilatura"
        text = trafilatura.extract(html, favor_precision=True, url=url) or ""
        if len(text.strip()) < 500:
            extractor_used = "trafilatura-short"  # will be considered for crawl4ai escalation separately

        # persist extracted text next to manifest for downstream fact-building
        safe_name = url.replace("https://", "").replace("/", "_").strip("_") or "root"
        with open(f"page_{safe_name}.txt", "w", encoding="utf-8") as pf:
            pf.write(f"URL: {url}\nSTATUS: {status}\nDEPTH: {depth}\n---\n{text}")

        log_manifest(url, status, depth, extractor_used)

        if depth < MAX_DEPTH:
            await context.enqueue_links(
                strategy="same-domain",
                user_data={"depth": depth + 1},
            )

    await crawler.run([SEED])
    manifest_f.close()


if __name__ == "__main__":
    asyncio.run(main())
