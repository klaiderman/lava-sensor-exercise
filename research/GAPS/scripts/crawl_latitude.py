# -*- coding: utf-8 -*-
import asyncio, json, time, re, sys
sys.stdout.reconfigure(encoding='utf-8')
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, BrowserConfig

URLS = [
    "https://www.latitude.sh/blog/introducing-remote-access-the-safest-way-to-access-your-servers-remotely",
    "https://www.latitude.sh/changelog/remote-access-without-vpn-now-generally-available",
    "https://www.latitude.sh/docs/servers/deleting-a-server",
    "https://www.latitude.sh/legal/security",
    "https://www.latitude.sh/docs/servers/user-data",
    "https://docs.latitude.sh/docs/ssh",
    "https://www.latitude.sh/docs/servers/custom-images",
    "https://www.latitude.sh/changelog/deploy-servers-in-15-seconds-with-instant-deployments",
]

def slug(u):
    return re.sub(r'[^a-zA-Z0-9]+', '_', u)[-60:]

async def main():
    bcfg = BrowserConfig(headless=True)
    cfg = CrawlerRunConfig(page_timeout=25000, wait_until="networkidle")
    async with AsyncWebCrawler(config=bcfg) as crawler:
        for url in URLS:
            t0 = time.time()
            try:
                res = await crawler.arun(url=url, config=cfg)
                dt = time.time() - t0
                ok = res.success
                mdlen = len(res.markdown.raw_markdown) if ok and res.markdown else 0
                print(f"URL {url}")
                print(f"  success={ok} status={getattr(res,'status_code',None)} elapsed={dt:.2f}s md_len={mdlen} err={getattr(res,'error_message',None)}")
                if ok and res.markdown:
                    fn = "lat_" + slug(url) + ".txt"
                    with open(fn, "w", encoding="utf-8") as f:
                        f.write(res.markdown.raw_markdown)
                    print(f"  saved {fn}")
            except Exception as e:
                print(f"URL {url}\n  EXCEPTION {repr(e)}")

asyncio.run(main())
