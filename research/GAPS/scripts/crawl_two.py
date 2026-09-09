# -*- coding: utf-8 -*-
import asyncio, sys
sys.stdout.reconfigure(encoding='utf-8')
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, BrowserConfig

async def main():
    url = "https://www.latitude.sh/docs/servers/instant-deployment"
    bcfg = BrowserConfig(headless=True)
    cfg = CrawlerRunConfig(page_timeout=25000, wait_until="networkidle")
    async with AsyncWebCrawler(config=bcfg) as crawler:
        res = await crawler.arun(url=url, config=cfg)
        print("success", res.success, "status", getattr(res,'status_code',None), "err", getattr(res,'error_message',None))
        if res.success and res.markdown:
            with open("lat_instant_deployment.txt","w",encoding="utf-8") as f:
                f.write(res.markdown.raw_markdown)
            print("saved, len=", len(res.markdown.raw_markdown))

asyncio.run(main())
