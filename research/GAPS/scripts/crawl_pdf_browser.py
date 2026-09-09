import asyncio, json, time
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, BrowserConfig

URLS = [
    "https://assets.micron.com/adobe/assets/urn:aaid:aem:e71d9e5e-58c1-43cb-94fd-5b0c023e9150/renditions/original/as/7450-nvme-ssd-product-brief.pdf",
]

async def main():
    bcfg = BrowserConfig(headless=True)
    cfg = CrawlerRunConfig(page_timeout=25000)
    async with AsyncWebCrawler(config=bcfg) as crawler:
        for url in URLS:
            t0 = time.time()
            try:
                res = await crawler.arun(url=url, config=cfg)
                dt = time.time() - t0
                print("RESULT", json.dumps({
                    "url": url, "success": res.success, "elapsed_s": round(dt,2),
                    "error": getattr(res, "error_message", None),
                    "md_len": len(res.markdown.raw_markdown) if res.success and res.markdown else 0,
                }))
                if res.success and res.markdown:
                    with open("pdf_browser_out.txt", "w", encoding="utf-8") as f:
                        f.write(res.markdown.raw_markdown)
                    print("SAVED pdf_browser_out.txt")
            except Exception as e:
                print("EXCEPTION", url, repr(e))

asyncio.run(main())
