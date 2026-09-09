import asyncio, json, time, pathlib
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig
from crawl4ai.processors.pdf import PDFCrawlerStrategy, PDFContentScrapingStrategy

FILES = {
    "brief": "raw_brief.pdf",
    "catalog": "raw_catalog.pdf",
    "techspec": "raw_techspec.pdf",
    "partnum": "raw_partnum.pdf",
}

async def main():
    strat = PDFCrawlerStrategy()
    scrape = PDFContentScrapingStrategy(extract_images=False, save_images_locally=False)
    cfg = CrawlerRunConfig(scraping_strategy=scrape, page_timeout=30000)
    async with AsyncWebCrawler(crawler_strategy=strat) as crawler:
        for name, fname in FILES.items():
            p = pathlib.Path(fname).resolve()
            url = p.as_uri()
            try:
                res = await crawler.arun(url=url, config=cfg)
                ok = res.success
                mdlen = len(res.markdown.raw_markdown) if ok and res.markdown else 0
                print(f"{name}: success={ok} md_len={mdlen} err={getattr(res,'error_message',None)}")
                if ok and res.markdown:
                    outp = f"text_{name}.txt"
                    with open(outp, "w", encoding="utf-8") as f:
                        f.write(res.markdown.raw_markdown)
                    print(f"  saved {outp}")
            except Exception as e:
                print(f"{name}: EXCEPTION {repr(e)}")

asyncio.run(main())
