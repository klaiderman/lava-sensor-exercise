import asyncio, sys, json, time
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig
from crawl4ai.processors.pdf import PDFCrawlerStrategy, PDFContentScrapingStrategy

URLS = [
    "https://www.mouser.com/pdfDocs/7450-product-catalog.pdf",
    "https://www.mouser.com/datasheet/2/671/7450_nvme_ssd_tech_prod_spec-3476020.pdf",
    "https://www.mouser.com/datasheet/2/671/7450_nvme_ssd_product_brief-3498712.pdf",
]

async def main():
    strat = PDFCrawlerStrategy()
    scrape = PDFContentScrapingStrategy(extract_images=False, save_images_locally=False)
    cfg = CrawlerRunConfig(scraping_strategy=scrape, page_timeout=30000)
    async with AsyncWebCrawler(crawler_strategy=strat) as crawler:
        for url in URLS:
            t0 = time.time()
            try:
                res = await crawler.arun(url=url, config=cfg)
                dt = time.time() - t0
                out = {
                    "url": url,
                    "success": res.success,
                    "status_code": getattr(res, "status_code", None),
                    "elapsed_s": round(dt, 2),
                    "error": getattr(res, "error_message", None),
                    "markdown_len": len(res.markdown.raw_markdown) if res.success and res.markdown else 0,
                }
                print("RESULT", json.dumps(out))
                if res.success and res.markdown:
                    fname = "pdf_" + str(abs(hash(url)) % 100000) + ".txt"
                    with open(fname, "w", encoding="utf-8") as f:
                        f.write(res.markdown.raw_markdown)
                    print("SAVED", fname, url)
            except Exception as e:
                print("EXCEPTION", url, repr(e))

asyncio.run(main())
