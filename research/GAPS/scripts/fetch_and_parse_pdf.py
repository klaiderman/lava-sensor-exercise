import sys, time
import urllib.request

URLS = {
    "brief": "https://assets.micron.com/adobe/assets/urn:aaid:aem:e71d9e5e-58c1-43cb-94fd-5b0c023e9150/renditions/original/as/7450-nvme-ssd-product-brief.pdf",
    "catalog": "https://assets.micron.com/adobe/assets/urn:aaid:aem:55f2def2-2eda-4480-80a8-6372dacf3ef9/original/as/7450-product-catalog.pdf",
    "techspec": "https://www.micron.com/content/dam/micron/global/public/documents/products/technical-marketing-brief/7450-nvme-ssd-tech-prod-spec.pdf",
    "partnum": "https://www.micron.com/content/dam/micron/global/public/products/part-numbering-guide/numssd.pdf",
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "application/pdf,*/*",
}

for name, url in URLS.items():
    try:
        req = urllib.request.Request(url, headers=headers)
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
        dt = time.time() - t0
        ctype = resp.headers.get("Content-Type")
        is_pdf = data[:4] == b"%PDF"
        print(f"{name}: status={resp.status} ctype={ctype} len={len(data)} is_pdf={is_pdf} time={dt:.2f}s")
        if is_pdf:
            with open(f"raw_{name}.pdf", "wb") as f:
                f.write(data)
            print(f"  saved raw_{name}.pdf")
        else:
            with open(f"raw_{name}.html", "wb") as f:
                f.write(data[:2000])
            print(f"  first bytes: {data[:200]}")
    except Exception as e:
        print(f"{name}: EXCEPTION {repr(e)}")
