# -*- coding: utf-8 -*-
import sys, io
sys.stdout.reconfigure(encoding='utf-8')
from pathlib import Path
from crawl4ai.processors.pdf import NaivePDFProcessorStrategy

FILES = {
    "brief": "raw_brief.pdf",
    "catalog": "raw_catalog.pdf",
    "techspec": "raw_techspec.pdf",
    "partnum": "raw_partnum.pdf",
}

strat = NaivePDFProcessorStrategy(extract_images=False, save_images_locally=False)

for name, fname in FILES.items():
    p = Path(fname).resolve()
    try:
        result = strat.process_batch(p)
        text = "\n\n".join((pg.markdown or pg.raw_text or "") for pg in result.pages)
        print(f"{name}: pages={len(result.pages)} chars={len(text)}")
        outp = f"text_{name}.txt"
        with open(outp, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"  saved {outp}")
    except Exception as e:
        print(f"{name}: EXCEPTION {repr(e)}")
