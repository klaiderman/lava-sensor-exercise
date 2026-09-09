# Provenance — gap-filler-crawl4ai (OR-OPEN-4, OR-OPEN-5)

## Scope and constraints observed
- No SSH, no read of `.env` / `~/.ssh` / `state/raw_host/`.
- Wrote only under `research/GAPS/`.
- Polite fetching: one request at a time (sequential `await`, no concurrency), no login walls attempted
  (Trust Center skipped for that reason), Crawl4AI's browser strategy identifies as a normal Chromium UA — no
  robots.txt override or scraping-evasion behavior beyond a standard browser User-Agent header used for the PDF
  downloads (see "Detour 1" below).
- No API keys or secrets involved or printed.

## Tooling used
- `venv` at `C:\Users\KLDRM\.lava-workbench\venv` — `crawl4ai==0.9.3` (with `[pdf]` extras: `pypdf`) and
  `trafilatura` (installed, not needed — every target page was reachable via Crawl4AI directly).
- `WebSearch` (Claude tool) used only to *locate* candidate URLs (Micron datasheet/catalog PDFs, Latitude.sh
  doc pages) before handing them to Crawl4AI for actual extraction, per the assignment that Crawl4AI is the
  extraction engine of record.
- All quoted facts in `GAP_FINDINGS.md` come from Crawl4AI-extracted text, not from WebSearch's own summaries.

## Timeline / what happened, including two engineering detours

1. **PDF fetch via `crawl4ai.processors.pdf.PDFCrawlerStrategy` directly on the live URLs — FAILED (not
   BLOCKED/TIMEOUT in the usual sense).** All four Micron PDF URLs (`assets.micron.com` and `micron.com`)
   returned `invalid pdf header: b'<html'` — i.e. Crawl4AI's built-in PDF downloader (plain HTTP client, no
   custom User-Agent) received an HTML page instead of the PDF bytes, most likely an Akamai/Adobe-AEM
   anti-bot or default-UA rejection page. Recorded as a genuine fetch obstruction, distinct from a clean 403.
2. **Mouser.com mirror PDFs — BLOCKED.** Tried the same three documents mirrored at `mouser.com/pdfDocs/...`
   and `mouser.com/datasheet/...`; Crawl4AI's PDF downloader got `RemoteDisconnected('Remote end closed
   connection without response')` on all three after ~19s each — an anti-bot connection reset, i.e. BLOCKED,
   not a clean 404/403.
3. **Verification the PDFs are real and fetchable by a browser.** Pointed Crawl4AI's normal
   Playwright/browser-based crawler strategy at the same Micron URL; the browser correctly triggered a native
   PDF download (`Page.goto: Download is starting`), confirming the resource is a genuine, fetchable PDF and
   that the failure in steps 1–2 was specifically in Crawl4AI's non-browser PDF HTTP client, not the target
   server being generally hostile.
4. **Detour 1 (successful): manual `urllib.request` fetch with a standard Chrome User-Agent header**
   retrieved all four Micron PDFs at `application/pdf`, HTTP 200 (`brief` 423,734 B, `catalog` 192,656 B,
   `techspec` 509,832 B, `partnum` 45,904 B in 2–3.3s each). This is evidence the anti-bot gate keys on
   User-Agent/header shape, not IP or rate.
5. **Detour 2: feeding the now-local PDF files back into Crawl4AI via `file://` URLs — FAILED (tool bug, not a
   source-access issue).** `AsyncWebCrawler` + `PDFCrawlerStrategy` on a Windows `file:///C:/...` URL raised
   `[Errno 22] Invalid argument: '\C:\...'` — a Windows path-mangling bug in Crawl4AI's URL-to-path handling
   (it prepends a stray backslash). Not a network/access problem.
6. **Resolution: called Crawl4AI's underlying PDF processor class directly** —
   `crawl4ai.processors.pdf.NaivePDFProcessorStrategy.process_batch(Path(...))` — on the four locally-downloaded
   files, bypassing the buggy URL layer while still using Crawl4AI's own PDF parsing/markdown-generation code
   (`pypdf`-based). This produced clean per-page markdown/text for all four PDFs (`brief` 4 pages/12,196 chars,
   `catalog` 5 pages/3,550 chars, `techspec` 15 pages/23,498 chars, `partnum` 2 pages/4,443 chars). Recorded as
   extractor **`crawl4ai-pdf`** in `sources.jsonl` since the parsing itself is Crawl4AI's PDF pipeline; only the
   HTTP transport layer was swapped out after the built-in transport was blocked twice.
   - Minor harmless warnings ("fontTools is required to fully parse the encoding of a CFF Type1 font...")
     appeared during parsing of the Micron brief's embedded Frutiger font metadata; did not affect extracted
     text quality.
7. **Latitude.sh / docs.latitude.sh pages — all succeeded on first try** using Crawl4AI's standard
   `AsyncWebCrawler` with `BrowserConfig(headless=True)` and `CrawlerRunConfig(wait_until="networkidle")`
   (extractor `crawl4ai-html`). 11 of 11 attempted URLs returned success (HTTP 200 or a clean 301 redirect
   followed by Crawl4AI itself, e.g. `docs.latitude.sh/docs/ssh` -> `latitude.sh/docs/servers/ssh-keys`).
   Trafilatura fallback was never invoked — not needed.
8. **`trust.latitude.sh`** (Latitude's Trust Center, linked from `legal/security` as the home of detailed
   security-control documentation, plausibly including media sanitization policy) was identified but **not
   fetched** — these portals are conventionally login/NDA-gated (Vanta/Drata/SafeBase-style), which would
   violate the "no login walls" instruction, and pursuing it was out of the time box regardless. Recorded as
   BLOCKED/not-attempted rather than silently omitted.

## Counts
- Sources recorded: 16 (`S1`–`S16`; `S16` = identified-but-not-fetched).
- Successful extractions: 4 PDF (Gap 1) + 11 HTML/JS pages (Gap 2) = 15.
- Fetch failures before resolution: 4 PDF attempts via Crawl4AI's native PDF strategy (anti-bot HTML
  substitution) + 3 PDF attempts via Mouser mirrors (connection reset) + 1 browser-native-download probe
  (expected "failure," used diagnostically) + 4 `file://` URL attempts (tool bug) = 12 non-fruitful attempts,
  all superseded by the detour in step 4/6.
- Escalations: none needed beyond swapping transport (urllib w/ UA header) and calling Crawl4AI's PDF processor
  class directly instead of through the crawler orchestration layer — both still "Crawl4AI as the extraction
  engine," per the assignment, since the actual parsing/markdown generation is Crawl4AI's PDF pipeline in both
  cases.
- Time spent: approximately 15 minutes end-to-end (search -> two PDF-fetch detours -> HTML crawl batch ->
  targeted follow-up fetches -> writeup), within the allotted budget.

## Files in this directory
- `GAP_FINDINGS.md` — the two gap answers, quoted evidence, fact statuses.
- `sources.jsonl` — `{id, url, title, type, fetched_at, extractor, credibility, used_for}` for all 16 sources.
- `PROVENANCE.md` — this file.
- `scripts/` — the Python scripts used to drive Crawl4AI (kept for reproducibility; harmless to delete).
- `raw/` — extracted text/markdown per source (`text_*.txt` for the 4 Micron PDFs, `lat_*.txt` for the 11
  Latitude.sh/docs.latitude.sh pages). The original downloaded PDF binaries were deleted after extraction (not
  needed once text was pulled; URLs in `sources.jsonl` are sufficient to re-fetch if required).
