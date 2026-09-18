from pathlib import Path
from playwright.sync_api import sync_playwright

output = Path("docs/screenshots/detectionforge-dashboard.png")
output.parent.mkdir(parents=True, exist_ok=True)
with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    page.goto("http://127.0.0.1:8000", wait_until="networkidle")
    page.screenshot(path=output, full_page=True)
    browser.close()
