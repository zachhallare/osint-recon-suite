import os
import glob
from playwright.sync_api import sync_playwright

def capture_report():
    reports_dir = os.path.join(os.getcwd(), 'reports')
    # find newest html file
    html_files = glob.glob(os.path.join(reports_dir, '*.html'))
    if not html_files:
        print("No html files found")
        return
    latest_report = max(html_files, key=os.path.getctime)
    print(f"Capturing: {latest_report}")
    
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        page.goto(f'file:///{latest_report}')
        # wait for animations
        page.wait_for_timeout(1000)
        # take screenshot of the top half
        os.makedirs('docs', exist_ok=True)
        page.screenshot(path='docs/sample_report.png')
        browser.close()
        print("Screenshot saved to docs/sample_report.png")

if __name__ == "__main__":
    capture_report()
