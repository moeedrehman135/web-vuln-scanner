import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class BaseScanner:
    def __init__(self, url, timeout=10):
        # Normalize URL — add https:// if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        
        # Pretend to be a real browser so sites don't block us
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })
        
        self.vulnerabilities = []  # all findings go here

    def get_page(self, url=None):
        """Fetch a page. Returns (response, soup) or (None, None) on error."""
        target = url or self.url
        try:
            response = self.session.get(target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, "html.parser")
            return response, soup
        except requests.exceptions.RequestException as e:
            print(f"  [!] Could not reach {target}: {e}")
            return None, None

    def get_forms(self, url=None):
        """Extract all <form> elements from a page."""
        _, soup = self.get_page(url)
        if not soup:
            return []
        return soup.find_all("form")

    def get_form_details(self, form):
        """Pull action URL, method, and all input fields from a form."""
        details = {}
        action = form.attrs.get("action", "")
        details["action"] = urljoin(self.url, action)
        details["method"] = form.attrs.get("method", "get").lower()
        details["inputs"] = []
        
        for input_tag in form.find_all(["input", "textarea", "select"]):
            details["inputs"].append({
                "type": input_tag.attrs.get("type", "text"),
                "name": input_tag.attrs.get("name"),
                "value": input_tag.attrs.get("value", "")
            })
        
        return details

    def add_vulnerability(self, vuln_type, severity, detail, url=None):
        """Record a found vulnerability."""
        self.vulnerabilities.append({
            "type": vuln_type,
            "severity": severity,       # "HIGH", "MEDIUM", "LOW", "INFO"
            "detail": detail,
            "url": url or self.url
        })
        
        # Color-coded terminal output
        colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", 
                  "LOW": "\033[94m", "INFO": "\033[96m"}
        reset = "\033[0m"
        color = colors.get(severity, "")
        print(f"  {color}[{severity}]{reset} {vuln_type}: {detail}")