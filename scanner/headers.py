from .base import BaseScanner
import socket

class HeaderScanner(BaseScanner):

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "detail": "HSTS missing — browser won't enforce HTTPS connections"
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "detail": "CSP missing — site is wide open to XSS and data injection"
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "detail": "X-Frame-Options missing — site may be vulnerable to clickjacking"
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "detail": "X-Content-Type-Options missing — browser may sniff MIME types"
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "detail": "Referrer-Policy missing — sensitive URLs may leak to third parties"
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "detail": "Permissions-Policy missing — no restrictions on camera/mic/location APIs"
        },
    }

    COMMON_PORTS = {
        21:   "FTP — often allows anonymous login",
        22:   "SSH — brute-force target if exposed",
        23:   "Telnet — unencrypted, should never be open",
        25:   "SMTP — can be abused for spam relay",
        80:   "HTTP — open (expected)",
        443:  "HTTPS — open (expected)",
        3306: "MySQL — database exposed to internet",
        3389: "RDP — Remote Desktop, common ransomware vector",
        5432: "PostgreSQL — database exposed to internet",
        6379: "Redis — often has no auth by default",
        8080: "HTTP-alt — dev server exposed?",
        8443: "HTTPS-alt — check if intentional",
        27017:"MongoDB — database exposed to internet",
    }

    def scan_headers(self):
        print("\n[*] Checking security headers...")
        response, _ = self.get_page()

        # If https fails, try http
        if not response and self.url.startswith("https://"):
            fallback = self.url.replace("https://", "http://")
            print(f"  [*] HTTPS failed, trying {fallback}")
            response, _ = self.get_page(fallback)

        if not response:
            print("  [!] Could not fetch headers — skipping header scan")
            return

        headers = response.headers

        for header, meta in self.SECURITY_HEADERS.items():
            if header not in headers:
                self.add_vulnerability(
                    vuln_type=f"Missing Header: {header}",
                    severity=meta["severity"],
                    detail=meta["detail"]
                )
            else:
                print(f"  \033[92m[OK]\033[0m  {header}: {headers[header][:60]}")

        self._check_cookies(headers)

    def _check_cookies(self, headers):
        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return

        if "httponly" not in set_cookie.lower():
            self.add_vulnerability(
                vuln_type="Cookie Missing HttpOnly",
                severity="MEDIUM",
                detail="Session cookie lacks HttpOnly — JavaScript can steal it"
            )

        if "secure" not in set_cookie.lower():
            self.add_vulnerability(
                vuln_type="Cookie Missing Secure Flag",
                severity="MEDIUM",
                detail="Session cookie lacks Secure flag — can be sent over HTTP"
            )

        if "samesite" not in set_cookie.lower():
            self.add_vulnerability(
                vuln_type="Cookie Missing SameSite",
                severity="LOW",
                detail="Cookie lacks SameSite — vulnerable to CSRF attacks"
            )

    def scan_ports(self, timeout=1):
        from urllib.parse import urlparse
        host = urlparse(self.url).hostname
        print(f"\n[*] Scanning ports on {host}...")

        try:
            ip = socket.gethostbyname(host)
            print(f"  [*] Resolved to {ip}")
        except socket.gaierror:
            print(f"  [!] Could not resolve hostname: {host}")
            return

        for port, description in self.COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    severity = "INFO" if port in (80, 443) else "MEDIUM"
                    self.add_vulnerability(
                        vuln_type=f"Open Port {port}",
                        severity=severity,
                        detail=description
                    )
            except socket.error:
                pass