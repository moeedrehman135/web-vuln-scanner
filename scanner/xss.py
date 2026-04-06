from .base import BaseScanner

class XSSScanner(BaseScanner):

    # Each payload tries to inject a script tag in a different way
    PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "'><script>alert('XSS')</script>",
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<body onload=alert("XSS")>',
    ]

    def scan(self):
        print("\n[*] Testing for XSS...")
        forms = self.get_forms()

        if not forms:
            print("  [*] No forms found on this page")
            return

        print(f"  [*] Found {len(forms)} form(s) — injecting XSS payloads...")

        for i, form in enumerate(forms):
            details = self.get_form_details(form)
            print(f"\n  [*] Testing form {i+1}: {details['action']}")
            self._test_form(details)

    def _test_form(self, details):
        for payload in self.PAYLOADS:
            data = {}
            for input_field in details["inputs"]:
                if input_field["type"] in ("hidden", "submit"):
                    data[input_field["name"]] = input_field["value"]
                elif input_field["name"]:
                    data[input_field["name"]] = payload

            try:
                if details["method"] == "post":
                    response = self.session.post(
                        details["action"], data=data, timeout=self.timeout
                    )
                else:
                    response = self.session.get(
                        details["action"], params=data, timeout=self.timeout
                    )

                # If the payload appears unescaped in the response, it's reflected XSS
                if payload in response.text:
                    self.add_vulnerability(
                        vuln_type="Reflected XSS",
                        severity="HIGH",
                        detail=f"Payload reflected unescaped: {payload[:50]}",
                        url=details["action"]
                    )
                    return  # Confirmed, move to next form

            except Exception as e:
                print(f"  [!] Request failed: {e}")