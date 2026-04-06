import argparse
import time
import threading
from scanner.headers import HeaderScanner
from scanner.sqli import SQLiScanner
from scanner.xss import XSSScanner

def print_banner():
    print("""
\033[91m
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\033[0m
 \033[93mWeb Vulnerability Scanner v1.0\033[0m  |  For authorized testing only
    """)

def run_scanner(scanner_class, url, results, label):
    """Run a single scanner in its own thread and collect results."""
    scanner = scanner_class(url)
    scanner.scan() if hasattr(scanner, 'scan') else (
        scanner.scan_headers(), scanner.scan_ports()
    )
    results[label] = scanner.vulnerabilities

def print_summary(all_vulns):
    high   = [v for v in all_vulns if v["severity"] == "HIGH"]
    medium = [v for v in all_vulns if v["severity"] == "MEDIUM"]
    low    = [v for v in all_vulns if v["severity"] == "LOW"]
    info   = [v for v in all_vulns if v["severity"] == "INFO"]

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — {len(all_vulns)} issues found")
    print(f"{'='*60}")
    print(f"  \033[91m[HIGH]   {len(high):>3} issue(s)\033[0m")
    print(f"  \033[93m[MEDIUM] {len(medium):>3} issue(s)\033[0m")
    print(f"  \033[94m[LOW]    {len(low):>3} issue(s)\033[0m")
    print(f"  \033[96m[INFO]   {len(info):>3} issue(s)\033[0m")
    print(f"{'='*60}\n")

def main():
    parser = argparse.ArgumentParser(
        description="VulnScan — Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--url", "-u",
        required=True,
        help="Target URL to scan\n  Example: --url http://testphp.vulnweb.com"
    )
    parser.add_argument(
        "--scan", "-s",
        nargs="+",
        choices=["headers", "ports", "sqli", "xss", "all"],
        default=["all"],
        help=(
            "Which scans to run (default: all)\n"
            "  headers  — check security headers\n"
            "  ports    — scan common ports\n"
            "  sqli     — test for SQL injection\n"
            "  xss      — test for XSS\n"
            "  all      — run everything"
        )
    )
    parser.add_argument(
        "--threads", "-t",
        action="store_true",
        help="Run all scans in parallel using threads (faster)"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "html"],
        help="Save report to file (json or html)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )

    args = parser.parse_args()

    print_banner()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scans = args.scan
    run_all = "all" in scans

    print(f"  Target  : {url}")
    print(f"  Scans   : {'all' if run_all else ', '.join(scans)}")
    print(f"  Threads : {'yes' if args.threads else 'no'}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  Output  : {args.output or 'terminal only'}")
    print()

    start_time = time.time()
    all_vulns = []

    if args.threads:
        # --- Threaded mode: all scanners run at the same time ---
        print("[*] Running scans in parallel...\n")
        results = {}
        threads = []

        def run(cls, label, method=None):
            obj = cls(url)
            if method:
                method(obj)
            else:
                obj.scan()
            results[label] = obj.vulnerabilities

        if run_all or "headers" in scans or "ports" in scans:
            def run_header_scanner():
                obj = HeaderScanner(url)
                obj.scan_headers()
                obj.scan_ports()
                results["headers"] = obj.vulnerabilities
            threads.append(threading.Thread(target=run_header_scanner))

        if run_all or "sqli" in scans:
            threads.append(threading.Thread(
                target=lambda: run(SQLiScanner, "sqli")
            ))

        if run_all or "xss" in scans:
            threads.append(threading.Thread(
                target=lambda: run(XSSScanner, "xss")
            ))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for vulns in results.values():
            all_vulns.extend(vulns)

    else:
        # --- Sequential mode: one scan at a time ---
        if run_all or "headers" in scans or "ports" in scans:
            h = HeaderScanner(url)
            h.scan_headers()
            h.scan_ports()
            all_vulns.extend(h.vulnerabilities)

        if run_all or "sqli" in scans:
            s = SQLiScanner(url)
            s.scan()
            all_vulns.extend(s.vulnerabilities)

        if run_all or "xss" in scans:
            x = XSSScanner(url)
            x.scan()
            all_vulns.extend(x.vulnerabilities)

    elapsed = round(time.time() - start_time, 2)
    print(f"\n  Completed in {elapsed}s")

    print_summary(all_vulns)

    # Save report if requested
    if args.output == "json":
        from scanner.reporter import generate_json_report
        import json
        report = generate_json_report(url, all_vulns, elapsed)
        filename = "report.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  [*] JSON report saved → {filename}\n")

    elif args.output == "html":
        from scanner.reporter import generate_html_report
        report_html = generate_html_report(url, all_vulns, elapsed)
        filename = "report.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_html)
        print(f"  [*] HTML report saved → {filename}\n")
        print(f"  Open it with: start {filename}\n")

    return all_vulns

if __name__ == "__main__":
    main()