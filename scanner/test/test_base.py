from scanner.base import BaseScanner

s = BaseScanner("example.com")
resp, soup = s.get_page()
print(resp.status_code)   # should print 200
print(soup.title.text)    # should print the page title