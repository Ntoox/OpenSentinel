import sys
sys.path.insert(0, '.')

from sacred_gatekeeper_interceptor.interceptor import Interceptor

# Test LOW
interceptor = Interceptor()
result = interceptor.intercept("read_file", {"path": "/tmp/test"})
print(f"LOW Result: {result}")

# Test MEDIUM
result2 = interceptor.intercept("send_email", {"to": "boss@company.com", "subject": "Report"})
print(f"MEDIUM Result: {result2}")