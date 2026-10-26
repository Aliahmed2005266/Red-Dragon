import warnings
warnings.filterwarnings("ignore")
from flask import Flask
import server_extensions

app = Flask(__name__)
server_extensions.register_extensions(app)
client = app.test_client()

# Validation path
r = client.post("/api/source/fetch", json={})
print("empty url ->", r.status_code, r.get_json()["error"])

# Monkeypatch requests.get to test analysis without network
import requests

html = """<html><head><meta name="generator" content="WordPress 5.2"></head><body>
<script>var api_key = "AKIAIOSFODNN7EXAMPLE";</script>
<!-- TODO: remove debug password=admin123 -->
<img src="http://insecure.example.com/a.png">
<iframe src="x"></iframe><input type="password" name="pw">
<a href="/about">About</a><a href="mailto:admin@corp.com">mail</a>
</body></html>"""


class FakeResp:
    text = html
    headers = {"Server": "nginx"}
    url = "https://test.com"
    status_code = 200
    reason = "OK"
    elapsed = None


orig = requests.get
requests.get = lambda *a, **k: FakeResp()
r = client.post("/api/source/fetch", json={"url": "https://test.com"})
requests.get = orig

d = r.get_json()
print("fetch ->", r.status_code, "status:", d["status_code"], "size:", d["total_size"])
a = d["analysis"]
print("technologies:", a["technologies"])
for i in a["issues"]:
    print("  ", i["severity"], "|", i["title"])
print("links:", a["links"])
print("emails:", a["emails"])
