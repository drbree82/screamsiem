from __future__ import annotations
import sys,time,urllib.request
url=sys.argv[1]
for _ in range(50):
    try:
        if urllib.request.urlopen(url,timeout=1).status==200: raise SystemExit(0)
    except Exception: time.sleep(.2)
raise SystemExit("server did not become ready")
