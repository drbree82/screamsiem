from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient
from screamsiem.config import Settings
from screamsiem.server import create_app

@pytest.mark.asyncio
async def test_deterministic_demo_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SCREAMSIEM_DEMO","1")
    config=Settings(database=str(tmp_path/"test.db"),internal_secret="internal",approval_secret="approval")
    app=create_app(config)
    for callback in app.router.on_startup:
        await callback()
    try:
        async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as client:
            assert (await client.get("/healthz")).status_code==200
            assert (await client.get("/")).status_code==200
            response=await client.post("/api/demo/trigger")
            assert response.status_code==200
            await __import__('asyncio').sleep(.05)
            findings=(await client.get("/api/findings")).json()
            assert findings and findings[0]["severity"]=="critical"
            assert findings[0]["actions"]
            action=next(a for a in findings[0]["actions"] if a["kind"]=="mcp_action")
            approved=await client.post(f"/api/actions/{action['id']}/approve",headers={"X-CSRF-Token":app.state.screamsiem.csrf})
            assert approved.status_code==200 and approved.json()["state"]=="executed"
            assert any(route.path=="/api/stream" for route in app.routes)
    finally:
        for callback in app.router.on_shutdown:
            await callback()
