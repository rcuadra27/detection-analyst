"""Public demo mode: anyone can open the demo day, each browser is its own
visitor, uploads need a personal code, and questions are capped per visitor and
per day."""

import pytest
from fastapi.testclient import TestClient

from src.agent import web
from tests.test_agent_loop import ScriptedLLM, text

CODES = {"code-a": "tester-1"}
A = {"X-Access-Code": "code-a"}
V1 = {"X-Access-Code": "public:" + "a" * 24}
V2 = {"X-Access-Code": "public:" + "b" * 24}


def client(tmp_path, public=True, answers=20, **kw):
    from src.agent.uploads import LocalBackend
    backend = LocalBackend(tmp_path / "uploads", 50 * 2**20)
    app = web.create_app(llm_factory=lambda: ScriptedLLM([[text("ok")]] * answers),
                         access_codes=CODES, model="scripted", upload_backend=backend,
                         public_demo=public, **kw)
    return TestClient(app)


def test_public_codes_only_work_when_enabled(tmp_path):
    with client(tmp_path, public=False) as c:
        assert c.post("/api/login", json={"code": V1["X-Access-Code"]}).status_code == 401
        assert c.get("/api/config").json()["public_demo"] is False
    with client(tmp_path) as c:
        r = c.post("/api/login", json={"code": V1["X-Access-Code"]}).json()
        assert r["public"] is True and r["uploads"] is False and r["tester"].startswith("visitor-")
        assert c.post("/api/login", json={"code": "public:not-hex!"}).status_code == 401
        assert c.post("/api/login", json={"code": "public:abc"}).status_code == 401     # too short
        assert c.get("/api/config").json()["public_demo"] is True


def test_visitors_cannot_upload_and_see_no_uploads(tmp_path):
    with client(tmp_path) as c:
        assert c.post("/api/uploads", headers=V1, json={"name": "x.pcap", "size": 10}).status_code == 403
        assert c.get("/api/uploads", headers=V1).json() == {
            "uploads": [], "max_upload_mb": 50, "uploads_enabled": False}
        # a personal code still uploads, and visitors never see it
        ds = c.post("/api/uploads", headers=A, json={"name": "x.pcap", "size": 10}).json()["dataset"]
        assert c.get("/api/uploads", headers=A).json()["uploads_enabled"] is True
        assert c.get("/api/uploads", headers=V1).json()["uploads"] == []
        assert c.post("/api/sessions", headers=V1, json={"dataset": ds}).status_code == 403
        assert c.get(f"/api/events?dataset={ds}", headers=V1).status_code == 404


def test_visitors_get_their_own_chats_and_a_question_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "PUBLIC_QUESTIONS_PER_VISITOR", 2)
    with client(tmp_path) as c:
        s1 = c.post("/api/sessions", headers=V1).json()
        assert s1["questions_left"] == 2
        s2 = c.post("/api/sessions", headers=V2).json()["session_id"]
        assert c.post(f"/api/sessions/{s2}/ask", headers=V1, json={"question": "hi"}).status_code == 404
        sid = s1["session_id"]
        assert c.post(f"/api/sessions/{sid}/ask", headers=V1, json={"question": "hi"}).json()["questions_left"] == 1
        assert c.post(f"/api/sessions/{sid}/ask", headers=V1, json={"question": "hi"}).json()["questions_left"] == 0
        r = c.post(f"/api/sessions/{sid}/ask", headers=V1, json={"question": "hi"})
        assert r.status_code == 429 and "per visitor" in r.json()["detail"]
        # a new chat does not reset the visitor's count, and replaces the old one
        sid2 = c.post("/api/sessions", headers=V1).json()["session_id"]
        assert sid2 != sid and c.post(f"/api/sessions/{sid}/ask", headers=V1,
                                      json={"question": "hi"}).status_code == 404
        assert c.post(f"/api/sessions/{sid2}/ask", headers=V1, json={"question": "hi"}).status_code == 429
        # the other visitor is unaffected
        assert c.post(f"/api/sessions/{s2}/ask", headers=V2, json={"question": "hi"}).status_code == 200


def test_daily_public_cap_and_slot_share(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "PUBLIC_DAILY_QUESTIONS", 1)
    monkeypatch.setattr(web, "PUBLIC_MAX_SESSIONS", 1)
    with client(tmp_path) as c:
        s1 = c.post("/api/sessions", headers=V1).json()["session_id"]
        assert c.post(f"/api/sessions/{s1}/ask", headers=V1, json={"question": "hi"}).status_code == 200
        # the only public slot is idle, so a second visitor takes it over
        s2 = c.post("/api/sessions", headers=V2).json()["session_id"]
        r = c.post(f"/api/sessions/{s2}/ask", headers=V2, json={"question": "hi"})
        assert r.status_code == 429 and "today's question limit" in r.json()["detail"]
        # personal codes are outside the public caps
        sa = c.post("/api/sessions", headers=A).json()["session_id"]
        assert c.post(f"/api/sessions/{sa}/ask", headers=A, json={"question": "hi"}).status_code == 200
