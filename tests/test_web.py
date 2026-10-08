"""The web host: access codes, a full question through the real MCP server, feedback,
analyst review, spend limits, and the structured log lines Cloud Logging will receive.

The model is the scripted stand-in from test_agent_loop, so no API key is needed."""

import json

import pytest
from fastapi.testclient import TestClient

from src.agent import web
from tests.test_agent_loop import WORM_INVESTIGATION, ScriptedLLM, text, tool

CODES = {"code-a": "tester-1", "code-b": "tester-2"}
A = {"X-Access-Code": "code-a"}
B = {"X-Access-Code": "code-b"}


def make_client(scripts, **kw):
    scripts = list(scripts)
    app = web.create_app(llm_factory=lambda: ScriptedLLM(scripts.pop(0)),
                         access_codes=CODES, model="scripted", **kw)
    return TestClient(app)


def logged(kind):
    lines = web.EVENTS_LOG.read_text().splitlines() if web.EVENTS_LOG.exists() else []
    return [json.loads(l) for l in lines if json.loads(l)["event"] == kind]


def test_unknown_code_is_refused():
    with make_client([]) as c:
        assert c.post("/api/login", json={"code": "nope"}).status_code == 401
        assert c.get("/api/events").status_code == 401
        assert c.post("/api/login", json={"code": "code-a"}).json() == {"tester": "tester-1"}


def test_app_refuses_to_start_without_codes(monkeypatch):
    monkeypatch.delenv("DA_ACCESS_CODES", raising=False)
    monkeypatch.delenv("DA_ALLOW_NO_AUTH", raising=False)
    with pytest.raises(RuntimeError):
        web.create_app(access_codes={})


def test_parse_access_codes():
    assert web.parse_access_codes("tester-1=a, tester-2=b,junk") == {"a": "tester-1", "b": "tester-2"}


def test_full_question_through_the_web_host():
    with make_client([WORM_INVESTIGATION]) as c:
        sid = c.post("/api/sessions", headers=A).json()["session_id"]
        r = c.post(f"/api/sessions/{sid}/ask", headers=A,
                   json={"question": "Is 10.0.3.57 a worm or a backdoor?"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert "worm" in body["answer"] and body["steps"] == 9
        assert len(body["triages"]) == 1 and body["triages"][0]["severity"] == "critical"
        assert body["guardrail_rejections"] and "without retrieving" in body["guardrail_rejections"][0]

        turn = [t for t in logged("turn") if t["turn_id"] == body["turn_id"]][0]
        assert turn["tester"] == "tester-1" and turn["tool_errors"] == 1
        assert turn["triage_ids"] == [body["triages"][0]["triage_id"]]
        assert turn["input_tokens"] == 900 and turn["latency_ms"] >= 0

        # feedback and review are tied to the tester who got the answer
        fb = {"turn_id": body["turn_id"], "rating": "up", "comment": "clear"}
        assert c.post("/api/feedback", headers=B, json=fb).status_code == 404
        assert c.post("/api/feedback", headers=A, json=fb).status_code == 200
        tri = body["triages"][0]["triage_id"]
        assert c.post("/api/review", headers=A,
                      json={"triage_id": tri, "decision": "reject"}).status_code == 422
        assert c.post("/api/review", headers=A,
                      json={"triage_id": tri, "decision": "approve"}).status_code == 200
        review = [x for x in logged("review") if x["triage_id"] == tri][0]
        assert review["reviewer"] == "tester-1" and review["event_id"] == "EV-10.0.3.57-49200"
        assert any(f["rating"] == "up" and f["turn_id"] == body["turn_id"]
                   for f in logged("feedback"))


def test_sessions_are_private_to_their_tester():
    with make_client([[[text("hi")]]]) as c:
        sid = c.post("/api/sessions", headers=A).json()["session_id"]
        assert c.post(f"/api/sessions/{sid}/ask", headers=B,
                      json={"question": "x"}).status_code == 404


def test_daily_budget_stops_new_questions():
    script = [[text("one")], [text("two")]]
    with make_client([script], daily_token_budget=100) as c:
        sid = c.post("/api/sessions", headers=A).json()["session_id"]
        assert c.post(f"/api/sessions/{sid}/ask", headers=A, json={"question": "a"}).status_code == 200
        r = c.post(f"/api/sessions/{sid}/ask", headers=A, json={"question": "b"})
        assert r.status_code == 429 and "budget" in r.json()["detail"]


def test_session_cap_evicts_idle_sessions():
    with make_client([[], [], []], max_sessions=2) as c:
        ids = [c.post("/api/sessions", headers=A).json()["session_id"] for _ in range(3)]
        assert len(c.app.state.manager.sessions) == 2
        assert ids[0] not in c.app.state.manager.sessions


def test_a_failed_turn_is_logged_and_the_session_survives():
    class Boom(ScriptedLLM):
        async def _create(self, **kw):
            if not self.turns:
                raise RuntimeError("api down")
            return await super()._create(**kw)

    app = web.create_app(llm_factory=lambda: Boom([[tool(1, "list_events", limit=1)]]),
                         access_codes=CODES, model="scripted")
    with TestClient(app) as c:
        sid = c.post("/api/sessions", headers=A).json()["session_id"]
        r = c.post(f"/api/sessions/{sid}/ask", headers=A, json={"question": "what happened?"})
        assert r.status_code == 502
        assert any("api down" in x["error"] for x in logged("turn_failed"))
        session = c.app.state.manager.sessions[sid]
        assert not session.busy


def test_events_panel_and_page():
    with make_client([]) as c:
        ev = c.get("/api/events", headers=A).json()["events"]
        assert ev and ev[0]["event_id"].startswith("EV-")
        assert "Detection Analyst" in c.get("/").text


def test_remote_eval_grades_the_deployed_host():
    import asyncio

    import httpx

    from src.agent.eval_agent import CASES, grade, remote_scenario_meta, run_case_remote
    from src.agent.store import META_PATH

    app = web.create_app(llm_factory=lambda: ScriptedLLM(list(WORM_INVESTIGATION)),
                         access_codes={"eval-code": "eval"}, model="scripted")
    case = next(c for c in CASES if c["id"] == "worm_vs_backdoor")

    async def go():
        transport = httpx.ASGITransport(app=app)
        served = await remote_scenario_meta("http://web", "eval-code", transport=transport)
        turn = await run_case_remote(case, "http://web", "eval-code", transport=transport)
        await app.state.manager.close_all()
        return served, turn

    served, turn = asyncio.run(go())
    assert served == json.loads(META_PATH.read_text())   # the build-match check has data
    result = grade(case, turn)
    assert result["checks"]["called_get_host_activity"]["ok"]
    assert result["checks"]["triage_submitted"]["ok"]
    assert result["checks"]["severity"]["ok"]
