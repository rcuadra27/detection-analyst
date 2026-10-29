"""Web host for the investigation agent: the same Agent and MCP server, behind a URL.

    DA_ACCESS_CODES="tester-1=apple-river,tester-2=stone-cloud" \
        uvicorn src.agent.web:app --port 8080

What changes from the CLI, and what does not:
  - The agent loop (cli.Agent), the MCP server, the tools and their guardrails are
    unchanged. This module is only a different HOST: it starts one MCP server
    subprocess per chat session, exactly as cli.py does for one terminal.
  - Testers reach the agent through a small chat page. Each tester has a personal
    access code; logs carry the tester label, never a name.
  - Every question, piece of feedback and review decision is written as one JSON
    line to stdout. On Cloud Run that lands in Cloud Logging, from where it can be
    routed to BigQuery. The local files under logs/ are a convenience copy only:
    a Cloud Run instance's disk does not survive a restart.
  - Spend is capped in code: a daily token budget, a question cap per session,
    and a cap on concurrent sessions.
  - Testers can upload a pcap of up to DA_MAX_UPLOAD_MB (2 GB by default). The
    file never passes through this app on Cloud Run: the browser puts it straight
    into a bucket with a signed URL, and a Cloud Run Job scores it (Zeek features,
    the trained detector, a baseline estimated from the capture). Chats started on
    an upload read its store. Uploads are private to the tester who sent them.
    See src/agent/uploads.py.

Run ONE worker process: sessions live in memory.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hmac
import json
import os
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from src.agent.cli import DEFAULT_MODEL, LOG_DIR, REPO_ROOT, Agent, AgentTurn, connect_mcp
from src.agent.uploads import LocalBackend, backend_from_env

STATIC_DIR = Path(__file__).resolve().parent / "web_static"
EVENTS_LOG = LOG_DIR / "web_events.jsonl"
REVIEWS_PATH = LOG_DIR / "reviews.jsonl"

MAX_SESSIONS = int(os.environ.get("DA_MAX_SESSIONS", "6"))
SESSION_IDLE_SECONDS = int(os.environ.get("DA_SESSION_IDLE_SECONDS", "1800"))
MAX_QUESTIONS_PER_SESSION = int(os.environ.get("DA_MAX_QUESTIONS_PER_SESSION", "25"))
DAILY_TOKEN_BUDGET = int(os.environ.get("DA_DAILY_TOKEN_BUDGET", "5000000"))
MAX_QUESTION_CHARS = 2000
MAX_UPLOADS_PER_TESTER = int(os.environ.get("DA_MAX_UPLOADS_PER_TESTER", "5"))
MAX_UPLOAD_NAME = 80
MAX_LOGGED_ANSWER_CHARS = 4000


# ------------------------------------------------------------------ logging

def log_event(kind: str, severity: str = "INFO", **fields) -> None:
    """One structured line per event. Cloud Run turns JSON on stdout into jsonPayload."""
    entry = {"severity": severity, "message": kind, "event": kind,
             "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **fields}
    line = json.dumps(entry, default=str)
    print(line, flush=True)
    try:
        EVENTS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS_LOG.open("a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass   # the stdout copy is the one that matters


# ------------------------------------------------------------------ access

def parse_access_codes(raw: str | None) -> dict[str, str]:
    """'tester-1=code-a,tester-2=code-b' -> {'code-a': 'tester-1', ...}"""
    codes: dict[str, str] = {}
    for part in (raw or "").split(","):
        if "=" not in part:
            continue
        label, code = (s.strip() for s in part.split("=", 1))
        if label and code:
            codes[code] = label
    return codes


class AccessControl:
    def __init__(self, codes: dict[str, str], allow_open: bool = False):
        self.codes = codes
        self.allow_open = allow_open

    def tester(self, code: str | None) -> str:
        if self.allow_open and not self.codes:
            return "local"
        for known, label in self.codes.items():
            if code and hmac.compare_digest(code.encode(), known.encode()):
                return label
        raise HTTPException(status_code=401, detail="Unknown access code.")


# ------------------------------------------------------------------ budget

class DailyBudget:
    """Tokens processed per UTC day: uncached input, cache reads and writes, and output.

    Cache reads count in full even though they are billed at a fraction, so the cap
    stays conservative. Resets with the day or a restart."""

    def __init__(self, limit: int):
        self.limit = limit
        self.day = dt.datetime.now(dt.timezone.utc).date()
        self.used = 0

    def _roll(self) -> None:
        today = dt.datetime.now(dt.timezone.utc).date()
        if today != self.day:
            self.day, self.used = today, 0

    def exhausted(self) -> bool:
        self._roll()
        return self.used >= self.limit

    def add(self, tokens: int) -> None:
        self._roll()
        self.used += tokens

    def status(self) -> dict:
        self._roll()
        return {"day": str(self.day), "used": self.used, "limit": self.limit,
                "remaining": max(0, self.limit - self.used)}


# ------------------------------------------------------------------ sessions

class ChatSession:
    """One conversation: an Agent plus its own MCP server subprocess.

    The MCP client must be opened and closed by the same task, so each session runs
    in one long-lived worker task and receives questions through a queue."""

    def __init__(self, session_id: str, tester: str, llm, model: str,
                 scenario_dir: Path | None = None):
        self.id = session_id
        self.tester = tester
        self.scenario_dir = scenario_dir
        self.llm = llm
        self.model = model
        self.queue: asyncio.Queue = asyncio.Queue()
        self.ready = asyncio.Event()
        self.start_error: str | None = None
        self.progress: list[str] = []
        self.busy = False
        self.questions = 0
        self.last_used = time.monotonic()
        self.task: asyncio.Task | None = None

    def _on_event(self, kind: str, detail: str) -> None:
        label = {"thinking": "Thinking", "tool": "Calling", "tool_error": "Guardrail rejected",
                 "retry": "Retrying"}.get(kind, kind)
        self.progress.append(f"{label}: {detail}")

    async def run(self) -> None:
        try:
            async with connect_mcp(self.id, self.scenario_dir) as mcp_session:
                agent = Agent(mcp_session, self.llm, model=self.model, session_id=self.id,
                              on_event=self._on_event)
                await agent.setup()
                self.ready.set()
                while True:
                    item = await self.queue.get()
                    if item is None:
                        break
                    question, fut = item
                    before = len(agent.messages)
                    try:
                        fut.set_result(await agent.ask(question))
                    except Exception as exc:
                        del agent.messages[before:]   # keep the conversation valid for the next turn
                        if not fut.done():
                            fut.set_exception(exc)
        except (Exception, SystemExit) as exc:
            self.start_error = f"{type(exc).__name__}: {exc}"
            log_event("session_error", severity="ERROR", session=self.id,
                      tester=self.tester, error=self.start_error)
        finally:
            self.ready.set()
            while not self.queue.empty():   # fail anything still waiting
                item = self.queue.get_nowait()
                if item is not None and not item[1].done():
                    item[1].set_exception(RuntimeError("session closed"))

    async def ask(self, question: str) -> AgentTurn:
        await self.ready.wait()
        if self.start_error or self.task is None or self.task.done():
            raise RuntimeError(f"The tools server for this session is not running "
                               f"({self.start_error or 'stopped'}).")
        fut = asyncio.get_running_loop().create_future()
        await self.queue.put((question, fut))
        return await fut

    async def close(self) -> None:
        if self.task and not self.task.done():
            await self.queue.put(None)
            try:
                await asyncio.wait_for(self.task, timeout=10)
            except asyncio.TimeoutError:
                self.task.cancel()


class SessionManager:
    def __init__(self, llm_factory, model: str, max_sessions: int = MAX_SESSIONS,
                 idle_seconds: int = SESSION_IDLE_SECONDS):
        self.llm_factory = llm_factory
        self.model = model
        self.max_sessions = max_sessions
        self.idle_seconds = idle_seconds
        self.sessions: dict[str, ChatSession] = {}

    async def create(self, tester: str, scenario_dir: Path | None = None,
                     dataset: str | None = None) -> ChatSession:
        if len(self.sessions) >= self.max_sessions:
            idle = [s for s in self.sessions.values() if not s.busy]
            if not idle:
                raise HTTPException(503, "All chat slots are busy. Try again in a minute.")
            await self.end(min(idle, key=lambda s: s.last_used).id, reason="evicted")
        s = ChatSession(f"web-{uuid.uuid4().hex[:10]}", tester, self.llm_factory(), self.model,
                        scenario_dir)
        s.task = asyncio.create_task(s.run())
        self.sessions[s.id] = s
        await s.ready.wait()
        if s.start_error:
            self.sessions.pop(s.id, None)
            raise HTTPException(500, "The tools server failed to start. See the logs.")
        log_event("session_start", session=s.id, tester=tester, model=self.model,
                  dataset=dataset or "demo")
        return s

    def get(self, session_id: str, tester: str) -> ChatSession:
        s = self.sessions.get(session_id)
        if s is None or s.tester != tester:
            raise HTTPException(404, "Session not found or expired. Start a new chat.")
        return s

    async def end(self, session_id: str, reason: str) -> None:
        s = self.sessions.pop(session_id, None)
        if s:
            await s.close()
            log_event("session_end", session=s.id, tester=s.tester, reason=reason,
                      questions=s.questions)

    async def reap_idle(self) -> None:
        now = time.monotonic()
        for s in list(self.sessions.values()):
            if not s.busy and now - s.last_used > self.idle_seconds:
                await self.end(s.id, reason="idle")

    async def close_all(self) -> None:
        for sid in list(self.sessions):
            await self.end(sid, reason="shutdown")


# ------------------------------------------------------------------ turn summaries

def summarize_turn(turn: AgentTurn) -> dict:
    """What the page shows and what the logs record about one answered question."""
    triages, rejections = [], []
    for c in turn.tool_calls:
        if c["name"] != "submit_triage":
            continue
        try:
            result = json.loads(c["result"])
        except (json.JSONDecodeError, TypeError):
            result = {}
        if c["is_error"]:
            rejections.extend(result.get("errors") or [c["result"][:300]])
        elif result.get("accepted"):
            # Prefer what was actually queued: fields the model wrote inside its
            # explanation are recovered server-side and appear only in the result.
            inp = {**(c["input"] or {}), **(result.get("triage") or {})}
            triages.append({"triage_id": result.get("triage_id"),
                            "event_id": inp.get("event_id"),
                            "severity": inp.get("severity"),
                            "assessment": inp.get("assessment"),
                            "attack_technique_ids": inp.get("attack_technique_ids") or [],
                            "confidence": inp.get("confidence"),
                            "explanation": inp.get("explanation"),
                            "recommended_action": inp.get("recommended_action"),
                            "status": result.get("status")})
    return {"triages": triages, "guardrail_rejections": rejections,
            "tool_errors": sum(1 for c in turn.tool_calls if c["is_error"])}


# ------------------------------------------------------------------ request bodies

class UploadBody(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    size: int


class SessionBody(BaseModel):
    dataset: str | None = None


class AskBody(BaseModel):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)


class FeedbackBody(BaseModel):
    turn_id: str
    rating: str = Field(pattern="^(up|down)$")
    comment: str = Field(default="", max_length=2000)


class ReviewBody(BaseModel):
    triage_id: str
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(default="", max_length=2000)


class LoginBody(BaseModel):
    code: str


# ------------------------------------------------------------------ app

def _default_llm_factory():
    from anthropic import AsyncAnthropic
    return AsyncAnthropic(timeout=120.0, max_retries=2)


def create_app(llm_factory=None, access_codes: dict[str, str] | None = None,
               model: str = DEFAULT_MODEL, daily_token_budget: int = DAILY_TOKEN_BUDGET,
               max_sessions: int = MAX_SESSIONS, upload_backend=None) -> FastAPI:
    os.chdir(REPO_ROOT)
    codes = parse_access_codes(os.environ.get("DA_ACCESS_CODES")) if access_codes is None \
        else access_codes
    allow_open = os.environ.get("DA_ALLOW_NO_AUTH") == "1"
    if not codes and not allow_open:
        raise RuntimeError("Set DA_ACCESS_CODES (or DA_ALLOW_NO_AUTH=1 for local use only).")

    access = AccessControl(codes, allow_open)
    budget = DailyBudget(daily_token_budget)
    manager = SessionManager(llm_factory or _default_llm_factory, model, max_sessions)
    turns: dict[str, dict] = {}       # turn_id -> {session, tester}
    triages: dict[str, dict] = {}     # triage_id -> {session, tester, event_id}

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async def reaper():
            while True:
                await asyncio.sleep(60)
                await manager.reap_idle()
        task = asyncio.create_task(reaper())
        log_event("app_start", model=model, testers=sorted(set(codes.values())),
                  daily_token_budget=daily_token_budget)
        yield
        task.cancel()
        await manager.close_all()

    app = FastAPI(title="Detection Analyst", lifespan=lifespan, docs_url=None, redoc_url=None)

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/api/login")
    def login(body: LoginBody):
        return {"tester": access.tester(body.code)}

    uploads = upload_backend if upload_backend is not None else backend_from_env()

    def owned(ds_id: str, tester: str, need_done: bool = False) -> dict:
        rec = uploads.read_status(ds_id) if ds_id.startswith("up-") else None
        if rec is None or rec.get("tester") != tester:
            raise HTTPException(404, "Unknown upload.")
        if need_done and rec.get("state") != "done":
            raise HTTPException(409, "That upload is not scored yet.")
        return rec

    @app.get("/api/events")
    def events(dataset: str | None = None, x_access_code: str | None = Header(default=None)):
        tester = access.tester(x_access_code)
        if dataset:
            owned(dataset, tester, need_done=True)
            return _events_panel(uploads.local_store(dataset))
        return _events_panel()

    @app.get("/api/uploads")
    def list_uploads(x_access_code: str | None = Header(default=None)):
        tester = access.tester(x_access_code)
        mine = [_public(r) for r in uploads.list_status() if r.get("tester") == tester]
        return {"uploads": sorted(mine, key=lambda r: r.get("created", ""), reverse=True),
                "max_upload_mb": uploads.max_bytes // 2**20}

    @app.post("/api/uploads")
    def create_upload(body: UploadBody, x_access_code: str | None = Header(default=None)):
        """Step 1: register an upload and get somewhere to put the file."""
        tester = access.tester(x_access_code)
        if body.size > uploads.max_bytes:
            raise HTTPException(413, f"Captures are limited to {uploads.max_bytes // 2**20} MB.")
        if body.size <= 0:
            raise HTTPException(422, "The file is empty.")
        active = [r for r in map(_public, uploads.list_status())
                  if r.get("tester") == tester and r.get("state") != "error"]
        if len(active) >= MAX_UPLOADS_PER_TESTER:
            raise HTTPException(429, f"Upload limit reached ({MAX_UPLOADS_PER_TESTER} per tester).")
        ds_id = f"up-{uuid.uuid4().hex[:10]}"
        rec = {"dataset": ds_id, "tester": tester, "name": Path(body.name).name[:MAX_UPLOAD_NAME],
               "size": body.size, "state": "waiting_upload", "created": _utcnow(),
               "updated": _utcnow()}
        uploads.write_status(ds_id, rec)
        log_event("upload_created", tester=tester, dataset=ds_id, name=rec["name"], bytes=body.size)
        return {"dataset": ds_id, "upload": uploads.upload_target(ds_id)}

    @app.put("/api/uploads/{ds_id}/data")
    async def upload_data(ds_id: str, request: Request,
                          x_access_code: str | None = Header(default=None)):
        """Step 2, local backend only: the file itself, streamed to disk.
        (On Cloud Run the browser sends it straight to the bucket instead.)"""
        tester = access.tester(x_access_code)
        rec = owned(ds_id, tester)
        if not isinstance(uploads, LocalBackend):
            raise HTTPException(404, "Upload the file to the signed URL.")
        if rec.get("state") != "waiting_upload":
            raise HTTPException(409, "This upload already has its file.")
        dest = uploads.pcap_path(ds_id)
        size = 0
        with dest.open("wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > uploads.max_bytes:
                    fh.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(413, f"Captures are limited to {uploads.max_bytes // 2**20} MB.")
                fh.write(chunk)
        return {"ok": True, "bytes": size}

    @app.post("/api/uploads/{ds_id}/abandon")
    def abandon_upload(ds_id: str, x_access_code: str | None = Header(default=None)):
        """The page could not send the file: close the record so it does not linger
        or count against the tester's limit."""
        tester = access.tester(x_access_code)
        rec = owned(ds_id, tester)
        if rec.get("state") != "waiting_upload":
            raise HTTPException(409, f"This upload is already {rec.get('state')}.")
        uploads.delete_pcap(ds_id)
        rec = uploads.update_status(ds_id, state="error",
                                    message="The file transfer did not complete.")
        log_event("upload_failed", severity="WARNING", tester=tester, dataset=ds_id,
                  message=rec["message"])
        return _public(rec)

    @app.post("/api/uploads/{ds_id}/start")
    def start_upload(ds_id: str, x_access_code: str | None = Header(default=None)):
        """Step 3: the file is in place; score it."""
        tester = access.tester(x_access_code)
        rec = owned(ds_id, tester)
        if rec.get("state") != "waiting_upload":
            raise HTTPException(409, f"This upload is already {rec.get('state')}.")
        uploads.update_status(ds_id, state="queued", stage="waiting for the scoring job")
        try:
            uploads.start(ds_id)
        except Exception as exc:
            uploads.update_status(ds_id, state="error", stage=None,
                                  message="The scoring job could not be started.")
            log_event("upload_failed", severity="ERROR", tester=tester, dataset=ds_id,
                      error=f"{type(exc).__name__}: {exc}"[:2000])
            raise HTTPException(502, "The scoring job could not be started.")
        log_event("upload_started", tester=tester, dataset=ds_id)
        return _public(uploads.read_status(ds_id))

    @app.get("/api/uploads/{ds_id}")
    def upload_status(ds_id: str, x_access_code: str | None = Header(default=None)):
        """Step 4: poll until state is done or error."""
        rec = owned(ds_id, access.tester(x_access_code))
        if rec.get("state") in ("done", "error") and not rec.get("logged"):
            log_event("upload_done" if rec["state"] == "done" else "upload_failed",
                      severity="INFO" if rec["state"] == "done" else "ERROR",
                      tester=rec["tester"], dataset=ds_id, name=rec.get("name"),
                      summary=rec.get("summary"), message=rec.get("message"))
            uploads.update_status(ds_id, logged=True)
        return _public(rec)

    @app.post("/api/sessions")
    async def new_session(body: SessionBody | None = None,
                          x_access_code: str | None = Header(default=None)):
        tester = access.tester(x_access_code)
        dataset = body.dataset if body else None
        scenario_dir = None
        if dataset:
            owned(dataset, tester, need_done=True)
            scenario_dir = uploads.local_store(dataset)
        s = await manager.create(tester, scenario_dir, dataset)
        return {"session_id": s.id, "questions_left": MAX_QUESTIONS_PER_SESSION,
                "dataset": dataset}

    @app.get("/api/sessions/{session_id}/progress")
    def progress(session_id: str, x_access_code: str | None = Header(default=None)):
        s = manager.get(session_id, access.tester(x_access_code))
        return {"busy": s.busy, "progress": s.progress[-12:]}

    @app.post("/api/sessions/{session_id}/ask")
    async def ask(session_id: str, body: AskBody,
                  x_access_code: str | None = Header(default=None)):
        tester = access.tester(x_access_code)
        s = manager.get(session_id, tester)
        if s.busy:
            raise HTTPException(409, "Still working on the previous question.")
        if s.questions >= MAX_QUESTIONS_PER_SESSION:
            raise HTTPException(429, "This chat hit its question limit. Start a new chat.")
        if budget.exhausted():
            log_event("budget_exhausted", severity="WARNING", tester=tester, **budget.status())
            raise HTTPException(429, "The daily usage budget is used up. Try again tomorrow.")

        s.busy, s.progress = True, []
        s.questions += 1
        s.last_used = time.monotonic()
        turn_id = f"turn-{uuid.uuid4().hex[:10]}"
        started = time.perf_counter()
        try:
            turn = await s.ask(body.question)
        except Exception as exc:
            log_event("turn_failed", severity="ERROR", session=s.id, tester=tester,
                      turn_id=turn_id, question=body.question,
                      error=f"{type(exc).__name__}: {exc}",
                      latency_ms=round((time.perf_counter() - started) * 1000))
            raise HTTPException(502, "The agent failed on this question. It was logged; "
                                     "try rephrasing or start a new chat.")
        finally:
            s.busy = False
            s.last_used = time.monotonic()

        latency_ms = round((time.perf_counter() - started) * 1000)
        budget.add(sum(turn.usage.values()))
        summary = summarize_turn(turn)
        turns[turn_id] = {"session": s.id, "tester": tester}
        for t in summary["triages"]:
            if t["triage_id"]:
                triages[t["triage_id"]] = {"session": s.id, "tester": tester,
                                           "event_id": t["event_id"], "turn_id": turn_id}
        log_event("turn", session=s.id, tester=tester, turn_id=turn_id, model=s.model,
                  question=body.question, answer=turn.answer[:MAX_LOGGED_ANSWER_CHARS],
                  latency_ms=latency_ms, steps=turn.steps, hit_step_cap=turn.hit_step_cap,
                  input_tokens=turn.usage["input_tokens"],
                  cache_read_input_tokens=turn.usage["cache_read_input_tokens"],
                  cache_creation_input_tokens=turn.usage["cache_creation_input_tokens"],
                  output_tokens=turn.usage["output_tokens"],
                  tools=[c["name"] for c in turn.tool_calls],
                  tool_errors=summary["tool_errors"],
                  guardrail_rejections=summary["guardrail_rejections"],
                  triage_ids=[t["triage_id"] for t in summary["triages"]],
                  stop_reasons=turn.stop_reasons, recoveries=turn.recoveries)
        return {"turn_id": turn_id, "answer": turn.answer, "steps": turn.steps,
                "latency_ms": latency_ms, "usage": turn.usage,
                "hit_step_cap": turn.hit_step_cap, "stop_reasons": turn.stop_reasons,
                "recoveries": turn.recoveries, "tool_calls": turn.tool_calls,
                "questions_left": MAX_QUESTIONS_PER_SESSION - s.questions, **summary}

    @app.post("/api/feedback")
    def feedback(body: FeedbackBody, x_access_code: str | None = Header(default=None)):
        tester = access.tester(x_access_code)
        t = turns.get(body.turn_id)
        if t is None or t["tester"] != tester:
            raise HTTPException(404, "Unknown answer.")
        log_event("feedback", tester=tester, session=t["session"], turn_id=body.turn_id,
                  rating=body.rating, comment=body.comment)
        return {"ok": True}

    @app.post("/api/review")
    def review(body: ReviewBody, x_access_code: str | None = Header(default=None)):
        tester = access.tester(x_access_code)
        t = triages.get(body.triage_id)
        if t is None or t["tester"] != tester:
            raise HTTPException(404, "Unknown triage.")
        if body.decision == "reject" and not body.reason.strip():
            raise HTTPException(422, "Say why you are rejecting it.")
        record = {"triage_id": body.triage_id, "decision": body.decision,
                  "reason": body.reason, "reviewer": tester, **t,
                  "reviewed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        REVIEWS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with REVIEWS_PATH.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
        log_event("review", **{k: v for k, v in record.items() if k != "reviewed_at"})
        return {"ok": True}

    @app.get("/api/status")
    def status(x_access_code: str | None = Header(default=None)):
        access.tester(x_access_code)
        return {"model": model, "active_sessions": len(manager.sessions),
                "budget": budget.status(), "scenario": _scenario_meta()}

    @app.exception_handler(HTTPException)
    async def http_error(_req, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    app.state.manager = manager
    app.state.budget = budget
    app.state.uploads = uploads
    return app


# ------------------------------------------------------------------ uploads

def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _public(rec: dict | None) -> dict:
    """An upload record as the page sees it: no internal bookkeeping fields, and an
    upload whose file never arrived shown as expired once its upload link has."""
    out = {k: v for k, v in (rec or {}).items() if k not in ("logged",)}
    if out.get("state") == "waiting_upload" and _expired(out.get("created")):
        out["state"], out["message"] = "error", "The file never arrived; the upload link expired."
    return out


def _expired(created: str | None) -> bool:
    from src.agent.uploads import SIGNED_URL_MINUTES
    try:
        t = dt.datetime.fromisoformat(created)
    except (TypeError, ValueError):
        return False
    return dt.datetime.now(dt.timezone.utc) - t > dt.timedelta(minutes=SIGNED_URL_MINUTES + 5)


_EVENTS_CACHE: dict | None = None
_DATASET_EVENTS: dict[str, dict] = {}


def _scenario_meta() -> dict:
    """The served scenario's meta.json, so a remote eval can check it grades the same build."""
    from src.agent.store import META_PATH
    return json.loads(META_PATH.read_text()) if META_PATH.exists() else {}


def _events_panel(dataset_dir: Path | None = None) -> dict:
    """Top events for the side panel. Read in-process, outside any chat session.

    Without `dataset_dir`, the demo day; with it, an uploaded capture's store."""
    global _EVENTS_CACHE
    from src.agent.store import DetectionStore
    from src.agent.tools import AuditLog, InvestigationSession
    if dataset_dir is None:
        if _EVENTS_CACHE is None:
            session = InvestigationSession(DetectionStore.load(), AuditLog(session_id="web-panel"))
            _EVENTS_CACHE = session.list_events(limit=12)
        return _EVENTS_CACHE
    key = str(dataset_dir)
    if key not in _DATASET_EVENTS:
        store = DetectionStore.load(Path(dataset_dir) / "flows.jsonl", Path(dataset_dir) / "meta.json")
        out = InvestigationSession(store, AuditLog(session_id="web-panel")).list_events(limit=12)
        m = store.meta
        out["dataset"] = {k: m.get(k) for k in ("scenario", "n_flows", "n_flagged",
                                                 "false_positive_rate",
                                                 "false_positive_rate_source")}
        _DATASET_EVENTS[key] = out
    return _DATASET_EVENTS[key]


def __getattr__(name: str):
    # `uvicorn src.agent.web:app` builds the app on first access, so importing this
    # module (e.g. in tests) does not require access codes to be configured.
    if name == "app":
        from dotenv import load_dotenv
        load_dotenv(REPO_ROOT / ".env")
        return create_app()
    raise AttributeError(name)
