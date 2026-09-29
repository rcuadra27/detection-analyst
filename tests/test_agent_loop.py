"""The MCP server and the agent loop, end to end, with a scripted stand-in model.

The stand-in replays a realistic worm investigation, including one rejected
submission, through the REAL MCP server subprocess. It proves the plumbing:
tools listed from MCP, calls routed, skills loaded progressively, errors fed
back, the step cap enforced. It says nothing about model quality; that is what
the live eval (src/agent/eval_agent.py) measures.
"""

import asyncio
import json
from types import SimpleNamespace as NS

from src.agent import skills as skill_lib
from src.agent.cli import Agent, connect_mcp


class Block(NS):
    def model_dump(self, **_):
        return dict(self.__dict__)


def text(t):
    return Block(type="text", text=t)


def tool(i, tool_name, **inp):
    return Block(type="tool_use", id=f"call_{i}", name=tool_name, input=inp)


class ScriptedLLM:
    """Returns pre-written responses in order and records every request."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.requests = []
        self.messages = NS(create=self._create)

    async def _create(self, **kw):
        self.requests.append(json.loads(json.dumps(kw, default=str)))
        content = self.turns.pop(0)
        stop = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
        return NS(content=content, stop_reason=stop,
                  usage=NS(input_tokens=100, output_tokens=20))


WORM_INVESTIGATION = [
    [tool(1, "load_skill", name="investigate-event")],
    [tool(2, "list_events", limit=5)],
    [tool(3, "get_event", event_id="EV-10.0.3.57-49200")],
    [tool(4, "load_skill", name="disambiguate-hypotheses"),
     tool(5, "load_skill", name="disambiguate-hypotheses", file="pairs.md")],
    [tool(6, "get_host_activity", host="10.0.3.57")],
    [tool(7, "lookup_techniques", technique_ids=["T1210", "T1570"])],
    # First submission cites T1021 without retrieving it: must be rejected.
    [tool(8, "submit_triage", event_id="EV-10.0.3.57-49200", severity="critical",
          assessment="true_positive", attack_technique_ids=["T1210", "T1570", "T1021"],
          explanation="x", recommended_action="y", confidence=0.85)],
    [tool(9, "submit_triage", event_id="EV-10.0.3.57-49200", severity="critical",
          assessment="true_positive", attack_technique_ids=["T1210", "T1570"],
          explanation="Reached 33 internal hosts on port 445 in 4 minutes.",
          recommended_action="Isolate 10.0.3.57 and check the 33 targets.", confidence=0.85)],
    [text("10.0.3.57 is propagating like a worm: 33 internal hosts on port 445 in 4 "
          "minutes. Triage queued for analyst review.")],
]


def run(coro):
    return asyncio.run(coro)


async def _investigate(turns, max_steps=15):
    async with connect_mcp("test-session") as mcp:
        llm = ScriptedLLM(turns)
        agent = Agent(mcp, llm, model="scripted", max_steps=max_steps, session_id="test-session")
        await agent.setup()
        turn = await agent.ask("Is 10.0.3.57 a worm or a backdoor?")
        return agent, llm, turn


def test_mcp_server_exposes_the_tools():
    async def go():
        async with connect_mcp("t") as mcp:
            return sorted(t.name for t in (await mcp.list_tools()).tools)
    assert run(go()) == ["get_attack_mapping", "get_event", "get_host_activity",
                         "list_events", "lookup_techniques", "submit_triage"]


def test_full_worm_investigation_through_mcp():
    agent, llm, turn = run(_investigate(WORM_INVESTIGATION))
    names = [c["name"] for c in turn.tool_calls]
    assert names == ["load_skill", "list_events", "get_event", "load_skill", "load_skill",
                     "get_host_activity", "lookup_techniques", "submit_triage", "submit_triage"]
    first, second = [c for c in turn.tool_calls if c["name"] == "submit_triage"]
    assert first["is_error"] and "without retrieving" in first["result"]
    assert not second["is_error"] and json.loads(second["result"])["accepted"]
    host = json.loads(turn.tool_calls[5]["result"])
    assert host["outbound"]["distinct_internal_dests_suspicious"] >= 5
    assert "worm" in turn.answer and not turn.hit_step_cap and turn.steps == 9


def test_skills_are_loaded_progressively():
    agent, llm, turn = run(_investigate(WORM_INVESTIGATION))
    first = llm.requests[0]
    system = first["system"][0]["text"]
    assert "investigate-event:" in system                       # level 1: index only
    assert "## 1. Find the event" not in system                  # body not preloaded
    loaded = json.loads(turn.tool_calls[0]["result"])
    assert "## 1. Find the event" in loaded["instructions"]      # level 2: on demand
    pairs = json.loads(turn.tool_calls[4]["result"])
    assert "Persistent channel" in pairs["content"]              # level 3: supporting file


def test_static_prefix_is_marked_for_caching():
    agent, llm, turn = run(_investigate(WORM_INVESTIGATION))
    req = llm.requests[0]
    assert req["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert req["tools"][-1]["cache_control"] == {"type": "ephemeral"}


def test_conversation_is_the_memory():
    agent, llm, turn = run(_investigate(WORM_INVESTIGATION))
    sizes = [len(r["messages"]) for r in llm.requests]
    assert sizes == [1, 3, 5, 7, 9, 11, 13, 15, 17]         # grows by call + result


def test_step_cap_forces_an_answer_without_tools():
    looping = [[tool(i, "list_events", limit=1)] for i in range(3)] + [[text("Partial answer.")]]
    agent, llm, turn = run(_investigate(looping, max_steps=3))
    assert turn.hit_step_cap and turn.answer == "Partial answer."
    assert "tools" not in llm.requests[-1]


def test_skill_file_access_is_confined_to_the_skill_folder():
    skills = skill_lib.discover()
    assert "error" in skill_lib.load(skills, "investigate-event", "../../../src/agent/tools.py")
    assert "error" in skill_lib.load(skills, "no-such-skill")


def test_progress_events_stream_during_the_turn():
    events = []

    async def go():
        async with connect_mcp("t-events") as mcp:
            agent = Agent(mcp, ScriptedLLM(WORM_INVESTIGATION), model="scripted",
                          on_event=lambda kind, detail: events.append((kind, detail)))
            await agent.setup()
            await agent.ask("Is 10.0.3.57 a worm or a backdoor?")
    run(go())
    kinds = [k for k, _ in events]
    assert kinds.count("thinking") == 9 and kinds.count("tool") == 9
    assert kinds.count("tool_error") == 1          # the rejected first submission
    assert events[0] == ("thinking", "step 1")
