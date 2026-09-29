"""Agent Skills with progressive disclosure.

Skills live in .claude/skills/<name>/SKILL.md (the standard layout, so Claude
Code picks up the same skills). Three levels of loading:
  1. The system prompt carries only each skill's name + description.
  2. load_skill(name) returns the SKILL.md body when a task needs it.
  3. load_skill(name, file) returns a supporting file the body points to.
Instructions enter the context window only when they are relevant.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parents[2] / ".claude" / "skills"


@dataclass
class Skill:
    name: str
    description: str
    path: Path

    def body(self) -> str:
        text = self.path.read_text()
        return text.split("---", 2)[2].strip() if text.startswith("---") else text


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    out = {}
    for line in text.split("---", 2)[1].strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def discover(skills_dir: Path = SKILLS_DIR) -> dict[str, Skill]:
    skills = {}
    for md in sorted(skills_dir.glob("*/SKILL.md")):
        fm = _frontmatter(md.read_text())
        if fm.get("name") and fm.get("description"):
            skills[fm["name"]] = Skill(fm["name"], fm["description"], md)
    return skills


def index_text(skills: dict[str, Skill]) -> str:
    return "\n".join(f"- {s.name}: {s.description}" for s in skills.values())


def load(skills: dict[str, Skill], name: str, file: str | None = None) -> dict:
    skill = skills.get(name)
    if skill is None:
        return {"error": "unknown_skill", "available": sorted(skills)}
    if not file:
        return {"skill": name, "instructions": skill.body()}
    target = (skill.path.parent / file).resolve()
    if skill.path.parent.resolve() not in target.parents or not target.is_file():
        return {"error": "unknown_file",
                "available": sorted(p.name for p in skill.path.parent.iterdir() if p.is_file())}
    return {"skill": name, "file": file, "content": target.read_text()}


LOAD_SKILL_TOOL = {
    "name": "load_skill",
    "description": ("Load a skill's full instructions (or one of its supporting files) when a "
                    "task matches its description. Load before starting that kind of task."),
    "input_schema": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Skill name from the skills list."},
            "file": {"type": "string",
                     "description": "Optional supporting file named in the skill, e.g. 'pairs.md'."},
        },
        "required": ["name"],
    },
}
