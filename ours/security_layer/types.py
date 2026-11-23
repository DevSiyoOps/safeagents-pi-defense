"""
Framework-free types for the security layer (spec sections 3, 4 and 6).
Nothing here imports LangGraph, so the guard can be unit-tested on hand-written inputs.
"""
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Optional


class Trust(IntEnum):
    """Lower is less trusted, so min() means "the lowest label wins"."""
    UNTRUSTED = 0
    TRUSTED = 1


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"        # content changed before the LLM sees it
    QUARANTINE = "QUARANTINE"    # content withheld from the LLM, placeholder shown
    BLOCK = "BLOCK"              # tool call stopped, never runs


@dataclass(frozen=True)
class GuardConfig:
    """Each component can be switched on or off for the ablations."""
    provenance: bool = False     # trust labels, untrusted-data wrapping, trust-based tool rules
    permissions: bool = False    # static table: which agent may call which tool
    schema: bool = False         # format rules for untrusted content
    classifier: bool = False     # LLM classifier on untrusted content

    def as_dict(self) -> dict:
        return {"provenance": self.provenance, "permissions": self.permissions,
                "schema": self.schema, "classifier": self.classifier}


@dataclass
class Msg:
    """Framework-free view of one message."""
    msg_id: str
    kind: str               # "human" | "ai" | "tool"
    producer: str           # "user", agent name, or tool name
    content: str
    trust: Trust


@dataclass
class Call:
    call_id: str
    agent: str
    tool: str
    args: dict


@dataclass
class Verdict:
    decision: Decision
    rule: Optional[str] = None          # which rule fired, e.g. "arg_not_from_trusted_content"
    replacement: Optional[str] = None   # new text for SANITIZE / QUARANTINE / BLOCK
