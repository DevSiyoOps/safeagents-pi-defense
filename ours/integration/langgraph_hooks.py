"""
Adapters between LangGraph and the guard (spec section 6).

make_hooks() returns the pre_model_hook and post_model_hook for one agent. They are installed
in every arm, including A and B: with all guard components off they change nothing, so every
arm produces the same trace format and the LLM input is identical to the unhooked code.

- pre_model_hook: labels new messages, asks the guard about untrusted messages from other
  producers, and passes the (possibly changed) list as llm_input_messages. The stored history
  keeps the original text.
- post_model_hook: labels the new AI message, records the LLM call, asks the guard about each
  tool call, and answers blocked calls with a ToolMessage so they never run.
"""
import time

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from ours.security_layer.guard import Guard, is_handoff
from ours.security_layer.types import Call, Decision, Msg, Trust

from .recorder import Recorder


def text_of(message) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    return "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)


class RunContext:
    """Per-run state shared by all agents' hooks: one label table, one guard, one recorder."""

    def __init__(self, guard: Guard, recorder: Recorder):
        self.guard = guard
        self.recorder = recorder
        self.labels = {}          # msg_id -> Trust
        self.call_owner = {}      # tool_call_id -> Trust of the AI message that made the call
        self.trusted_texts = []   # contents of TRUSTED messages, for the trusted_args rule
        self.pending = {}         # agent -> info about the LLM call in progress

    def set_label(self, message, kind: str, producer: str, trust: Trust):
        self.labels[message.id] = trust
        if trust == Trust.TRUSTED:
            self.trusted_texts.append(text_of(message))
        event = {"msg_id": message.id, "kind": kind, "producer": producer,
                 "content": text_of(message), "trust": trust.name}
        if isinstance(message, AIMessage) and message.tool_calls:
            event["tool_calls"] = [{"call_id": c["id"], "tool": c["name"], "args": c["args"]}
                                   for c in message.tool_calls]
        self.recorder.add("message", **event)

    def label_new(self, message, agent: str):
        """Label a message the first time any hook sees it."""
        if message.id in self.labels:
            return
        if isinstance(message, HumanMessage):
            self.set_label(message, "human", "user", Trust.TRUSTED)
        elif isinstance(message, ToolMessage):
            owner = self.call_owner.get(message.tool_call_id, Trust.UNTRUSTED)
            producer = message.name or "unknown_tool"
            self.set_label(message, "tool", producer, self.guard.label("tool", producer, owner))
        elif isinstance(message, AIMessage):
            # AI messages from an LLM are labeled in post_model_hook. An unseen one was made by
            # code: handoff-back messages from langgraph_supervisor have fixed text, anything
            # else fails closed.
            handoff_only = bool(message.tool_calls) and all(is_handoff(c["name"]) for c in message.tool_calls)
            trust = Trust.TRUSTED if handoff_only else Trust.UNTRUSTED
            self.set_label(message, "ai", message.name or agent, trust)
        else:
            self.set_label(message, "other", type(message).__name__, Trust.UNTRUSTED)


def _producer(message, agent: str) -> str:
    if isinstance(message, HumanMessage):
        return "user"
    return message.name or agent


def make_hooks(ctx: RunContext, agent: str) -> dict:
    """Returns {"pre_model_hook": ..., "post_model_hook": ...} for one agent."""

    def pre_model_hook(state):
        messages = state["messages"]
        for message in messages:
            ctx.label_new(message, agent)

        llm_input, decisions, seen_trust = [], [], []
        for message in messages:
            trust = ctx.labels[message.id]
            producer = _producer(message, agent)
            if trust == Trust.UNTRUSTED and producer != agent:
                verdict = ctx.guard.check_message(
                    Msg(message.id, type(message).__name__, producer, text_of(message), trust), agent)
                if verdict.decision != Decision.ALLOW:
                    decisions.append({"msg_id": message.id, "decision": verdict.decision.value,
                                      "rule": verdict.rule, "replacement": verdict.replacement})
                    message = message.model_copy(update={"content": verdict.replacement})
                if verdict.decision != Decision.QUARANTINE:
                    seen_trust.append(trust)   # quarantined text never reaches the LLM
            else:
                seen_trust.append(trust)
            llm_input.append(message)

        ctx.pending[agent] = {
            "context_trust": min(seen_trust, default=Trust.TRUSTED),
            "input_msg_ids": [m.id for m in messages],
            "input_decisions": decisions,
            "start": time.monotonic(),
        }
        return {"llm_input_messages": llm_input}

    def post_model_hook(state):
        message = state["messages"][-1]
        info = ctx.pending.pop(agent)
        context_trust = info["context_trust"]
        ctx.set_label(message, "ai", agent, context_trust)

        usage = getattr(message, "usage_metadata", None) or {}
        ctx.recorder.add(
            "llm_call", agent=agent, input_msg_ids=info["input_msg_ids"],
            context_trust=context_trust.name, input_decisions=info["input_decisions"],
            output_msg_id=message.id, input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_s=round(time.monotonic() - info["start"], 3),
        )

        blocked = []
        trusted_text = "\n".join(ctx.trusted_texts)
        for call in getattr(message, "tool_calls", []) or []:
            ctx.call_owner[call["id"]] = context_trust
            if is_handoff(call["name"]):
                ctx.recorder.add("tool_call", call_id=call["id"], msg_id=message.id, agent=agent,
                                 tool=call["name"], args=call["args"], context_trust=context_trust.name,
                                 decision=Decision.ALLOW.value, rule="handoff")
                continue
            verdict = ctx.guard.check_tool_call(
                Call(call["id"], agent, call["name"], call["args"]), context_trust, trusted_text)
            ctx.recorder.add("tool_call", call_id=call["id"], msg_id=message.id, agent=agent,
                             tool=call["name"], args=call["args"], context_trust=context_trust.name,
                             decision=verdict.decision.value, rule=verdict.rule)
            if verdict.decision == Decision.BLOCK:
                reply = ToolMessage(content=verdict.replacement, tool_call_id=call["id"],
                                    name=call["name"], id=f"blocked-{call['id']}")
                ctx.set_label(reply, "tool", "guard", Trust.TRUSTED)
                blocked.append(reply)
        return {"messages": blocked} if blocked else {}

    return {"pre_model_hook": pre_model_hook, "post_model_hook": post_model_hook}
