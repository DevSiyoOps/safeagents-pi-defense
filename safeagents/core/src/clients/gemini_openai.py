"""
ChatOpenAI for Gemini models served through an OpenAI-compatible endpoint.

Gemini 3 models attach a thought signature to every tool call
(tool_calls[i].extra_content.google.thought_signature) and reject a request
(HTTP 400) if a tool call in the current turn comes back without one.
ChatOpenAI keeps the raw tool calls, signature included, in
additional_kwargs["tool_calls"], but rebuilds outgoing tool calls without it,
so we copy it back. Tool calls created by LangGraph itself (e.g. handoffs)
never had a signature, so they get a placeholder value that Gemini accepts.
"""
from typing import Any, Optional

from langchain_core.messages import AIMessage
from langchain_openai.chat_models import ChatOpenAI

PLACEHOLDER_SIGNATURE = "skip_thought_signature_validator"


class GeminiChatOpenAI(ChatOpenAI):
    """ChatOpenAI that sends Gemini thought signatures back with tool calls."""

    def _get_request_payload(self, input_: Any, *, stop: Optional[list[str]] = None, **kwargs: Any) -> dict:
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        messages = self._convert_input(input_).to_messages()

        # payload["messages"] is built 1:1 from messages, in the same order
        for message, message_dict in zip(messages, payload.get("messages", [])):
            if not isinstance(message, AIMessage) or not message_dict.get("tool_calls"):
                continue
            raw_calls = {call.get("id"): call for call in message.additional_kwargs.get("tool_calls", [])}
            for tool_call in message_dict["tool_calls"]:
                extra = raw_calls.get(tool_call["id"], {}).get("extra_content")
                tool_call["extra_content"] = extra or {"google": {"thought_signature": PLACEHOLDER_SIGNATURE}}
        return payload
