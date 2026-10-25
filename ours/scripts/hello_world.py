"""
Smoke test for our setup: LangGraph supervisor + 2 agents + 1 harmless tool,
using the LLM configured in .env (LLM_API_KEY, LLM_MODEL, LLM_BASE_URL).

Checks that:
1. the supervisor can hand off to agents
2. an agent can call a tool through the provider's API
3. token counts come back (needed for our cost metrics)

Run from the repo root (as a module, so `safeagents` can be imported):
    python -m ours.scripts.hello_world
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from langchain_core.callbacks import get_usage_metadata_callback

from safeagents import Agent, AgentConfig, Team, tool

load_dotenv()


@tool()
def get_weather(city: str) -> str:
    """
    Get the current weather for a city.

    Args:
        city: Name of the city

    Returns:
        A short weather report
    """
    return f"It is 18 degrees and sunny in {city}."


async def main():
    if not os.getenv("LLM_API_KEY") or not os.getenv("LLM_MODEL"):
        sys.exit("Set LLM_API_KEY and LLM_MODEL in .env first (see .env.example).")

    print(f"Model: {os.getenv('LLM_MODEL')}")
    print(f"Base URL: {os.getenv('LLM_BASE_URL') or 'default OpenAI'}\n")

    weather_agent = Agent(config=AgentConfig(
        name="WeatherAgent",
        tools=[get_weather],
        system_message="You answer weather questions. Always use the get_weather tool.",
    ))
    writer_agent = Agent(config=AgentConfig(
        name="WriterAgent",
        system_message="You rewrite facts as one short, friendly sentence.",
    ))

    team = Team.create(
        agents=[weather_agent, writer_agent],
        framework="langgraph",
        architecture="centralized",
    )

    task = "What is the weather in Paris? Answer in one friendly sentence."
    print(f"Task: {task}\n")

    with get_usage_metadata_callback() as usage:
        result = await team.run(task=task)

    tool_calls = result["execution_trace"]["tool_calls"]
    print("Tool calls:")
    for call in tool_calls:
        print(f"  {call['agent']} -> {call['name']}({call['args']}) = {call['result']}")
    if not tool_calls:
        print("  none")

    if result.get("messages"):
        print(f"\nFinal message:\n  {result['messages'][-1]['content']}")

    print("\nToken usage:")
    for model, counts in usage.usage_metadata.items():
        print(f"  {model}: {counts['input_tokens']} in, {counts['output_tokens']} out")
    if not usage.usage_metadata:
        print("  none reported")

    ok = any(call["name"] == "get_weather" for call in tool_calls)
    print("\nPASS: tool calling works" if ok else "\nFAIL: get_weather was never called")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
