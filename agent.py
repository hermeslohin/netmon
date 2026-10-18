"""Tool-using AI conversation loop shared by the research job (review.py) and the dashboard chat.

run(target, system, user, tools, ...) keeps calling the model, runs the tools it asks for and feeds the results back
until the model answers without tool calls (or a limit is hit). Tools are plain Python functions:
    tools = {"name": (fn(args: dict) -> str | dict | list, "description", {JSON-schema properties}, [required])}
A tool's return value is JSON-encoded and cut to max_result chars; an exception becomes an "error: ..." result, so the
model can correct itself. Results from tools are data, never instructions (the system prompts say so).
Budget(tokens, usd) is shared across conversations of one run: every call is charged, and BudgetExceeded is raised
before the next call once a limit is passed.
"""
import json
import re
import time

import llm_providers as LP


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, provider, model, max_tokens=None, max_usd=None):
        self.provider, self.model, self.max_tokens, self.max_usd = provider, model, max_tokens, max_usd
        self.usage = {"prompt": 0, "completion": 0, "cache_read": 0, "cache_write": 0}
        self.calls, self.usd, self.priced = 0, 0.0, LP.price(provider, model) is not None

    def charge(self, u):
        for k in self.usage:
            self.usage[k] += int(u.get(k) or 0)
        self.calls += 1
        c = LP.cost(self.provider, self.model, u)
        if c is not None:
            self.usd += c

    def check(self):
        tot = self.usage["prompt"] + self.usage["completion"]
        if self.max_tokens and tot >= self.max_tokens:
            raise BudgetExceeded(f"token limit reached ({tot:,} of {self.max_tokens:,} tokens)")
        if self.max_usd and self.priced and self.usd >= self.max_usd:
            raise BudgetExceeded(f"cost limit reached (${self.usd:.2f} of ${self.max_usd:.2f})")

    def summary(self):
        return {**self.usage, "total": self.usage["prompt"] + self.usage["completion"], "calls": self.calls,
                "cost_usd": round(self.usd, 4) if self.priced else None}


_SECRET_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"  # JWTs (session tokens in logged HTTP headers)
                        r"|(?i:(?:bearer|apikey|basic)\s+)[A-Za-z0-9+/=._-]{16,}"  # Authorization header values
                        r"|(?i:ory_kratos_session|session|token|api[_-]?key|password)(\\*\"?\s*[:=]\s*\\*\"?)[^\s\"\\,;]{12,}")


def redact(s):
    """Remove credentials that log data can carry (HTTP headers, cookies) before a tool result reaches the model or a transcript."""
    return _SECRET_RE.sub(lambda m: (m.group(1) and m.group(0)[:m.start(1) - m.start(0)] + m.group(1) or "") + "[redacted]", s)


def _schema(props, req):
    return {"type": "object", "properties": props or {}, "required": list(req or [])}


def _trim(messages, keep_last=6):
    """Shrink old tool results when the conversation grows too big (the newest ones stay complete)."""
    tool_idx = [i for i, m in enumerate(messages) if m["role"] == "tool"]
    n = 0
    for i in tool_idx[:-keep_last]:
        if len(messages[i].get("content") or "") > 400:
            messages[i] = {**messages[i], "content": messages[i]["content"][:300] + " …[older tool result shortened to save space]"}
            n += 1
    return n


def run(target, system, user, tools, budget=None, max_turns=30, max_tokens=4000, max_result=12000, context_limit=150000,
        on_event=None, history=None, stop_tools=()):
    """-> {"text", "messages", "turns", "tool_calls": [names], "stopped": None | reason}.
    stop_tools: names of tools after which the conversation ends (e.g. a submit_* tool that was accepted)."""
    provider, model = target["provider"], target["model"]
    budget = budget or Budget(provider, model)
    specs = [{"name": n, "description": d, "parameters": _schema(p, req[0] if req else ())} for n, (fn, d, p, *req) in tools.items()]
    messages = list(history or []) + [{"role": "user", "content": user}]
    used, text, stopped = [], "", None
    emit = on_event or (lambda *_: None)
    for turn in range(1, max_turns + 1):
        budget.check()
        r = LP.chat(provider, model, system, messages, tools=specs or None, max_tokens=max_tokens)
        budget.charge(r["usage"])
        emit("usage", r["usage"])
        if r["usage"].get("prompt", 0) > context_limit:
            _trim(messages)
        text = r["text"] or text
        if r["text"]:
            emit("text", r["text"])
        raw = {"raw": r["raw"]} if r.get("raw") else {}
        if not r["tool_calls"]:
            messages.append({"role": "assistant", "content": r["text"], **raw})
            if r["stop"] == "length" and not r["text"]:
                stopped = "the model ran out of output tokens"
            return {"text": text, "messages": messages, "turns": turn, "tool_calls": used, "stopped": stopped}
        messages.append({"role": "assistant", "content": r["text"], "tool_calls": r["tool_calls"], **raw})
        done = False
        for tc in r["tool_calls"]:
            used.append(tc["name"])
            emit("tool", tc["name"], tc.get("args"))
            spec = tools.get(tc["name"])
            t0 = time.time()
            if not spec:
                out, ok = f"error: unknown tool {tc['name']!r}", False
            else:
                try:
                    res = spec[0](tc.get("args") or {})
                    out, ok = res if isinstance(res, str) else json.dumps(res, default=str, ensure_ascii=False), True
                except Exception as e:  # noqa: BLE001 - the model sees the error and can retry
                    out, ok = f"error: {type(e).__name__}: {str(e)[:600]}", False
            out = redact(out)
            if len(out) > max_result:
                out = out[:max_result] + f" …[cut at {max_result} characters; narrow the request for more]"
            emit("tool_done", tc["name"], ok, round(time.time() - t0, 2))
            messages.append({"role": "tool", "id": tc["id"], "name": tc["name"], "content": out})
            if ok and tc["name"] in stop_tools and not out.startswith("error"):
                done = True
        if done:
            return {"text": text, "messages": messages, "turns": turn, "tool_calls": used, "stopped": None}
    return {"text": text, "messages": messages, "turns": max_turns, "tool_calls": used, "stopped": f"turn limit ({max_turns}) reached"}
