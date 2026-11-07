---
title: AI application, agent and MCP security test
standard: OWASP Top 10 for LLM Applications 2025, OWASP Agentic AI threats, MITRE ATLAS
tiers: passive, active; adversarial prompts and tool calls are intrusive (approval)
---
# AI application, agent and MCP security test

Covers chatbots and copilots, RAG apps, autonomous agents with tools, and MCP servers. Ask the client for: the
chat endpoint (or UI) and a test account, the system prompt if they will share it (white-box finds far more),
the tools/plugins the agent can call and with what permissions, the data sources it reads (RAG, email, web,
tickets), and which actions are real (sending email, payments). Adversarial prompts cost the client tokens:
agree a request budget and keep `--rate` low.

`rv-llm` is the main tool (`rv-llm help`). Every probe carries a random canary (RVC-XXXXXXXX): if it shows up in
a reply, request log or callback, the injection worked. HIT = lead, confirm it by hand.

## 1. Recon and architecture (passive, active)
- [ ] Map the system: model/provider (ask, or fingerprint from error messages and behaviour), system prompt
      source, RAG stores, tools/functions and their scopes, memory, output channels (web UI rendering markdown/
      HTML, email, tickets, code execution)
- [ ] Find the API behind the UI: `katana -u <app> -jc -f qurl`, then build the target flags:
      `--http <url> --body '{"message":"{{prompt}}"}' --reply reply` or `--openai <base> --model <name>`
- [ ] Baseline: `rv-llm ask <target> "Hello, what can you help me with?" --repeat 3` (non-determinism shows how
      many repeats each test needs)
- [ ] MCP servers in scope: `rv-llm mcp <url>/mcp` (or `<url>/sse`). Check: unauthenticated access, transport
      without TLS, tools with exec/file/network power, free-form string parameters, poisoned tool descriptions
      (hidden instructions, invisible characters, cross-tool instructions), duplicate/shadowed tool names
- [ ] Record the tool inventory and the trust boundaries (what untrusted text reaches the model) in PLAN.md

## 2. Prompt injection and jailbreak (LLM01). Intrusive
- [ ] Probe library: `rv-llm probe <target> --suite injection,jailbreak --rate 1 --out evidence/llm-probe.jsonl`
- [ ] Manually vary the HITs and REVIEWs: other languages, encodings (base64, leetspeak), role-play, long
      context, multi-turn escalation; record the shortest working prompt
- [ ] garak for breadth (string-based detectors only; no model downloads in the sandbox):
      `garak --target_type rest -G evidence/garak-rest.json --probes promptinject,encoding,dan.DanInTheWild
      --generations 1 --report_prefix evidence/garak` (REST config: see "garak REST config" below)
- [ ] Indirect injection (the agent's real risk): `rv-llm payloads --canary <C>` gives payloads for content the
      target ingests (web pages, documents, emails, tickets, RAG). Plant them only in places the client
      authorised, ask the agent to process them, and check for the canary in replies and tool calls

## 3. Sensitive information disclosure (LLM02, LLM07)
- [ ] `rv-llm probe <target> --suite leak,exfil --system-file <prompt.txt if known>`
- [ ] System prompt leakage: secrets, internal URLs, rules that help an attacker (LLM07)
- [ ] Data of other users/tenants through RAG or memory: ask for documents, conversations or records that belong
      to the second test account
- [ ] Exfiltration channels: does the UI render markdown images/links from model output (zero-click exfil),
      can the agent send email / call URLs with conversation data

## 4. Output handling (LLM05)
- [ ] `rv-llm probe <target> --suite output`, then check how the app uses the reply: rendered as HTML (XSS),
      passed to SQL, shell, templates, file paths, or another agent. Open the UI and confirm in the browser
      where possible
- [ ] Code-executing features (code interpreter, generated SQL): sandbox escape, network and file access

## 5. Excessive agency and tool abuse (LLM06, agentic threats)
- [ ] `rv-llm probe <target> --suite tools`, then for each tool: can the model be talked into calling it with
      attacker-chosen arguments (other users' ids → BOLA, internal URLs → SSRF, paths → traversal)?
- [ ] Confirmation and least privilege: do destructive actions need human confirmation, do tools run with the
      user's permissions or a service account's
- [ ] MCP tools directly (intrusive): `rv-llm mcp-call <url> <tool> '{"arg": "..."}'` with injection, traversal
      and SSRF payloads on the parameters flagged in step 1
- [ ] Multi-agent / memory: poisoning persistent memory or shared context, delegation to more-privileged agents

## 6. Supply chain, poisoning, misinformation, consumption (LLM03, LLM04, LLM08, LLM09, LLM10)
- [ ] Code review (if source is in scope): model and dataset provenance, pickle/unsafe model loading
      (`torch.load`, `pickle`), prompt templates with string concatenation, secrets in prompts, RAG ingestion
      without sanitisation, embeddings store access control (LLM08). Use the code-review playbook too
- [ ] Hallucinated packages and facts on the client's key workflows (LLM09): `--suite output` probe misinfo-package
- [ ] Unbounded consumption (LLM10): `rv-llm probe <target> --suite dos` only with approval; measure reply size,
      latency and whether limits exist (max tokens, per-user rate, cost caps)

## garak REST config
`evidence/garak-rest.json` (replace the URI, headers and field names with the target's):
```json
{"rest": {"RestGenerator": {"name": "target", "uri": "http://10.250.0.15:8000/api/chat", "method": "post",
  "headers": {"Content-Type": "application/json"}, "req_template_json_object": {"message": "$INPUT"},
  "response_json": true, "response_json_field": "reply"}}}
```

## Findings
- Asset = endpoint + feature (e.g. "POST /api/chat, order lookup tool"). Reproduction = exact prompt(s) and the
  reply excerpt; note how many of N attempts succeeded (LLM output is not deterministic).
- Severity follows the impact of what the injection achieves (data access, actions), not the injection itself.
- Map each finding to an OWASP LLM id (LLM01–LLM10) in its description and to a CWE (77/1427 prompt injection,
  200 disclosure, 79 output XSS, 918 SSRF via tool, 639 BOLA via tool, 22 traversal, 78 command injection,
  306 missing auth, 770 unbounded resources).

## Done when
Every tool and data source in the inventory has been tested for injection and abuse, LLM01–LLM10 are each covered
or marked out of scope in PLAN.md, MCP servers in scope have been audited, and candidates are triaged with
success rates.
