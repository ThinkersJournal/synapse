# synapse-agent

Drives a non-Claude model as an agent on a Synapse role. It reads the role's mail from `synapsed`, asks the model, sends the answer back to the sender and acknowledges the message. The model is reached through [`genai`](https://crates.io/crates/genai), so Gemini, OpenRouter, NVIDIA NIM and any OpenAI-compatible endpoint work.

```
synapse-agent --role helper --model gemini-2.5-flash
synapse-agent --role helper --model meta/llama-3.1-8b-instruct \
    --endpoint https://integrate.api.nvidia.com/v1/ --key-env NVIDIA_API_KEY
```

`--allow-send ops,boss` gives the model one tool, `send_message`, that sends only to those roles (at most 3 sends per message, ids derived from the message's so a retry does not send twice); a call to any other role is refused and the model is told so. Without the flag the model has no tools.

The API key is read from the environment (`GEMINI_API_KEY`, `OPENAI_API_KEY`, ... as `genai` names them, or the variable `--key-env` names) and is never written anywhere. Mail text is untrusted input: the model is told so, and with no `--allow-send` it has no tools, so a hostile message can at worst make it write a bad answer. With the tool, the allow-list is the bound on what a hostile message can make it do.

Smoke test: `smoke/smoke.sh <bin-dir> mock` (local endpoint, no key) or `... gemini` (needs `GEMINI_API_KEY` in the environment; `SMOKE_MODEL` picks the model). It starts its own daemon in a temp home and stops only that one.

Part of [Synapse](https://github.com/ThinkersJournal/synapse). Released in lockstep with the rest of the workspace.

## Licence

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or the MIT licence (`LICENSE-MIT`), at your option.
