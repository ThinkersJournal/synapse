# synapse-agent

Drives a non-Claude model as an agent on a Synapse role. It reads the role's mail from `synapsed`, asks the model, sends the answer back to the sender and acknowledges the message. The model is reached through [`genai`](https://crates.io/crates/genai), so Gemini, OpenRouter, NVIDIA NIM and any OpenAI-compatible endpoint work.

```
synapse-agent --role helper --model gemini-2.5-flash
synapse-agent --role helper --model meta/llama-3.1-8b-instruct \
    --endpoint https://integrate.api.nvidia.com/v1/ --key-env NVIDIA_API_KEY
```

The API key is read from the environment (`GEMINI_API_KEY`, `OPENAI_API_KEY`, ... as `genai` names them, or the variable `--key-env` names) and is never written anywhere. Mail text is untrusted input: the model is told so, and it has no tools in this release, so a hostile message can at worst make it write a bad answer.

Part of [Synapse](https://github.com/ThinkersJournal/synapse). Released in lockstep with the rest of the workspace.

## Licence

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or the MIT licence (`LICENSE-MIT`), at your option.
