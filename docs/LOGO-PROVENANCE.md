<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Logo provenance (`Synapse.png`)

`Synapse.png` replaces `Synapse.jpeg`, a Microsoft Designer image whose terms allow personal use only
(CireSnave, 2026-10-24). Board 267. The old image is removed from the working tree; history is not rewritten.

| | |
|---|---|
| Generated | 2026-11-21, by the portfolio PM, on this laptop |
| Tool | ComfyUI 0.43.0 (local) |
| Model | FLUX.1 [schnell] (`flux1-schnell.safetensors`), Apache-2.0 per its model card; weights checked against Black Forest Labs' files |
| Text encoders, VAE | `clip_l`, `t5xxl_fp16`, `ae.safetensors`; `weight_dtype` `fp8_e4m3fn` |
| Sampler | euler / simple, 4 steps, cfg 1.0, 1024 x 1024 |
| Pick | candidate 1, seed 11 (CireSnave 2026-11-21: "For Synapse, I like the first image.") |
| Prompt | "A clean modern illustration of a glowing network of connected nodes and synapse links joining abstract human silhouettes and small friendly robot icons across a dark blue globe, luminous blue light, one bright central node, balanced square composition, no text, no letters" |
| Edit | one node near the bottom of the globe held a small garbled glyph; it was painted over with a plain glowing disc (about 21 px radius at 594, 730) using System.Drawing. Nothing else changed. |
| Source of record | `C:/Projects/.lane-state/logo-picks/synapse-pick.png` and `PROVENANCE.txt` beside it (not in this repo) |

The images are model output; no third-party artwork or text was copied in.
