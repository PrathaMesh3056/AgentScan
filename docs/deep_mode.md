# DEEP Mode — Neural Activation Probing

> **DEEP Mode** measures the hidden states of an open-weight local reference model. These experimental observations describe that reference model, not the hidden states or safety of an arbitrary remote target, and are excluded from remote-target scoring.

---

## 🔬 Motivation & Theoretical Foundation

Standard black-box scanners evaluate an agent's vulnerability purely from its **textual output**. However, defensive techniques such as paraphrasing, prompt wrappers, or implicit refusals can mask whether an injection payload actually compromised the model's latent processing.

DEEP mode replays payloads through a local reference model (`Qwen/Qwen2.5-0.5B-Instruct`) and measures representation changes against a benign baseline. The model revision is pinned, safetensors are required, remote model code is disabled and shared inference/hooks are serialized. A changed representation does not by itself establish an injection, compromise or the behavior of a separate target agent.

```
Input Prompt ───▶ [ Reference Model Hidden Layers ] ───▶ Residual Stream Activation
                                                                   │
                                                ┌──────────────────┴──────────────────┐
                                                ▼                                     ▼
                                       Magnitude (L2 Shift)                Direction (Cosine Shift)
                                                │                                     │
                                                └──────────────────┬──────────────────┘
                                                                   ▼
                                                       Benign Noise Floor Comparison
                                                                   ▼
                                                      Ranked Forensic Finding
```

---

## 📐 Dual-Axis Activation Metrics

For each layer in the residual stream, AgentScan measures two complementary geometric metrics:

1. **Magnitude ($\Delta L_2$)**:
   $$\Delta L_2 = \| \mathbf{h}_{\text{probe}} - \mathbf{\mu}_{\text{benign}} \|_2$$
   Quantifies the absolute displacement in latent space caused by the adversarial payload relative to benign prompts.

2. **Direction ($\cos \theta$)**:
   $$\cos \theta = \frac{\mathbf{h}_{\text{probe}} \cdot \mathbf{\mu}_{\text{benign}}}{\| \mathbf{h}_{\text{probe}} \|_2 \, \| \mathbf{\mu}_{\text{benign}} \|_2}$$
   Detects orthogonal shifts or vector inversions where the model's semantic trajectory abruptly diverges from standard instruction-following manifolds.

### Dynamic Noise Floor
AgentScan computes a **benign noise floor** across fixed benign instructions. Payload deviations are experimental reference observations. This baseline has not been established as independent held-out calibration of jailbreak detection, so an anomaly is not a confirmed neural injection.

---

## 🧬 Cross-Modal Correlation (`yaml_variant_id`)

Activation-probe observations attach `metadata["yaml_variant_id"]` for comparison with the payload variant used by `SCAN` mode's `ATK-001`; other DEEP probes have their own evidence fields.

In the final report (JSON, HTML, or PDF), security engineers can inspect the **dual perspective**:
- **Black-box observation**: Did the endpoint output indicate compliance or refusal?
- **Local reference observation**: Did the same payload change activations in a separate reference model? Correlation does not establish target compromise.

---

## 🛡️ Registered DEEP Probes

| Probe ID | Target Metric | Detection Technique |
| :--- | :--- | :--- |
| **ATK-023** | Latent Shift | $L_2$ + Cosine distance against calibrated benign noise floor |
| **ATK-024** | Trojan / Suffix Scan | Kullback-Leibler (KL) divergence shift on suffix tokens |
| **ATK-025** | Attention Anomaly | Attention entropy collapse and attention sink concentration |
| **ATK-026** | Model Fingerprint | Multi-probe activation hash verification (`AGENTSCAN_MODEL_FINGERPRINT`) |

---

## 🚀 Running DEEP Mode

Run DEEP mode alongside live scans:

```bash
uv run agentscan scan http://localhost:8000/chat --deep --output report.html
```

Or target local models directly:
```bash
uv run agentscan scan http://localhost:8000/chat --deep --fail-on HIGH
```

> [!NOTE]
> PyTorch runs on the CPU wheel by default. The reference weights (`Qwen/Qwen2.5-0.5B-Instruct`) are downloaded lazily and cached locally on the first `--deep` invocation.
