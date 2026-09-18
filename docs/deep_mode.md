# DEEP Mode — Neural Activation Probing

> **DEEP Mode** inspects the hidden internal states of an open-weight aligned reference model to corroborate prompt injection payloads at the neural activation level, bypassing textual obfuscation and implicit refusals.

---

## 🔬 Motivation & Theoretical Foundation

Standard black-box scanners evaluate an agent's vulnerability purely from its **textual output**. However, defensive techniques such as paraphrasing, prompt wrappers, or implicit refusals can mask whether an injection payload actually compromised the model's latent processing.

DEEP mode resolves this by replaying prompt-injection payloads through a local aligned reference model (default: `Qwen/Qwen2.5-0.5B-Instruct` on CPU) and measuring how far each payload shifts the model's internal representation away from an empirical **benign baseline**.

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
Rather than relying on arbitrary static cutoffs, AgentScan computes a **benign noise floor** across a diverse calibration set of standard, benign instructions. Payloads that statistically deviate beyond this floor are flagged as corroborated neural injections.

---

## 🧬 Cross-Modal Correlation (`yaml_variant_id`)

Every finding emitted by DEEP mode attaches a shared `metadata["yaml_variant_id"]`. This matches the exact variant ID used by `SCAN` mode's `ATK-001`.

In the final report (JSON, HTML, or PDF), security engineers can inspect the **dual perspective**:
- **Black-box observation**: Did the endpoint output indicate compliance or refusal?
- **White-box corroboration**: Did the payload trigger an anomalous latent activation spike inside the model?

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
