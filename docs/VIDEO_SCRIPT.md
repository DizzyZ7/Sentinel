# Sentinel demo video script

Target duration: **2 minutes 45 seconds**. Keep the final upload below three minutes.

## 0:00–0:18 — problem

**Screen:** Sentinel landing page, no interaction yet.

**Voiceover:**

> Static analysis gives developers evidence, but often too much noise. AI code review understands context, but it can hallucinate fixes. Sentinel combines both and refuses to trust a patch until the original security signal is proven gone.

## 0:18–0:34 — product and architecture

**Screen:** briefly show the pipeline section or architecture diagram.

**Voiceover:**

> Sentinel is a local-first evidence-to-patch security agent for Python and JavaScript repositories. Deterministic rules create candidates. GPT-5.6 confirms exploitability and proposes a minimal diff. Sentinel validates the patch, builds a non-executing regression proof, and leaves the final decision to a human.

## 0:34–0:48 — start the demo

**Screen:** click **Run the 60-second security demo**. Show live progress.

**Voiceover:**

> For a reliable judge path, this button runs an explicitly labelled deterministic replay. It does not pretend to call GPT-5.6, but it exercises the real ingestion, analysis, patch, proof, policy, and reporting pipeline. A separate button runs the same fixture through the live GPT-5.6 API boundary.

## 0:48–1:18 — successful proof

**Screen:** open the first confirmed SQL injection. Show source, verdict, patch, and `passed` proof.

**Voiceover:**

> Here request data reaches an interpolated SQL query. The proposed parameterized patch passes path and syntax checks. Sentinel applies it only to a temporary copy, re-runs the original rule, and records that the signal existed before and disappeared after. The repository itself is never modified.

## 1:18–1:37 — false positive

**Screen:** show the rejected constant-expression candidate.

**Voiceover:**

> The second case demonstrates why GPT-5.6 matters. The deterministic rule notices dynamic execution, but the evidence shows a fixed constant with no attacker-controlled path, so the candidate is rejected instead of becoming noisy security debt.

## 1:37–1:57 — failed patch and release gate

**Screen:** show the cosmetic patch, failed regression proof, disabled approval, and blocked gate.

**Voiceover:**

> The third patch is syntactically valid and applies cleanly, but it only changes formatting. The same SQL injection remains. Regression proof fails, approval stays disabled, and the release gate remains blocked. Sentinel fails closed.

## 1:57–2:13 — Evidence Bundle

**Screen:** download/open the Evidence Bundle JSON and highlight integrity hashes.

**Voiceover:**

> Every finding can be exported as one privacy-safe Evidence Bundle containing deterministic evidence, the GPT audit, patch digest, regression proof, human decision, release policy, attack path, and SHA-256 hashes for independent integrity checking.

## 2:13–2:31 — GPT-5.6 integration

**Screen:** show the LLM audit page and, if available, a live-demo audit row.

**Voiceover:**

> In live mode, GPT-5.6 receives a secret-sanitized fifty-line evidence window and must return strict structured JSON. Sentinel records the model, response ID, prompt and schema versions, latency, retries, usage, and redaction metadata without storing original credentials.

## 2:31–2:43 — Codex collaboration

**Screen:** show GitHub pull requests, tests, and Build Week engineering log.

**Voiceover:**

> I built Sentinel with Codex in small reviewed slices. Codex helped design the trust boundaries, implement the pipeline, generate adversarial fixtures, refactor the architecture, and verify each change through tests, Ruff, Docker, and GitHub Actions.

## 2:43–2:50 — close

**Screen:** return to the blocked/allowed release view and Sentinel logo.

**Voiceover:**

> Sentinel does not ask developers to trust AI. It gives them evidence they can verify.
