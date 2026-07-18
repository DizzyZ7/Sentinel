# Devpost submission draft

## Project name

Sentinel

## Tagline

Evidence-to-patch security review that makes AI prove a fix before a human can approve it.

## Track

Developer Tools

## One-line summary

Sentinel combines deterministic security evidence, GPT-5.6 contextual review, constrained patch generation, non-executing regression proof, and explicit human approval in one local-first workflow.

## Project description

Traditional static analysis is deterministic but noisy. General AI code review understands context but can hallucinate vulnerabilities or generate unsafe fixes. Sentinel is designed around the gap between those two approaches.

A repository enters an isolated workspace and is scanned with lightweight Python AST and JavaScript/TypeScript rules. Those rules create review candidates rather than final verdicts. Before any external model call, Sentinel replaces credential-like values with typed placeholders while preserving code structure and line numbers. GPT-5.6 then receives the candidate plus a bounded evidence window and must return strict structured JSON containing a verdict, severity, explanation, attack scenario, recommendation, and minimal unified diff.

A proposed patch is never applied to the user's repository. Sentinel restricts it to the reviewed file, rejects unsafe diff features, runs `git apply --check`, and validates Python syntax. It then applies the patch only inside an isolated temporary copy and re-runs the same deterministic rule near the changed hunk. The proof records whether the original signal was reproduced, whether it disappeared, before/after SHA-256 digests, and an explicit `source_executed=false` statement.

High- or critical-severity findings remain release blockers until the patch is valid, regression proof passes, and a human explicitly approves it. A reviewer cannot approve a failed or inconclusive proof.

Each finding can be exported as a privacy-safe Evidence Bundle containing scan provenance, static evidence, GPT-5.6 audit metadata, patch digest, regression proof, human decision, release policy, attack path, version information, per-section hashes, and a canonical payload SHA-256.

For judges, Sentinel includes a one-click deterministic replay with three distinct outcomes: a successful SQL injection fix, a false-positive rejection, and a cosmetic patch that applies but fails regression proof. A separate live mode sends the same fixture through GPT-5.6. The prebuilt multi-architecture Docker image removes the need to rebuild from source.

## How GPT-5.6 is used

GPT-5.6 is the evidence-bound contextual reviewer. It decides whether a deterministic candidate is plausibly exploitable, explains the attack path, assigns severity and confidence, recommends remediation, and proposes a minimal unified diff through a strict JSON schema. It does not apply patches, decide human approval, or override the release policy.

## How Codex was used

Codex was used throughout the Build Week implementation to explore architecture, implement vertical slices, review and refactor changes, build adversarial fixtures, improve the user experience, and verify every merge through tests and GitHub Actions. Key Codex-assisted decisions included keeping a modular monolith, separating candidates from verdicts, forbidding source execution and auto-apply, adding secret redaction, building a deterministic judge replay, and publishing transparent evaluation limitations.

The repository's `docs/BUILD_LOG.md` and merged pull requests show the implementation sequence and the features added during the submission period.

## Technical highlights

- FastAPI modular monolith with PostgreSQL and Pydantic
- Python AST plus JavaScript/TypeScript deterministic triage
- OpenAI Responses API with strict GPT-5.6 structured output
- secret-safe context sanitization and model-call audit trail
- path-restricted unified diff validation and patch escrow
- non-executing regression proof with before/after hashes
- seven-stage attack paths and fail-closed release gate
- SARIF, Mermaid, JSON, HTML, and Evidence Bundle exports
- one-click replay and separate live GPT-5.6 judge mode
- hardened non-root, read-only Docker delivery for amd64 and arm64
- 20-case deterministic regression corpus enforced in CI

## Evaluation disclosure

The committed deterministic corpus currently passes 20/20 exact cases with 15 true positives, zero false positives, and zero false negatives. These are transparent regression-fixture results, not a claim of general-world security accuracy. Full case-level results are committed in `evals/results/latest.json` and reproduced by CI.

## How to test

```bash
docker compose -f compose.demo.yml up -d
```

Open `http://localhost:8000` and run the deterministic 60-second tour. No OpenAI API key is needed for replay. Set `OPENAI_API_KEY` and choose live mode to exercise the real GPT-5.6 boundary.

## Supported platforms

The prebuilt container targets linux/amd64 and linux/arm64 and runs through Docker Desktop on Windows/macOS or Docker Engine on Linux. Source development requires Python 3.12+.

## Repository and demo fields

- Repository: `https://github.com/DizzyZ7/Sentinel`
- Public YouTube video: `ADD FINAL VIDEO URL`
- Demo/test path: `docker compose -f compose.demo.yml up -d`
- Codex `/feedback` Session ID: `ADD PRIMARY SESSION ID`

## Final submission checklist

- [ ] GHCR `sentinel` package is public and anonymously pullable
- [ ] clean-machine `compose.demo.yml` test completed
- [ ] README screenshots or GIF added
- [ ] final video is public on YouTube and shorter than three minutes
- [ ] voiceover explains the product, Codex workflow, and GPT-5.6 integration
- [ ] repository URL and MIT license confirmed
- [ ] primary `/feedback` Codex Session ID added
- [ ] project entered in Developer Tools
- [ ] submission sent before July 21, 2026 at 5:00 PM Pacific Time
