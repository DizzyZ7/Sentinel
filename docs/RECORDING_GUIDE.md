# Sentinel recording guide

Use this guide together with `VIDEO_SCRIPT.md`. The goal is a clean 2:45 product demo with no editing ambiguity.

## Capture setup

- Resolution: 1920×1080 or 2560×1440.
- Browser zoom: 90% at 1080p, 100% at 1440p.
- Hide bookmarks, downloads, notifications, and personal browser profiles.
- Use a fresh deterministic replay immediately before recording.
- Keep the mouse still while speaking; move only when the next UI element is introduced.
- Record voice at a stable level and remove long pauses rather than speeding up speech.

## Required shots

1. **Landing page** — both demo buttons visible.
2. **Live progress** — capture at least two stage changes.
3. **Decision brief** — release blocked, recommended next action, and five trust-chain steps visible.
4. **Three-outcome demo** — verified fix, dismissed candidate, and blocked patch cards in one frame.
5. **Passed proof** — `before_detected=true`, `after_detected=false`, `source_executed=false`.
6. **Dismissed false positive** — contextual review explanation visible.
7. **Failed proof** — failed banner, unavailable approval action, release blocker.
8. **Evidence Bundle** — download and show the canonical payload digest.
9. **GPT audit** — model, response ID, prompt/schema versions, redaction count.
10. **GitHub** — merged PRs, green CI, evaluation artifact, and `BUILD_LOG.md`.

## Safe recording data

- Use only the packaged judge fixture.
- Never scan a private production repository during recording.
- Do not show a real `OPENAI_API_KEY`, environment file, browser password manager, terminal history, or private GitHub notification.
- The deterministic replay must remain visibly labelled; do not present it as a live GPT-5.6 call.

## Final edit checklist

- Opening problem is understandable within 15 seconds.
- Product differentiator appears before 35 seconds.
- Failed-proof behavior is shown, not merely described.
- Codex and GPT-5.6 have separate, accurate explanations.
- Final duration is under three minutes.
- Video is public and playable in a signed-out browser.
