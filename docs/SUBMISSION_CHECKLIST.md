# Sentinel final submission checklist

Official deadline: **July 21, 2026 at 5:00 PM PDT**, equal to **July 22 at 02:00 CEST in Europe/Amsterdam**. Use July 20 at 22:00 CEST as the internal completion target.

Exact publication locations and copy-ready values are in [`SUBMISSION_HANDOFF.md`](SUBMISSION_HANDOFF.md).

Run the automated preflight first:

```bash
python -m scripts.check_release
```

The command must report `automated_checks_passed: true`. The four remaining items are intentionally manual because they depend on external publication state.

## 1. Public image

1. Open GitHub profile → Packages → `sentinel` → Package settings.
2. Set package visibility to **Public**.
3. Run:

```bash
python -m scripts.check_public_image
```

4. In GitHub Actions, manually run **verify-public-image** and confirm all three steps pass.

## 2. Final video

- Public YouTube URL.
- Under three minutes.
- Audio explains both Codex collaboration and GPT-5.6 integration.
- Show the deterministic replay label before the live model path.
- Show the passed proof, dismissed false positive, failed proof, and blocked release gate.
- Add the URL to `docs/DEVPOST_SUBMISSION.md` and Devpost.

## 3. Codex disclosure

- Add the primary Codex Session ID to `/feedback` and the Devpost submission.
- Confirm `docs/BUILD_LOG.md` accurately describes the implementation slices.
- Keep the distinction between Codex-assisted development and runtime GPT-5.6 behavior explicit.

## 4. Devpost final review

- Track: Developer Tool.
- Repository is public.
- Installation and supported-platform instructions are visible in README.
- Judges can test without rebuilding through `compose.demo.yml`.
- Description matches `docs/DEVPOST_SUBMISSION.md`.
- Video is public and playable while signed out.
- No unsupported benchmark claim: eval figures remain scoped to the committed curated corpus.
- Retain the passing `sentinel-validation-pack` CI artifact and keep its limitations visible.

## Strict final preflight

After all manual items are complete:

```bash
export SENTINEL_GHCR_PUBLIC=true
export SENTINEL_VIDEO_URL='https://youtu.be/...'
export SENTINEL_CODEX_SESSION_ID='...'
export SENTINEL_DEVPOST_COMPLETE=true
python -m scripts.check_release --strict
```

Exit code `0` means the repository-side checklist is complete.

## Automated judge verification

- [ ] Run `sentinel-verify-judge --base-url http://localhost:8000 --output sentinel-judge-smoke.json`.
- [ ] Confirm the report status is `passed` and retain it with the submission artifacts.


## Local CLI evidence

- [ ] Run `sentinel scan . --json-output sentinel-local-scan.json --sarif-output sentinel-local-scan.sarif`.
- [ ] Confirm `source_executed`, `dependencies_installed`, and `patches_applied` are all `false`.
- [ ] Confirm the local report SHA-256 verifies before retaining the files as submission evidence.


## Submission release artifact

- [ ] Run the **submission-release** workflow once in draft mode to publish/refresh the image and produce retained assets.
- [ ] Make the GHCR package public and verify an anonymous pull.
- [ ] Run **submission-release** again with `strict_finalize=true` and all final external values.
- [ ] Set `publish_release=true` only for the strict final run.
- [ ] Download the workflow artifact and verify `SHA256SUMS`.
- [ ] Confirm the GitHub Release assets are accessible while signed out.
