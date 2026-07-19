# Sentinel final submission checklist

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
