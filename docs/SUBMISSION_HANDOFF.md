# Sentinel submission handoff

## Deadline

The official OpenAI Build Week submission deadline is **Tuesday, July 21, 2026 at 5:00 PM Pacific Daylight Time**.

For Europe/Amsterdam this is **Wednesday, July 22, 2026 at 02:00 CEST**.

Do not use that converted time as the working deadline. Finish and save the Devpost submission by **Monday, July 20 at 22:00 CEST** so the final day remains available for signed-out link checks and emergency corrections.

Official pages:

- Hackathon: `https://openai.devpost.com/`
- Rules: `https://openai.devpost.com/rules`
- FAQ: `https://openai.devpost.com/details/faqs`

After the submission period ends, the Devpost entry cannot be changed.

## Exact external actions

### 1. Join and create the Devpost project

1. Open `https://openai.devpost.com/`.
2. Sign in to Devpost.
3. Click **Join Hackathon** if the account is not registered yet.
4. Open **My projects**.
5. Choose **Enter a submission** or continue the existing Sentinel draft.
6. Select the **Developer Tools** track.

Use `docs/DEVPOST_SUBMISSION.md` for the long description and the generated `documents/DEVPOST_COPY.md` from the submission pack for copy-ready fields.

### 2. Publish the container image

1. Open GitHub Actions in `DizzyZ7/Sentinel`.
2. Run **submission-release** with image publishing enabled.
3. Open GitHub profile → **Packages** → `sentinel` → **Package settings**.
4. Change visibility to **Public**.
5. Run **verify-public-image**.
6. Confirm an anonymous pull succeeds:

```bash
docker logout ghcr.io || true
docker pull ghcr.io/dizzyz7/sentinel:latest
```

The image link used in the README and Devpost testing instructions is:

`ghcr.io/dizzyz7/sentinel:latest`

### 3. Record and publish the video

1. Follow `docs/RECORDING_GUIDE.md` and `docs/VIDEO_SCRIPT.md`.
2. Keep the final video below three minutes; the target script is approximately 2:50.
3. Include spoken audio explaining both Codex-assisted development and runtime GPT-5.6 usage.
4. Do not use copyrighted music, logos, footage, or other material without permission.
5. Upload to YouTube as **Public**. Unlisted is not sufficient because the official rules require publicly visible YouTube video.
6. Open the video in a private/incognito window while signed out.
7. Paste the final URL into Devpost and into the final submission-release workflow inputs.

### 4. Obtain the Codex Session ID

1. Open the primary Codex build thread used for Sentinel.
2. Run `/feedback`.
3. Copy the returned primary Session ID exactly.
4. Paste it into the Devpost Session ID field and the final submission-release workflow input.
5. Keep `docs/BUILD_LOG.md` and merged pull requests as the timestamped implementation evidence.

### 5. Fill the required Devpost fields

Use these values:

- **Project name:** Sentinel
- **Tagline:** Evidence-to-patch security review that makes AI prove a fix before a human can approve it.
- **Track:** Developer Tools
- **Repository URL:** `https://github.com/DizzyZ7/Sentinel`
- **Demo/testing command:** `docker compose -f compose.demo.yml up -d`
- **Public video:** final YouTube URL
- **Primary Codex Session ID:** value returned by `/feedback`

The repository must remain public with the MIT license. The README already contains installation, supported platform, local CLI, and judge testing instructions.

### 6. Final release pack

Run the **submission-release** workflow twice if necessary:

1. First run: publish the multi-architecture image and build a draft submission pack.
2. Make the GHCR package public and finish the YouTube/Devpost fields.
3. Final run: enable strict finalization, supply the video URL and Session ID, confirm GHCR public and Devpost complete, and publish the GitHub Release.

The final GitHub Release should contain:

- Python wheel and source distribution;
- `sentinel-submission-pack-<version>.zip`;
- validation report;
- local CLI JSON and SARIF;
- release readiness report;
- judge smoke report;
- `SHA256SUMS` and manifest.

Devpost itself requires the repository and video URLs; the GitHub Release is judge convenience and integrity evidence, not a replacement for the required fields.

## Signed-out verification

Before pressing the final Devpost submit button, verify while signed out:

- repository opens;
- README renders and commands are visible;
- YouTube video plays and has audio;
- GHCR image pulls anonymously;
- GitHub Release assets download;
- no document contains `ADD FINAL`, `ADD PRIMARY`, or another placeholder;
- video duration is under three minutes;
- Devpost track is Developer Tools;
- description distinguishes deterministic replay from live GPT-5.6;
- corpus metrics are described as committed fixture results, not universal accuracy.

## Final strict commands

```bash
export SENTINEL_GHCR_PUBLIC=true
export SENTINEL_VIDEO_URL='https://youtu.be/...'
export SENTINEL_CODEX_SESSION_ID='...'
export SENTINEL_DEVPOST_COMPLETE=true
python -m scripts.check_release --strict
```

Then build the final local copy of the handoff pack:

```bash
python -m scripts.build_submission_pack \
  --output-dir build/submission-pack \
  --archive build/sentinel-submission-pack-2.2.1.zip \
  --ghcr-public \
  --devpost-complete \
  --strict
```
