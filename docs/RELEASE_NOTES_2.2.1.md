# Sentinel 2.2.1 — Submission Release Pack

Sentinel 2.2.1 freezes product expansion for OpenAI Build Week and adds a reproducible publication path.

## Included

- local-first evidence-to-patch security workflow powered by GPT-5.6;
- deterministic 60-second judge replay and separate live GPT-5.6 path;
- 60 static validation cases and 17 patch/regression cases;
- local `sentinel scan` CLI with changed-files, baseline, JSON, and SARIF support;
- multi-architecture GHCR image for linux/amd64 and linux/arm64;
- hash-covered submission pack containing copy-ready Devpost material and retained evidence;
- clean-container judge smoke verification before release publication.

## Safety boundaries

Sentinel does not execute scanned repository source, install scanned project dependencies, auto-apply AI patches, expose original secrets to the model or export, or allow failed regression proof to be approved.

## Judge path

```bash
docker compose -f compose.demo.yml up -d
```

Open `http://localhost:8000` and choose **Run the 60-second security demo**.
