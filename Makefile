.PHONY: up down logs test lint eval release-check public-image-check demo-archives

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f api

test:
	pytest -q

lint:
	ruff check app tests scripts

eval:
	python -m scripts.run_evals --fail-on-regression

release-check:
	python -m scripts.check_release

public-image-check:
	python -m scripts.check_public_image

demo-archives:
	python scripts/create_demo_archives.py
