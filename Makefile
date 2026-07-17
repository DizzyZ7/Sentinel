.PHONY: up down logs test lint demo-archives

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f api

test:
	pytest -q

lint:
	ruff check app tests

demo-archives:
	python scripts/create_demo_archives.py
