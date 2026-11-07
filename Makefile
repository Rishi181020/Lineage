.PHONY: up down test e2e agent-shell

up:
	docker compose up --build -d

down:
	docker compose --profile tools down --remove-orphans

test:
	uv run pytest -q
	uv run python -m compileall -q control egress modeltap stubs launcher scripts
	docker compose config --quiet

e2e:
	bash scripts/e2e.sh

agent-shell:
	docker compose --profile tools run --rm agent-shell bash
