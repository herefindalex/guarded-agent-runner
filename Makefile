.PHONY: install frontend-build lint run run-lan dev test verify demo

ENV_NAME := guarded-agent-runner
CONDA_RUN := conda run --name $(ENV_NAME)

install:
	$(CONDA_RUN) python -m pip install -e ".[dev]"
	npm --prefix frontend install

frontend-build:
	npm --prefix frontend run build

lint:
	$(CONDA_RUN) ruff check guarded_agent_runner tests

run: frontend-build
	$(CONDA_RUN) uvicorn guarded_agent_runner.main:create_app --factory --host 127.0.0.1 --port 8000

run-lan: frontend-build
	$(CONDA_RUN) uvicorn guarded_agent_runner.main:create_app --factory --host 0.0.0.0 --port 8000

dev:
	$(CONDA_RUN) uvicorn guarded_agent_runner.main:create_app --factory --reload --host 127.0.0.1 --port 8000

test:
	$(CONDA_RUN) pytest -q

verify: lint test frontend-build

demo:
	$(CONDA_RUN) python scripts/demo.py
