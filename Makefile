.PHONY: install frontend-build frontend-verify lint go-test admission-verify paper-guard-verify run run-lan dev test verify demo

ENV_NAME := guarded-agent-runner
CONDA_RUN := conda run --name $(ENV_NAME)
PAPER_GUARD_BUILDER := gradle:9.1.0-jdk25-alpine@sha256:b22ef7ecc0718b37e59630a3c095cff7369c3a709830d89bcd7e7a68ba3de7a4

install:
	$(CONDA_RUN) python -m pip install -e ".[dev]"
	npm --prefix frontend install

frontend-build:
	npm --prefix frontend run build

frontend-verify:
	npm --prefix frontend run test:node
	docker build --target frontend --tag guarded-agent-runner-frontend:verify .

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

go-test:
	go test ./...
	go vet ./...

admission-verify:
	go test -race ./internal/admission ./internal/acceptance/g02 ./cmd/gar-gate ./cmd/gar-g02-verify

paper-guard-verify:
	mkdir -p "$(CURDIR)/.cache/gradle"
	docker run --rm --user "$$(id -u):$$(id -g)" \
		-e GRADLE_USER_HOME=/gradle-cache \
		-v "$(CURDIR)/.cache/gradle:/gradle-cache" \
		-v "$(CURDIR)/plugins/paper-guard:/workspace" -w /workspace \
		$(PAPER_GUARD_BUILDER) gradle --no-daemon --project-cache-dir /gradle-cache/project-cache clean test jar

verify: lint test go-test admission-verify paper-guard-verify frontend-verify

demo:
	$(CONDA_RUN) python scripts/demo.py
