# wazuh-logtest-offline
#
# Local targets need python3 + pytest (see .venv). Docker targets need
# docker + compose v2 (not available on the dev host; validated on a
# Docker-enabled machine / CI -- see docker/test.sh).

COMPOSE := docker compose -f docker/docker-compose.yml

.PHONY: help test cov build up down test-docker examples

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

test: ## Run the unit test suite locally (no docker needed)
	python3 -m pytest

cov: ## Run tests with per-file coverage report
	python3 -m pytest --cov=wlogtest --cov-report=term-missing

build: ## Build the runner images (runtime runner + builder-stage runner-test)
	$(COMPOSE) build

up: ## Start the wazuh manager in the background (runner runs via `compose run`)
	$(COMPOSE) up -d manager
	$(COMPOSE) ps

down: ## Stop and remove containers/networks (keeps the wazuh-queue volume)
	$(COMPOSE) down

test-docker: ## Full end-to-end validation inside docker (manager + datasets + pytest)
	bash docker/test.sh

examples: ## Run all three example datasets against a running manager (make up first)
	$(COMPOSE) run --rm runner run /data/datasets/basic.json
	$(COMPOSE) run --rm runner run /data/datasets/correlation.json
	-$(COMPOSE) run --rm runner run /data/datasets/fail_demo.json
