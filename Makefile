# wazuh-logtest-offline
#
# Local targets need python3 + pytest. Docker targets need docker + compose v2.
# On hosts where docker needs sudo, run:
#     DOCKER="sudo docker" make build up test-docker

COMPOSE := $${DOCKER:-docker} compose -f docker/docker-compose.yml

.PHONY: help test cov build up down test-docker examples

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

test: ## Run the unit test suite locally (no docker needed)
	python3 -m pytest

cov: ## Run tests with coverage; fails below the 85% gate
	python3 -m pytest --cov=wlogtest --cov-report=term-missing --cov-fail-under=85

build: ## Build all images (manager + runner + runner-test)
	$(COMPOSE) build

up: ## Start the wazuh manager in the background (runner runs via `compose run`)
	$(COMPOSE) up -d manager
	$(COMPOSE) ps

down: ## Stop and remove containers/networks (keeps the wazuh-queue volume)
	$(COMPOSE) down

test-docker: ## Full end-to-end validation inside docker (manager + datasets + pytest)
	DOCKER="$${DOCKER:-docker}" bash docker/test.sh

examples: ## Run all three example datasets against a running manager (make up first)
	$(COMPOSE) run --rm runner run /data/datasets/basic.json
	$(COMPOSE) run --rm runner run /data/datasets/correlation.json
	-$(COMPOSE) run --rm runner run /data/datasets/fail_demo.json
