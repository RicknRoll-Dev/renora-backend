SHELL := /bin/bash
.DEFAULT_GOAL := help

# Load .env for local runs when it exists.
ifneq (,$(wildcard .env))
include .env
export
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/renora/renora-api/internal/version.Version=$(VERSION) -X github.com/renora/renora-api/internal/version.Commit=$(COMMIT)
GOLANGCI_LINT_VERSION := v2.5.0
# The contract repo, checked out beside this one (as the web and mobile apps expect it).
CONTRACT_DIR ?= ../renora-api-contract
SCHEMA_DIR   := internal/graph/schema

.PHONY: help deps deps-down contract-sync generate migrate-up migrate-down migrate-status api worker test test-integration lint build image check-contract check-generated

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

deps: ## Start Postgres and Redis
	docker compose up -d --wait

deps-down: ## Stop local dependencies
	docker compose down

contract-sync: ## Copy the schema from $(CONTRACT_DIR) and record its commit
	@test -d $(CONTRACT_DIR)/schema || { echo "contract not found at $(CONTRACT_DIR); set CONTRACT_DIR"; exit 1; }
	rm -f $(SCHEMA_DIR)/*.graphql
	cp $(CONTRACT_DIR)/schema/*.graphql $(SCHEMA_DIR)/
	git -C $(CONTRACT_DIR) log -1 --format='%H %cs %s' > $(SCHEMA_DIR)/CONTRACT_REF

generate: ## Regenerate GraphQL code from the vendored schema
	go tool gqlgen generate

migrate-up: ## Apply migrations
	go run ./cmd/migrate up

migrate-down: ## Roll back the latest migration
	go run ./cmd/migrate down

migrate-status: ## Show migration status
	go run ./cmd/migrate status

api: ## Run the API locally
	go run ./cmd/api

worker: ## Run the worker locally
	go run ./cmd/worker

test: ## Run unit tests
	go test -race ./...

test-integration: ## Run tests that need Postgres and Redis (TEST_DATABASE_URL, TEST_REDIS_URL)
	TEST_DATABASE_URL=$${TEST_DATABASE_URL:-$(DATABASE_URL)} TEST_REDIS_URL=$${TEST_REDIS_URL:-$(REDIS_URL)} go test -race -count=1 ./...

lint: ## Run golangci-lint
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

check-contract: ## Fail if the vendored schema differs from $(CONTRACT_DIR)
	diff -r --exclude=CONTRACT_REF $(CONTRACT_DIR)/schema $(SCHEMA_DIR)

check-generated: generate ## Fail if generated code is out of date
	git diff --exit-code -- internal/graph

build: ## Build all binaries into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

image: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t renora/renora-api:$(VERSION) .
