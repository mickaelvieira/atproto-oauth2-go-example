SHELL   := /bin/bash
OS      := $(shell uname -s)
CWD     := $(shell pwd)
VERSION := $(shell git rev-parse --short=6 HEAD)
GOFMT   := gofmt -s -w -l

.PHONY: build
build: ## Build the service
	go build .

.PHONY: build-docker
build-docker:	## Build the Docker image
	docker --debug buildx build \
	  --platform linux/amd64 \
		--build-arg GIT_COMMIT="$$(git log -n 1 --pretty=%h)" \
		--build-arg BUILD_TIME="$$(date --rfc-3339='ns' --utc)" \
		--tag mickaelvieira/atproto-oauth2-go-example:latest .

.PHONY: run-docker
run-docker:	## Run the Docker container
	docker run -it -p 9000:9000 --rm --env SECRET_JWK='${SECRET_JWK}' mickaelvieira/atproto-oauth2-go-example:latest

.PHONY: help
help:	## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
