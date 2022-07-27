SHELL := /bin/bash

.PHONY: build format test

build:
	go build .

format:
	gofmt -s -w -l .

test:
	go test ./...
