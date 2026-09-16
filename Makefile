.PHONY: all build test clean run-backend run-web

BIN_DIR := bin
BINARY_NAME := provenancex
BINARY := $(BIN_DIR)/$(BINARY_NAME)

all: test build

build:
	go build -v -o $(BINARY) ./cmd/provenancex

test:
	go test -v -race ./...

clean:
	rm -rf $(BIN_DIR) web/dist web/node_modules

run-backend: build
	./$(BINARY) --help

run-web:
	cd web && npm run dev
