GO ?= go
BIN ?= bin/relay

.PHONY: run build test test-race vet tidy docker loadtest loadtest-e2e clean

# Loadtest knobs (override on the command line, e.g. `make loadtest N=2000`)
N          ?= 1000
CONCURRENCY ?= 100
DURATION   ?= 15s
RATE       ?= 20
ADDR       ?= http://localhost:8080

run:
	$(GO) run ./cmd/relay

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/relay

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

docker:
	docker build -t relay-demo:dev .

# Run the loadtest against an ALREADY-RUNNING relay.
# Start the relay in another terminal with `make run` before invoking this.
loadtest:
	$(GO) run ./cmd/loadtest -addr $(ADDR) -n $(N) -concurrency $(CONCURRENCY) -duration $(DURATION) -rate $(RATE)

# End-to-end: start a relay on a random port in the background, run the
# loadtest against it, and shut the relay down cleanly when the harness exits.
loadtest-e2e:
	@set -e; \
	PORT=$$(( (RANDOM % 10000) + 20000 )); \
	echo "starting relay on 127.0.0.1:$$PORT"; \
	RELAY_HTTP_ADDR=127.0.0.1:$$PORT RELAY_LOG_LEVEL=warn $(GO) run ./cmd/relay & \
	RELAY_PID=$$!; \
	trap "kill -TERM $$RELAY_PID 2>/dev/null; wait $$RELAY_PID 2>/dev/null" EXIT; \
	sleep 2; \
	$(GO) run ./cmd/loadtest -addr http://127.0.0.1:$$PORT -n $(N) -concurrency $(CONCURRENCY) -duration $(DURATION) -rate $(RATE)

clean:
	rm -rf bin
